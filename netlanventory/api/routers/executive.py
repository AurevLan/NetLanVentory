"""Executive / RSSI dashboard router.

Returns a high-level summary for management reporting: global risk score,
top vulnerable assets, CVE trends, remediation rate, and asset coverage.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve
from netlanventory.models.hardening_report import HardeningReport
from netlanventory.models.ssl_scan_report import SslScanReport

router = APIRouter(prefix="/executive", tags=["executive"])

DbDep = Annotated[AsyncSession, Depends(get_db)]


class RiskTrendPoint(BaseModel):
    date: str
    new_cves: int
    resolved_cves: int
    cumulative_unacked: int


class TopRiskyAsset(BaseModel):
    asset_id: str
    ip: str | None
    name: str | None
    criticality: str
    risk_score: float | None
    cve_count: int
    critical_cve_count: int


class SecurityCoverage(BaseModel):
    assets_with_recent_scan: int
    assets_with_hardening: int
    assets_with_ssl_ok: int
    total_assets: int
    scan_coverage_pct: float
    hardening_coverage_pct: float


class ExecutiveSummary(BaseModel):
    # Overall risk score (0-100, higher = worse)
    global_risk_score: float
    risk_trend: str  # improving | stable | worsening

    # CVE summary
    total_cves: int
    critical_cves: int
    high_cves: int
    unacknowledged_pct: float
    remediation_rate_pct: float  # % of CVEs acknowledged in last 30d

    # Top risks
    top_risky_assets: list[TopRiskyAsset]

    # Asset coverage
    coverage: SecurityCoverage

    # 30-day trend
    trend_30d: list[RiskTrendPoint]

    # Context
    total_assets: int
    active_assets: int
    generated_at: str


@router.get("/summary", response_model=ExecutiveSummary)
async def get_executive_summary(db: DbDep) -> ExecutiveSummary:
    """Return the RSSI executive security summary."""
    now = datetime.now(timezone.utc)
    cutoff_30d = now - timedelta(days=30)
    cutoff_7d = now - timedelta(days=7)

    # Asset counts
    total_assets = (await db.execute(select(func.count()).select_from(Asset))).scalar_one()
    active_assets = (
        await db.execute(
            select(func.count()).select_from(Asset).where(Asset.is_active.is_(True))
        )
    ).scalar_one()

    # CVE counts by severity
    sev_rows = (
        await db.execute(
            select(Cve.severity, func.count(AssetCve.id).label("cnt"))
            .join(AssetCve, AssetCve.cve_id == Cve.id)
            .where(AssetCve.ack_status == "none")
            .group_by(Cve.severity)
        )
    ).all()

    sev_map = {r.severity or "Unknown": r.cnt for r in sev_rows}
    critical_cves = sev_map.get("Critical", 0)
    high_cves = sev_map.get("High", 0)
    total_unacked = sum(sev_map.values())
    total_cves = (await db.execute(select(func.count()).select_from(AssetCve))).scalar_one()

    unacknowledged_pct = (total_unacked / total_cves * 100) if total_cves > 0 else 0.0

    # Remediation rate: CVEs acknowledged in last 30d / total CVEs
    acked_30d = (
        await db.execute(
            select(func.count()).select_from(AssetCve).where(
                AssetCve.ack_at.isnot(None),
                AssetCve.ack_at >= cutoff_30d,
            )
        )
    ).scalar_one()
    remediation_rate_pct = (acked_30d / total_cves * 100) if total_cves > 0 else 0.0

    # Global risk score (weighted)
    # Formula: critical*15 + high*5 + medium*2 + low*0.5 capped at 100
    total_medium = sev_map.get("Medium", 0)
    total_low = sev_map.get("Low", 0)
    raw_score = critical_cves * 15 + high_cves * 5 + total_medium * 2 + total_low * 0.5
    max_score = max(active_assets * 20, 1)
    global_risk_score = min(100.0, round(raw_score / max_score * 100, 1))

    # Risk trend: compare last 7d vs previous 7d
    new_cves_7d = (
        await db.execute(
            select(func.count()).select_from(AssetCve).where(
                AssetCve.discovered_at >= cutoff_7d
            )
        )
    ).scalar_one()
    new_cves_prev_7d = (
        await db.execute(
            select(func.count()).select_from(AssetCve).where(
                AssetCve.discovered_at >= cutoff_30d,
                AssetCve.discovered_at < cutoff_7d,
            )
        )
    ).scalar_one()

    if new_cves_7d < new_cves_prev_7d * 0.9:
        risk_trend = "improving"
    elif new_cves_7d > new_cves_prev_7d * 1.1:
        risk_trend = "worsening"
    else:
        risk_trend = "stable"

    # Top 10 risky assets
    top_rows = (
        await db.execute(
            select(
                Asset.id,
                Asset.ip,
                Asset.name,
                Asset.criticality,
                Asset.risk_score,
                func.count(AssetCve.id).label("total"),
                func.sum(case((Cve.severity == "Critical", 1), else_=0)).label("critical"),
            )
            .join(AssetCve, AssetCve.asset_id == Asset.id)
            .join(Cve, AssetCve.cve_id == Cve.id)
            .where(AssetCve.ack_status == "none")
            .group_by(Asset.id, Asset.ip, Asset.name, Asset.criticality, Asset.risk_score)
            .order_by(func.sum(case((Cve.severity == "Critical", 1), else_=0)).desc(), func.count(AssetCve.id).desc())
            .limit(10)
        )
    ).all()

    top_risky_assets = [
        TopRiskyAsset(
            asset_id=str(r.id),
            ip=r.ip,
            name=r.name,
            criticality=r.criticality or "medium",
            risk_score=r.risk_score,
            cve_count=r.total or 0,
            critical_cve_count=int(r.critical or 0),
        )
        for r in top_rows
    ]

    # Coverage metrics
    cutoff_scan = now - timedelta(days=7)
    assets_recently_scanned = (
        await db.execute(
            select(func.count()).select_from(Asset).where(
                Asset.is_active.is_(True),
                Asset.last_seen >= cutoff_scan,
            )
        )
    ).scalar_one()

    assets_with_hardening = (
        await db.execute(
            select(func.count(func.distinct(HardeningReport.asset_id)))
            .where(HardeningReport.status == "completed")
        )
    ).scalar_one()

    assets_with_ssl_ok = (
        await db.execute(
            select(func.count(func.distinct(SslScanReport.asset_id)))
            .where(SslScanReport.status == "valid")
        )
    ).scalar_one()

    denom = max(active_assets, 1)
    coverage = SecurityCoverage(
        assets_with_recent_scan=assets_recently_scanned,
        assets_with_hardening=assets_with_hardening,
        assets_with_ssl_ok=assets_with_ssl_ok,
        total_assets=active_assets,
        scan_coverage_pct=round(assets_recently_scanned / denom * 100, 1),
        hardening_coverage_pct=round(assets_with_hardening / denom * 100, 1),
    )

    # 30-day trend: daily CVE discovery vs acknowledgment
    disc_rows = (
        await db.execute(
            select(
                func.date(AssetCve.discovered_at).label("day"),
                func.count(AssetCve.id).label("cnt"),
            )
            .where(AssetCve.discovered_at >= cutoff_30d)
            .group_by(func.date(AssetCve.discovered_at))
        )
    ).all()
    disc_map = {str(r.day): r.cnt for r in disc_rows}

    ack_rows = (
        await db.execute(
            select(
                func.date(AssetCve.ack_at).label("day"),
                func.count(AssetCve.id).label("cnt"),
            )
            .where(AssetCve.ack_at.isnot(None), AssetCve.ack_at >= cutoff_30d)
            .group_by(func.date(AssetCve.ack_at))
        )
    ).all()
    ack_map = {str(r.day): r.cnt for r in ack_rows}

    trend_30d: list[RiskTrendPoint] = []
    running_unacked = total_unacked
    for i in range(30):
        day = (now - timedelta(days=29 - i)).date()
        day_str = str(day)
        new = disc_map.get(day_str, 0)
        resolved = ack_map.get(day_str, 0)
        trend_30d.append(RiskTrendPoint(
            date=day_str,
            new_cves=new,
            resolved_cves=resolved,
            cumulative_unacked=max(0, running_unacked),
        ))
        running_unacked += new - resolved

    return ExecutiveSummary(
        global_risk_score=global_risk_score,
        risk_trend=risk_trend,
        total_cves=total_cves,
        critical_cves=critical_cves,
        high_cves=high_cves,
        unacknowledged_pct=round(unacknowledged_pct, 1),
        remediation_rate_pct=round(remediation_rate_pct, 1),
        top_risky_assets=top_risky_assets,
        coverage=coverage,
        trend_30d=trend_30d,
        total_assets=total_assets,
        active_assets=active_assets,
        generated_at=now.isoformat(),
    )
