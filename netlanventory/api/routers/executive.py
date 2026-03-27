"""Executive / RSSI dashboard router.

Returns a high-level summary for management reporting: global risk score,
top vulnerable assets, CVE trends, remediation rate, and asset coverage.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import case, func, literal, select, text
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


class VelocityPoint(BaseModel):
    week: str
    resolved: int


class BurndownPoint(BaseModel):
    date: str
    open_count: int


class HeatmapEntry(BaseModel):
    criticality: str
    critical_cves: int
    high_cves: int
    medium_cves: int
    low_cves: int


class SlaMetrics(BaseModel):
    total_breach_count: int
    avg_days_overdue: float | None


class RemediationFunnel(BaseModel):
    open: int
    planned: int
    in_progress: int
    resolved: int
    blocked: int


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

    # MTTR
    mttr_hours: float | None

    # Velocity (CVEs resolved per week, last 12 weeks)
    velocity: list[VelocityPoint]

    # Burndown (daily open CVE count, last 30 days)
    burndown: list[BurndownPoint]

    # Forecast days until critical+high CVEs reach zero
    forecast_days_to_zero: int | None

    # Severity heatmap grouped by asset criticality
    heatmap: list[HeatmapEntry]

    # SLA metrics
    sla_metrics: SlaMetrics

    # Remediation funnel
    remediation_funnel: RemediationFunnel

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

    # ── MTTR (Mean Time to Remediation) ────────────────────────────────
    cutoff_90d = now - timedelta(days=90)
    mttr_result = (
        await db.execute(
            select(
                func.avg(
                    func.extract("epoch", AssetCve.remediation_resolved_at)
                    - func.extract("epoch", AssetCve.discovered_at)
                )
                / 3600.0
            )
            .where(
                AssetCve.remediation_status == "resolved",
                AssetCve.remediation_resolved_at.isnot(None),
                AssetCve.remediation_resolved_at >= cutoff_90d,
            )
        )
    ).scalar_one_or_none()
    mttr_hours: float | None = round(mttr_result, 2) if mttr_result is not None else None

    # ── Velocity (CVEs resolved per week, last 12 weeks) ────────────
    velocity: list[VelocityPoint] = []
    for w in range(12, 0, -1):
        week_end = now - timedelta(weeks=w - 1)
        week_start = now - timedelta(weeks=w)
        cnt = (
            await db.execute(
                select(func.count())
                .select_from(AssetCve)
                .where(
                    AssetCve.remediation_resolved_at.isnot(None),
                    AssetCve.remediation_resolved_at >= week_start,
                    AssetCve.remediation_resolved_at < week_end,
                )
            )
        ).scalar_one()
        iso_year, iso_week, _ = week_start.isocalendar()
        velocity.append(VelocityPoint(week=f"{iso_year}-W{iso_week:02d}", resolved=cnt))

    # ── Burndown (daily open CVE count, last 30 days) ────────────────
    burndown: list[BurndownPoint] = []
    for d in range(30):
        day = (now - timedelta(days=29 - d)).date()
        day_end = datetime(day.year, day.month, day.day, 23, 59, 59, tzinfo=timezone.utc)
        # Count CVEs that were open at end of this day:
        # discovered_at <= day_end AND (remediation_resolved_at IS NULL OR remediation_resolved_at > day_end)
        open_count = (
            await db.execute(
                select(func.count())
                .select_from(AssetCve)
                .where(
                    AssetCve.discovered_at <= day_end,
                    AssetCve.remediation_status != "resolved",
                )
                .where(
                    (AssetCve.remediation_resolved_at.is_(None))
                    | (AssetCve.remediation_resolved_at > day_end)
                )
            )
        ).scalar_one()
        burndown.append(BurndownPoint(date=str(day), open_count=open_count))

    # ── Forecast days to zero critical+high ──────────────────────────
    current_critical_high = critical_cves + high_cves
    total_velocity = sum(v.resolved for v in velocity)
    avg_weekly_velocity = total_velocity / 12.0 if velocity else 0.0
    if avg_weekly_velocity > 0 and current_critical_high > 0:
        forecast_days_to_zero = int(current_critical_high / avg_weekly_velocity * 7)
    else:
        forecast_days_to_zero = None

    # ── Severity heatmap (group by asset criticality) ────────────────
    heatmap_rows = (
        await db.execute(
            select(
                Asset.criticality,
                func.sum(case((Cve.severity == "Critical", 1), else_=0)).label("critical_cves"),
                func.sum(case((Cve.severity == "High", 1), else_=0)).label("high_cves"),
                func.sum(case((Cve.severity == "Medium", 1), else_=0)).label("medium_cves"),
                func.sum(case((Cve.severity == "Low", 1), else_=0)).label("low_cves"),
            )
            .join(AssetCve, AssetCve.asset_id == Asset.id)
            .join(Cve, AssetCve.cve_id == Cve.id)
            .group_by(Asset.criticality)
        )
    ).all()
    heatmap = [
        HeatmapEntry(
            criticality=r.criticality or "unknown",
            critical_cves=int(r.critical_cves or 0),
            high_cves=int(r.high_cves or 0),
            medium_cves=int(r.medium_cves or 0),
            low_cves=int(r.low_cves or 0),
        )
        for r in heatmap_rows
    ]

    # ── SLA metrics ──────────────────────────────────────────────────
    sla_breach_count = (
        await db.execute(
            select(func.count())
            .select_from(AssetCve)
            .where(AssetCve.sla_breached.is_(True))
        )
    ).scalar_one()

    sla_avg_overdue = (
        await db.execute(
            select(
                func.avg(
                    func.extract("epoch", func.now() - AssetCve.sla_deadline) / 86400.0
                )
            )
            .where(
                AssetCve.sla_breached.is_(True),
                AssetCve.sla_deadline.isnot(None),
            )
        )
    ).scalar_one_or_none()
    sla_metrics = SlaMetrics(
        total_breach_count=sla_breach_count,
        avg_days_overdue=round(sla_avg_overdue, 1) if sla_avg_overdue is not None else None,
    )

    # ── Remediation funnel ───────────────────────────────────────────
    funnel_rows = (
        await db.execute(
            select(AssetCve.remediation_status, func.count(AssetCve.id).label("cnt"))
            .group_by(AssetCve.remediation_status)
        )
    ).all()
    funnel_map = {r.remediation_status: r.cnt for r in funnel_rows}
    remediation_funnel = RemediationFunnel(
        open=funnel_map.get("open", 0),
        planned=funnel_map.get("planned", 0),
        in_progress=funnel_map.get("in_progress", 0),
        resolved=funnel_map.get("resolved", 0),
        blocked=funnel_map.get("blocked", 0),
    )

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
        mttr_hours=mttr_hours,
        velocity=velocity,
        burndown=burndown,
        forecast_days_to_zero=forecast_days_to_zero,
        heatmap=heatmap,
        sla_metrics=sla_metrics,
        remediation_funnel=remediation_funnel,
        total_assets=total_assets,
        active_assets=active_assets,
        generated_at=now.isoformat(),
    )
