"""Dashboard stats router — aggregated metrics for the home page."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_current_active_user, get_db
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

DbDep = Annotated[AsyncSession, Depends(get_db)]


class SeverityCount(BaseModel):
    severity: str
    count: int


class TopVulnerableAsset(BaseModel):
    asset_id: str
    ip: str | None
    name: str | None
    cve_count: int
    critical_count: int


class SsvcDecisionCount(BaseModel):
    decision: str                   # act | attend | track* | track | unevaluated
    count: int


class DashboardStats(BaseModel):
    total_assets: int
    active_assets: int
    total_cves: int
    unacknowledged_cves: int
    cves_by_severity: list[SeverityCount]
    top_vulnerable_assets: list[TopVulnerableAsset]
    assets_not_scanned_30d: int
    critical_cves_without_remediation: int
    # Unified patching verdict (most urgent first); default keeps pre-v0.16
    # cached payloads deserializable.
    ssvc_open: list[SsvcDecisionCount] = []


class TrendPoint(BaseModel):
    date: str  # ISO date string YYYY-MM-DD
    cves_discovered: int
    cves_acknowledged: int


class TrendData(BaseModel):
    points: list[TrendPoint]
    active_assets: int


@router.get("", response_model=DashboardStats)
async def get_dashboard_stats(
    db: DbDep,
    _current_user: Annotated[object, Depends(get_current_active_user)],
) -> DashboardStats:
    """Return aggregated security metrics for the dashboard."""
    from netlanventory.core.cache import cache_get_json, cache_set_json
    from netlanventory.core.config import get_settings

    _cache_key = "dashboard:stats"
    cached = await cache_get_json(_cache_key)
    if cached is not None:
        return DashboardStats(**cached)

    # Asset counts
    total_assets = (await db.execute(select(func.count()).select_from(Asset))).scalar_one()
    active_assets = (
        await db.execute(select(func.count()).select_from(Asset).where(Asset.is_active.is_(True)))
    ).scalar_one()

    # CVE counts
    total_cves = (await db.execute(select(func.count()).select_from(AssetCve))).scalar_one()
    unacknowledged_cves = (
        await db.execute(
            select(func.count()).select_from(AssetCve).where(AssetCve.ack_status == "none")
        )
    ).scalar_one()

    # CVEs by severity (join AssetCve → Cve)
    severity_rows = (
        await db.execute(
            select(Cve.severity, func.count(AssetCve.id).label("cnt"))
            .join(Cve, AssetCve.cve_id == Cve.id)
            .group_by(Cve.severity)
            .order_by(func.count(AssetCve.id).desc())
        )
    ).all()
    cves_by_severity = [
        SeverityCount(severity=row.severity or "Unknown", count=row.cnt)
        for row in severity_rows
    ]

    # Top 5 vulnerable assets
    top_rows = (
        await db.execute(
            select(
                Asset.id,
                Asset.ip,
                Asset.name,
                func.count(AssetCve.id).label("total"),
                func.sum(
                    case((Cve.severity == "Critical", 1), else_=0)
                ).label("critical"),
            )
            .join(AssetCve, AssetCve.asset_id == Asset.id)
            .join(Cve, AssetCve.cve_id == Cve.id)
            .where(AssetCve.ack_status == "none")
            .group_by(Asset.id, Asset.ip, Asset.name)
            .order_by(func.count(AssetCve.id).desc())
            .limit(5)
        )
    ).all()

    top_vulnerable = [
        TopVulnerableAsset(
            asset_id=str(row.id),
            ip=row.ip,
            name=row.name,
            cve_count=row.total or 0,
            critical_count=int(row.critical or 0),
        )
        for row in top_rows
    ]

    # Assets not scanned in 30 days (active assets with last_seen < 30d ago or null)
    cutoff_30d = datetime.now(timezone.utc) - timedelta(days=30)
    assets_not_scanned_30d = (
        await db.execute(
            select(func.count()).select_from(Asset).where(
                Asset.is_active.is_(True),
                (Asset.last_seen < cutoff_30d) | (Asset.last_seen.is_(None)),
            )
        )
    ).scalar_one()

    # Critical CVEs with no remediation plan and at least one unacknowledged exposure
    critical_no_remediation = (
        await db.execute(
            select(func.count(func.distinct(Cve.id)))
            .select_from(Cve)
            .join(AssetCve, AssetCve.cve_id == Cve.id)
            .where(
                func.lower(Cve.severity) == "critical",
                (Cve.remediation.is_(None)) | (Cve.remediation == ""),
                AssetCve.ack_status == "none",
            )
        )
    ).scalar_one()

    # SSVC verdict counts (unacked pairs), most urgent first
    from netlanventory.core.prioritization import open_decision_counts

    decision_counts = await open_decision_counts(db)
    ssvc_open = [
        SsvcDecisionCount(decision=d, count=decision_counts[d])
        for d in ("act", "attend", "track*", "track", "unevaluated")
    ]

    result = DashboardStats(
        total_assets=total_assets,
        active_assets=active_assets,
        total_cves=total_cves,
        unacknowledged_cves=unacknowledged_cves,
        cves_by_severity=cves_by_severity,
        top_vulnerable_assets=top_vulnerable,
        assets_not_scanned_30d=assets_not_scanned_30d,
        critical_cves_without_remediation=critical_no_remediation,
        ssvc_open=ssvc_open,
    )
    await cache_set_json(_cache_key, result.model_dump(), ttl=get_settings().cache_ttl_seconds)
    return result


@router.get("/trends", response_model=TrendData)
async def get_dashboard_trends(
    db: DbDep,
    _current_user: Annotated[object, Depends(get_current_active_user)],
) -> TrendData:
    """Return daily CVE discovery and acknowledgment counts for the last 30 days."""
    from netlanventory.core.cache import cache_get_json, cache_set_json
    from netlanventory.core.config import get_settings

    _cache_key = "dashboard:trends"
    cached = await cache_get_json(_cache_key)
    if cached is not None:
        return TrendData(**cached)

    cutoff = datetime.now(timezone.utc) - timedelta(days=30)

    # Daily CVE discoveries (using AssetCve.discovered_at)
    discovered_rows = (
        await db.execute(
            select(
                func.date(AssetCve.discovered_at).label("day"),
                func.count(AssetCve.id).label("cnt"),
            )
            .where(AssetCve.discovered_at >= cutoff)
            .group_by(func.date(AssetCve.discovered_at))
            .order_by(func.date(AssetCve.discovered_at))
        )
    ).all()

    # Daily CVE acknowledgments (using AssetCve.ack_at)
    acked_rows = (
        await db.execute(
            select(
                func.date(AssetCve.ack_at).label("day"),
                func.count(AssetCve.id).label("cnt"),
            )
            .where(
                AssetCve.ack_at.is_not(None),
                AssetCve.ack_at >= cutoff,
            )
            .group_by(func.date(AssetCve.ack_at))
            .order_by(func.date(AssetCve.ack_at))
        )
    ).all()

    # Build date-indexed dicts
    disc_map: dict[str, int] = {str(r.day): r.cnt for r in discovered_rows}
    ack_map: dict[str, int] = {str(r.day): r.cnt for r in acked_rows}

    # Generate 30-day range
    points: list[TrendPoint] = []
    for i in range(30):
        day = (datetime.now(timezone.utc) - timedelta(days=29 - i)).date()
        day_str = str(day)
        points.append(TrendPoint(
            date=day_str,
            cves_discovered=disc_map.get(day_str, 0),
            cves_acknowledged=ack_map.get(day_str, 0),
        ))

    # Current active asset count
    active_assets = (
        await db.execute(select(func.count()).select_from(Asset).where(Asset.is_active.is_(True)))
    ).scalar_one()

    trend_result = TrendData(points=points, active_assets=active_assets)
    await cache_set_json(_cache_key, trend_result.model_dump(), ttl=get_settings().cache_ttl_seconds)
    return trend_result
