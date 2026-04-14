"""IOC ↔ Asset correlation router.

Confronts all collected threat IOCs against all assets:
  - IP matching (asset IPs vs IOC IPs)
  - Domain matching (asset DNS entries vs IOC domains)
  - Aggregated correlation summary with severity breakdown
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import get_current_active_user, get_db
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.asset_dns import AssetDns
from netlanventory.models.threat_ioc import ThreatIoc

logger = get_logger(__name__)

router = APIRouter(prefix="/threat-intel/correlations", tags=["threat-intel"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]


# ── Schemas ───────────────────────────────────────────────────────────────────


class IocMatch(BaseModel):
    asset_id: uuid.UUID
    asset_ip: str | None
    asset_hostname: str | None
    asset_name: str | None
    ioc_id: uuid.UUID
    indicator: str
    ioc_type: str
    source: str
    severity: str
    description: str | None
    match_type: str  # ip | domain
    first_seen: datetime | None
    last_seen: datetime | None


class CorrelationSummary(BaseModel):
    total_matches: int
    affected_assets: int
    by_severity: dict[str, int]
    by_match_type: dict[str, int]
    by_source: dict[str, int]
    matches: list[IocMatch]


class AssetCorrelation(BaseModel):
    asset_id: uuid.UUID
    matches: list[IocMatch]


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("", response_model=CorrelationSummary)
@limiter.limit("10/minute")
async def get_ioc_correlations(
    request: Request,
    db: DbDep,
    _user: UserDep,
    severity: str | None = None,
    ioc_type: str | None = None,
) -> CorrelationSummary:
    """Correlate all threat IOCs against all active assets.

    Returns matched IOCs with affected asset details.
    Optionally filter by severity (critical|high|medium|low) or ioc_type (ip|domain).
    """
    # Load all active assets with their IPs and DNS entries
    assets_q = select(Asset).options(selectinload(Asset.dns_entries)).where(Asset.is_active.is_(True))
    assets_result = await db.execute(assets_q)
    assets = list(assets_result.scalars().all())

    # Build lookup maps
    ip_to_assets: dict[str, list[Asset]] = {}
    domain_to_assets: dict[str, list[Asset]] = {}

    for asset in assets:
        if asset.ip:
            ip_to_assets.setdefault(asset.ip, []).append(asset)
        for dns in (asset.dns_entries or []):
            if dns.fqdn:
                domain_to_assets.setdefault(dns.fqdn.lower(), []).append(asset)

    # Load IOCs
    ioc_q = select(ThreatIoc)
    if severity:
        ioc_q = ioc_q.where(ThreatIoc.severity == severity)
    if ioc_type:
        ioc_q = ioc_q.where(ThreatIoc.ioc_type == ioc_type)
    else:
        ioc_q = ioc_q.where(ThreatIoc.ioc_type.in_(["ip", "domain", "url"]))

    iocs_result = await db.execute(ioc_q)
    iocs = list(iocs_result.scalars().all())

    # Correlate
    matches: list[IocMatch] = []
    affected_asset_ids: set[uuid.UUID] = set()
    by_severity: dict[str, int] = {}
    by_match_type: dict[str, int] = {}
    by_source: dict[str, int] = {}

    for ioc in iocs:
        matched_assets: list[tuple[Asset, str]] = []

        if ioc.ioc_type == "ip" and ioc.indicator in ip_to_assets:
            for asset in ip_to_assets[ioc.indicator]:
                matched_assets.append((asset, "ip"))

        elif ioc.ioc_type == "domain":
            indicator_lower = ioc.indicator.lower()
            if indicator_lower in domain_to_assets:
                for asset in domain_to_assets[indicator_lower]:
                    matched_assets.append((asset, "domain"))

        elif ioc.ioc_type == "url":
            # URL IOCs: check if any asset's DNS domains appear in the URL
            import re
            url_domain_match = re.search(r"https?://([^/:]+)", ioc.indicator)
            if url_domain_match:
                url_domain = url_domain_match.group(1).lower()
                if url_domain in domain_to_assets:
                    for asset in domain_to_assets[url_domain]:
                        matched_assets.append((asset, "url"))

        for asset, match_type in matched_assets:
            match = IocMatch(
                asset_id=asset.id,
                asset_ip=asset.ip,
                asset_hostname=asset.hostname,
                asset_name=asset.name,
                ioc_id=ioc.id,
                indicator=ioc.indicator,
                ioc_type=ioc.ioc_type,
                source=ioc.source,
                severity=ioc.severity,
                description=ioc.description,
                match_type=match_type,
                first_seen=ioc.first_seen,
                last_seen=ioc.last_seen,
            )
            matches.append(match)
            affected_asset_ids.add(asset.id)
            by_severity[ioc.severity] = by_severity.get(ioc.severity, 0) + 1
            by_match_type[match_type] = by_match_type.get(match_type, 0) + 1
            by_source[ioc.source] = by_source.get(ioc.source, 0) + 1

    # Fire notifications for high/critical IOC matches (fire-and-forget)
    if matches:
        import asyncio
        from netlanventory.core.notifications import notify_ioc_match

        async def _notify_matches():
            # Only notify for high/critical severity to avoid noise
            notifiable = [m for m in matches if m.severity in ("critical", "high")]
            for m in notifiable[:10]:  # cap at 10 notifications per correlation run
                try:
                    # Build a minimal asset-like object
                    class _AssetStub:
                        def __init__(self, **kw):
                            for k, v in kw.items():
                                setattr(self, k, v)
                    stub = _AssetStub(id=m.asset_id, ip=m.asset_ip, name=m.asset_name)
                    await notify_ioc_match(
                        asset=stub,
                        ioc_indicator=m.indicator,
                        ioc_type=m.ioc_type,
                        ioc_severity=m.severity,
                        ioc_source=m.source,
                        match_type=m.match_type,
                    )
                except Exception as exc:
                    logger.warning("ioc_notification_failed", indicator=m.indicator, error=str(exc))

        asyncio.ensure_future(_notify_matches())

    return CorrelationSummary(
        total_matches=len(matches),
        affected_assets=len(affected_asset_ids),
        by_severity=by_severity,
        by_match_type=by_match_type,
        by_source=by_source,
        matches=sorted(matches, key=lambda m: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(m.severity, 4)),
    )


@router.get("/assets/{asset_id}", response_model=AssetCorrelation)
async def get_asset_ioc_correlations(
    asset_id: uuid.UUID,
    db: DbDep,
    _user: UserDep,
) -> AssetCorrelation:
    """Get all IOC matches for a specific asset."""
    asset = (
        await db.execute(
            select(Asset).options(selectinload(Asset.dns_entries)).where(Asset.id == asset_id)
        )
    ).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Collect indicators to match
    indicators = set()
    if asset.ip:
        indicators.add(("ip", asset.ip))
    for dns in (asset.dns_entries or []):
        if dns.fqdn:
            indicators.add(("domain", dns.fqdn.lower()))

    if not indicators:
        return AssetCorrelation(asset_id=asset_id, matches=[])

    # Query matching IOCs
    matches: list[IocMatch] = []

    for ioc_type, indicator in indicators:
        result = await db.execute(
            select(ThreatIoc).where(
                ThreatIoc.ioc_type == ioc_type,
                ThreatIoc.indicator == indicator,
            )
        )
        for ioc in result.scalars().all():
            matches.append(IocMatch(
                asset_id=asset.id,
                asset_ip=asset.ip,
                asset_hostname=asset.hostname,
                asset_name=asset.name,
                ioc_id=ioc.id,
                indicator=ioc.indicator,
                ioc_type=ioc.ioc_type,
                source=ioc.source,
                severity=ioc.severity,
                description=ioc.description,
                match_type=ioc_type,
                first_seen=ioc.first_seen,
                last_seen=ioc.last_seen,
            ))

    return AssetCorrelation(asset_id=asset_id, matches=matches)
