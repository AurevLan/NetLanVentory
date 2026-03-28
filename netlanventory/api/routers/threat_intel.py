"""Threat intelligence router — IOC management and feed refresh."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db
from netlanventory.core.config import get_settings
from netlanventory.core.logging import get_logger
from netlanventory.core.threat_feeds import check_asset_against_iocs, refresh_abusech_feed, refresh_otx_feed
from netlanventory.models.asset import Asset
from netlanventory.models.threat_ioc import ThreatIoc

logger = get_logger(__name__)
router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])

DbDep = Annotated[AsyncSession, Depends(get_db)]


class IocResponse(BaseModel):
    id: str
    indicator: str
    ioc_type: str
    source: str
    severity: str | None
    description: str | None
    first_seen: str | None
    last_seen: str | None


class FeedRefreshResult(BaseModel):
    otx_count: int | None
    abusech_count: int | None
    errors: list[str]


class AssetIocResult(BaseModel):
    asset_id: str
    asset_ip: str | None
    iocs: list[IocResponse]


def _ioc_to_response(ioc: ThreatIoc) -> IocResponse:
    return IocResponse(
        id=str(ioc.id),
        indicator=ioc.indicator,
        ioc_type=ioc.ioc_type,
        source=ioc.source,
        severity=ioc.severity,
        description=ioc.description,
        first_seen=ioc.first_seen.isoformat() if ioc.first_seen else None,
        last_seen=ioc.last_seen.isoformat() if ioc.last_seen else None,
    )


@router.get("/iocs", response_model=list[IocResponse])
async def list_iocs(
    db: DbDep,
    ioc_type: str | None = Query(None, description="Filter by type: ip, domain, url, hash"),
    indicator: str | None = Query(None, description="Filter by indicator value"),
    severity: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
) -> list[IocResponse]:
    """List threat IOCs with optional filters."""
    q = select(ThreatIoc).order_by(ThreatIoc.last_seen.desc()).limit(limit)
    if ioc_type:
        q = q.where(ThreatIoc.ioc_type == ioc_type)
    if indicator:
        q = q.where(ThreatIoc.indicator.ilike(f"%{indicator}%"))
    if severity:
        q = q.where(ThreatIoc.severity == severity)

    rows = (await db.execute(q)).scalars().all()
    return [_ioc_to_response(r) for r in rows]


@router.post("/refresh", response_model=FeedRefreshResult)
async def refresh_feeds(background_tasks: BackgroundTasks) -> FeedRefreshResult:
    """Refresh threat intelligence feeds (runs in background)."""
    settings = get_settings()
    errors: list[str] = []

    async def _do_refresh() -> None:
        otx_count = None
        abusech_count = None

        if settings.otx_api_key:
            try:
                otx_count = await refresh_otx_feed(settings.otx_api_key)
                logger.info("OTX feed refreshed", count=otx_count)
            except Exception as exc:  # noqa: BLE001
                logger.error("OTX refresh failed", error=str(exc))

        try:
            abusech_count = await refresh_abusech_feed()
            logger.info("Abuse.ch feed refreshed", count=abusech_count)
        except Exception as exc:  # noqa: BLE001
            logger.error("Abuse.ch refresh failed", error=str(exc))

    background_tasks.add_task(_do_refresh)

    return FeedRefreshResult(
        otx_count=None,
        abusech_count=None,
        errors=errors,
    )


@router.get("/asset/{asset_id}/iocs", response_model=AssetIocResult)
async def get_asset_iocs(asset_id: str, db: DbDep) -> AssetIocResult:
    """Return threat IOCs matching this asset's IP address."""
    try:
        aid = uuid.UUID(asset_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid asset_id")

    asset = (await db.execute(select(Asset).where(Asset.id == aid))).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    if not asset.ip:
        return AssetIocResult(asset_id=asset_id, asset_ip=None, iocs=[])

    matching_dicts = await check_asset_against_iocs(asset.ip)
    iocs = [
        IocResponse(
            id=d["id"],
            indicator=d["indicator"],
            ioc_type=d["ioc_type"],
            source=d.get("source", ""),
            severity=d.get("severity"),
            description=d.get("description"),
            first_seen=d.get("first_seen"),
            last_seen=d.get("last_seen"),
        )
        for d in matching_dicts
    ]
    return AssetIocResult(
        asset_id=asset_id,
        asset_ip=asset.ip,
        iocs=iocs,
    )
