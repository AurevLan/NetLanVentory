"""CVE acknowledgment router — mark asset CVEs as accepted / false positive / in progress."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import actor_from_user, get_current_active_user, get_db
from netlanventory.core.audit import log_action
from netlanventory.models.asset_cve import AssetCve
from netlanventory.schemas.zap import AssetCveOut

router = APIRouter(prefix="/assets/{asset_id}/cves", tags=["cve-ack"])
bulk_ack_router = APIRouter(prefix="/cves", tags=["cve-ack"])

DbDep = Annotated[AsyncSession, Depends(get_db)]

_VALID_STATUSES = {"none", "accepted", "false_positive", "in_progress"}


class AckRequest(BaseModel):
    ack_status: str = Field(..., description="none | accepted | false_positive | in_progress")
    ack_note: str | None = Field(default=None, max_length=1000)


@router.patch("/{link_id}/ack", response_model=AssetCveOut)
async def acknowledge_cve(
    asset_id: uuid.UUID,
    link_id: uuid.UUID,
    payload: AckRequest,
    db: DbDep,
    current_user: Annotated[object, Depends(get_current_active_user)],
) -> AssetCveOut:
    """Set the acknowledgment status of a CVE link for an asset."""
    if payload.ack_status not in _VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"ack_status must be one of: {', '.join(sorted(_VALID_STATUSES))}",
        )

    result = await db.execute(
        select(AssetCve)
        .where(AssetCve.id == link_id, AssetCve.asset_id == asset_id)
        .options(selectinload(AssetCve.cve))
    )
    link = result.scalar_one_or_none()
    if not link:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE link not found")

    actor = actor_from_user(current_user)
    link.ack_status = payload.ack_status
    link.ack_note = payload.ack_note
    link.ack_by = actor
    link.ack_at = datetime.now(timezone.utc) if payload.ack_status != "none" else None
    await db.flush()

    await log_action(
        db,
        user=actor,
        action="cve.ack",
        resource_type="cve",
        resource_id=str(link_id),
        detail={"ack_status": payload.ack_status, "asset_id": str(asset_id)},
    )

    return AssetCveOut.from_orm_with_cve(link)


# ── Bulk acknowledge ──────────────────────────────────────────────────────────

class BulkAckRequest(BaseModel):
    link_ids: list[uuid.UUID]
    ack_status: str = Field(..., description="none | accepted | false_positive | in_progress")
    ack_note: str | None = Field(default=None, max_length=1000)


class BulkAckResult(BaseModel):
    updated: int


@bulk_ack_router.post("/bulk-ack", response_model=BulkAckResult)
async def bulk_acknowledge_cves(
    payload: BulkAckRequest,
    db: DbDep,
    current_user: Annotated[object, Depends(get_current_active_user)],
) -> BulkAckResult:
    """Bulk-set acknowledgment status for multiple CVE links."""
    if payload.ack_status not in _VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"ack_status must be one of: {', '.join(sorted(_VALID_STATUSES))}",
        )
    if not payload.link_ids:
        return BulkAckResult(updated=0)

    result = await db.execute(
        select(AssetCve)
        .where(AssetCve.id.in_(payload.link_ids))
        .options(selectinload(AssetCve.cve))
    )
    links = result.scalars().all()

    actor = actor_from_user(current_user)
    now = datetime.now(timezone.utc)
    for link in links:
        link.ack_status = payload.ack_status
        link.ack_note = payload.ack_note
        link.ack_by = actor
        link.ack_at = now if payload.ack_status != "none" else None

    await db.flush()

    await log_action(
        db,
        user=actor,
        action="cve.bulk_ack",
        resource_type="cve",
        resource_id=",".join(str(i) for i in payload.link_ids[:10]),
        detail={"ack_status": payload.ack_status, "count": len(links)},
    )
    return BulkAckResult(updated=len(links))
