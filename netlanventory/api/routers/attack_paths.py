"""Attack Path Graph API (innovation #1).

Read endpoints to surface the most dangerous bounded-hop attack chains
between internet-facing entry points and crown-jewel assets, plus an
admin-only POST to trigger a full recomputation.

Recomputation should normally be driven by a nightly scheduler hook (to
add in a follow-up commit). The admin endpoint exists so an operator can
force a refresh after a major change (new tag, new IOC import, …).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_current_active_user, get_db, require_admin
from netlanventory.core.attack_paths import refresh_attack_paths
from netlanventory.core.logging import get_logger
from netlanventory.models.attack_path import AttackPath

logger = get_logger(__name__)

router = APIRouter(prefix="/attack-paths", tags=["attack-paths"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]
AdminDep = Annotated[object, Depends(require_admin)]


class HopOut(BaseModel):
    asset_id: str
    edge_type: str
    weight: float
    cve_id: str | None = None
    evidence: str = ""


class AttackPathOut(BaseModel):
    id: uuid.UUID
    source_asset_id: uuid.UUID
    target_asset_id: uuid.UUID
    hops: list[HopOut]
    total_weight: float
    hop_count: int
    computed_at: datetime


class RefreshOut(BaseModel):
    paths_persisted: int
    message: str


def _row_to_out(row: AttackPath) -> AttackPathOut:
    return AttackPathOut(
        id=row.id,
        source_asset_id=row.source_asset_id,
        target_asset_id=row.target_asset_id,
        hops=[HopOut(**h) for h in (row.hops or [])],
        total_weight=row.total_weight,
        hop_count=row.hop_count,
        computed_at=row.computed_at,
    )


@router.get("/critical", response_model=list[AttackPathOut])
async def list_critical_paths(
    db: DbDep,
    _user: UserDep,
    limit: int = 20,
) -> list[AttackPathOut]:
    """Top-N highest-weight attack paths across the whole inventory."""
    rows = (
        await db.execute(
            select(AttackPath).order_by(desc(AttackPath.total_weight)).limit(min(limit, 200))
        )
    ).scalars().all()
    return [_row_to_out(r) for r in rows]


@router.get("/asset/{asset_id}/inbound", response_model=list[AttackPathOut])
async def list_inbound_paths(
    asset_id: uuid.UUID, db: DbDep, _user: UserDep, limit: int = 50,
) -> list[AttackPathOut]:
    """Paths whose target is this asset — *what threatens it*."""
    rows = (
        await db.execute(
            select(AttackPath)
            .where(AttackPath.target_asset_id == asset_id)
            .order_by(desc(AttackPath.total_weight))
            .limit(min(limit, 200))
        )
    ).scalars().all()
    return [_row_to_out(r) for r in rows]


@router.get("/asset/{asset_id}/outbound", response_model=list[AttackPathOut])
async def list_outbound_paths(
    asset_id: uuid.UUID, db: DbDep, _user: UserDep, limit: int = 50,
) -> list[AttackPathOut]:
    """Paths whose source is this asset — *what it can reach if compromised*."""
    rows = (
        await db.execute(
            select(AttackPath)
            .where(AttackPath.source_asset_id == asset_id)
            .order_by(desc(AttackPath.total_weight))
            .limit(min(limit, 200))
        )
    ).scalars().all()
    return [_row_to_out(r) for r in rows]


@router.post("/refresh", response_model=RefreshOut, status_code=status.HTTP_200_OK)
async def refresh_paths(db: DbDep, _admin: AdminDep) -> RefreshOut:
    """Admin-only: recompute the entire attack graph now."""
    try:
        count = await refresh_attack_paths(db)
    except Exception as exc:  # noqa: BLE001
        logger.error("attack_paths_refresh_failed", error=str(exc), exc_info=True)
        raise HTTPException(status_code=500, detail=f"Refresh failed: {exc}") from exc
    return RefreshOut(paths_persisted=count, message=f"Persisted {count} attack paths")
