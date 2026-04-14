"""Compensating Controls API — effective severity per (asset, cve).

Two endpoints:
  - GET /assets/{asset_id}/cves/{cve_id}/effective-severity
  - GET /assets/{asset_id}/effective-severities  (batch for all CVEs on the asset)

Both return the raw CVSS, the effective score, the list of factors that
applied, and whether the KEV clamp kicked in. The frontend must always
display the raw severity alongside the effective one.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import get_current_active_user, get_db
from netlanventory.core.compensating_controls import (
    build_context,
    compute_effective_severity,
    compute_for_asset_cve,
)
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve

logger = get_logger(__name__)

router = APIRouter(tags=["compensating-controls"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]


# ── Schemas ───────────────────────────────────────────────────────────────────


class FactorOut(BaseModel):
    rule: str
    delta: float
    evidence: str
    confidence: str


class EffectiveSeverityOut(BaseModel):
    cve_id: str
    base: float = Field(..., description="Raw CVSS base score")
    effective: float = Field(..., description="Score after compensating controls")
    downgrade: float
    kev_clamped: bool
    factors: list[FactorOut]


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get(
    "/assets/{asset_id}/cves/{cve_id}/effective-severity",
    response_model=EffectiveSeverityOut,
)
async def get_effective_severity(
    asset_id: uuid.UUID,
    cve_id: str,
    db: DbDep,
    _user: UserDep,
) -> EffectiveSeverityOut:
    result = await compute_for_asset_cve(db, asset_id, cve_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Asset or CVE not found")
    payload = result.to_dict()
    return EffectiveSeverityOut(cve_id=cve_id, **payload)


@router.get(
    "/assets/{asset_id}/effective-severities",
    response_model=list[EffectiveSeverityOut],
)
async def list_effective_severities(
    asset_id: uuid.UUID,
    db: DbDep,
    _user: UserDep,
) -> list[EffectiveSeverityOut]:
    """Compute effective severity for every CVE attached to an asset.

    Builds the ControlContext **once** for the asset, then loops over CVEs
    to keep this O(N) DB queries instead of O(N × reports).
    """
    asset = (
        await db.execute(
            select(Asset).where(Asset.id == asset_id).options(selectinload(Asset.tags))
        )
    ).scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    ctx = await build_context(db, asset)

    rows = (
        await db.execute(
            select(Cve)
            .join(AssetCve, AssetCve.cve_id == Cve.id)
            .where(AssetCve.asset_id == asset_id)
        )
    ).scalars().all()

    out: list[EffectiveSeverityOut] = []
    for cve in rows:
        eff = compute_effective_severity(cve, ctx)
        payload = eff.to_dict()
        out.append(EffectiveSeverityOut(cve_id=cve.cve_id, **payload))

    # Sort by effective desc so the UI shows the worst first
    out.sort(key=lambda x: x.effective, reverse=True)
    return out
