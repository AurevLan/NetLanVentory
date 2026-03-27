"""Tags router — manage labels on assets."""

from __future__ import annotations

import re
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db
from netlanventory.models.asset import Asset
from netlanventory.models.asset_tag import AssetTag

router = APIRouter(prefix="/assets/{asset_id}/tags", tags=["tags"])

DbDep = Annotated[AsyncSession, Depends(get_db)]

_TAG_RE = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")


@router.get("", response_model=list[str])
async def list_tags(asset_id: uuid.UUID, db: DbDep) -> list[str]:
    await _get_asset_or_404(asset_id, db)
    result = await db.execute(
        select(AssetTag.name).where(AssetTag.asset_id == asset_id).order_by(AssetTag.name)
    )
    return list(result.scalars().all())


@router.post("/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def add_tag(asset_id: uuid.UUID, name: str, db: DbDep) -> None:
    name = name.strip().lower()
    if not _TAG_RE.match(name):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Tag must be 1-64 chars: letters, digits, -, _, . only.",
        )
    await _get_asset_or_404(asset_id, db)
    existing = await db.get(AssetTag, {"asset_id": asset_id, "name": name})
    if not existing:
        db.add(AssetTag(asset_id=asset_id, name=name))
        await db.flush()


@router.delete("/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_tag(asset_id: uuid.UUID, name: str, db: DbDep) -> None:
    name = name.strip().lower()
    tag = await db.get(AssetTag, {"asset_id": asset_id, "name": name})
    if tag:
        await db.delete(tag)
        await db.flush()


async def _get_asset_or_404(asset_id: uuid.UUID, db: AsyncSession) -> Asset:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset
