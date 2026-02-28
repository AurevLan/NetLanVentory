"""Assets API router."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import get_db
from netlanventory.core.crypto import encrypt
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.asset_dns import AssetDns
from netlanventory.schemas.asset import (
    AssetCreate,
    AssetList,
    AssetOut,
    AssetUpdate,
    AssetVocabularyOut,
)

router = APIRouter(prefix="/assets", tags=["assets"])

DbDep = Annotated[AsyncSession, Depends(get_db)]

_ASSET_OPTIONS = [
    selectinload(Asset.ports),
    selectinload(Asset.zap_reports),
    selectinload(Asset.cves).selectinload(AssetCve.cve),
    selectinload(Asset.dns_entries),
]


@router.get("", response_model=AssetList)
async def list_assets(
    db: DbDep,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    active_only: bool = Query(False),
) -> AssetList:
    query = select(Asset).options(*_ASSET_OPTIONS)
    if active_only:
        query = query.where(Asset.is_active.is_(True))
    query = query.offset(skip).limit(limit).order_by(Asset.created_at.desc())

    count_query = select(func.count()).select_from(Asset)
    if active_only:
        count_query = count_query.where(Asset.is_active.is_(True))

    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    result = await db.execute(query)
    assets = result.scalars().all()

    return AssetList(total=total, items=list(assets))


# NOTE: /vocabulary must be defined before /{asset_id} to avoid UUID parse conflicts
@router.get("/vocabulary", response_model=AssetVocabularyOut)
async def get_vocabulary(db: DbDep) -> AssetVocabularyOut:
    """Return distinct non-null values for editable dropdown fields."""
    os_result = await db.execute(
        select(distinct(Asset.os_family)).where(Asset.os_family.isnot(None))
    )
    device_result = await db.execute(
        select(distinct(Asset.device_type)).where(Asset.device_type.isnot(None))
    )
    return AssetVocabularyOut(
        os_family=sorted([r for r in os_result.scalars().all() if r]),
        device_type=sorted([r for r in device_result.scalars().all() if r]),
    )


@router.get("/{asset_id}", response_model=AssetOut)
async def get_asset(asset_id: uuid.UUID, db: DbDep) -> Asset:
    result = await db.execute(
        select(Asset)
        .where(Asset.id == asset_id)
        .options(*_ASSET_OPTIONS)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset


@router.get("/by-ip/{ip}", response_model=AssetOut)
async def get_asset_by_ip(ip: str, db: DbDep) -> Asset:
    result = await db.execute(
        select(Asset).where(Asset.ip == ip).options(*_ASSET_OPTIONS)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Asset with IP {ip!r} not found"
        )
    return asset


def _apply_ssh_credentials(data: dict, asset: Asset) -> None:
    """Pop write-only SSH credential fields and store their encrypted versions."""
    if pw := data.pop("ssh_password", None):
        asset.ssh_password_enc = encrypt(pw)
    if key := data.pop("ssh_private_key", None):
        asset.ssh_private_key_enc = encrypt(key)


@router.post("", response_model=AssetOut, status_code=status.HTTP_201_CREATED)
async def create_asset(payload: AssetCreate, db: DbDep) -> Asset:
    data = payload.model_dump(exclude_none=True)
    asset = Asset(**{k: v for k, v in data.items() if k not in ("ssh_password", "ssh_private_key")})
    _apply_ssh_credentials(data, asset)
    db.add(asset)
    await db.flush()
    result = await db.execute(
        select(Asset).where(Asset.id == asset.id).options(*_ASSET_OPTIONS)
    )
    return result.scalar_one()


@router.patch("/{asset_id}", response_model=AssetOut)
async def update_asset(asset_id: uuid.UUID, payload: AssetUpdate, db: DbDep) -> Asset:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    data = payload.model_dump(exclude_unset=True)
    _apply_ssh_credentials(data, asset)
    for field, value in data.items():
        setattr(asset, field, value)

    await db.flush()
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id).options(*_ASSET_OPTIONS)
    )
    return result.scalar_one()


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(asset_id: uuid.UUID, db: DbDep) -> None:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    await db.delete(asset)
