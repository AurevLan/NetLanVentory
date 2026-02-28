"""DNS entries router — manage DNS names associated with assets."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db
from netlanventory.models.asset import Asset
from netlanventory.models.asset_dns import AssetDns
from netlanventory.schemas.asset import AssetDnsCreate, AssetDnsOut

router = APIRouter(prefix="/assets/{asset_id}/dns", tags=["dns"])

DbDep = Annotated[AsyncSession, Depends(get_db)]


async def _get_asset_or_404(asset_id: uuid.UUID, db: AsyncSession) -> Asset:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset


@router.get("", response_model=list[AssetDnsOut])
async def list_dns_entries(asset_id: uuid.UUID, db: DbDep) -> list[AssetDns]:
    """List all DNS entries for an asset."""
    await _get_asset_or_404(asset_id, db)
    result = await db.execute(
        select(AssetDns)
        .where(AssetDns.asset_id == asset_id)
        .order_by(AssetDns.created_at.asc())
    )
    return list(result.scalars().all())


@router.post("", response_model=AssetDnsOut, status_code=status.HTTP_201_CREATED)
async def add_dns_entry(
    asset_id: uuid.UUID, payload: AssetDnsCreate, db: DbDep
) -> AssetDns:
    """Add a DNS entry to an asset."""
    await _get_asset_or_404(asset_id, db)

    entry = AssetDns(asset_id=asset_id, fqdn=payload.fqdn.strip())
    db.add(entry)
    await db.flush()
    await db.refresh(entry)
    return entry


@router.delete("/{dns_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_dns_entry(
    asset_id: uuid.UUID, dns_id: uuid.UUID, db: DbDep
) -> None:
    """Remove a DNS entry from an asset."""
    await _get_asset_or_404(asset_id, db)
    result = await db.execute(
        select(AssetDns).where(
            AssetDns.id == dns_id,
            AssetDns.asset_id == asset_id,
        )
    )
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="DNS entry not found")
    await db.delete(entry)
