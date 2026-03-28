"""Baseline / drift detection router — snapshot asset state and detect changes."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import actor_from_user, get_current_active_user, get_db
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.asset_baseline import AssetBaseline
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve
from netlanventory.models.port import Port
from netlanventory.models.ssh_scan_report import SshScanReport

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/baseline", tags=["baseline"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
AuthDep = Annotated[object, Depends(get_current_active_user)]


# ── Pydantic schemas ──────────────────────────────────────────────────────────


class BaselineCreate(BaseModel):
    notes: str | None = None


class BaselineOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    created_at: datetime
    created_by: str | None
    ports_snapshot: list | None
    packages_snapshot: list | None
    cves_snapshot: list | None
    notes: str | None


class DriftOut(BaseModel):
    new_ports: list[int]
    removed_ports: list[int]
    new_cves: list[str]
    resolved_cves: list[str]
    new_packages: list[str]
    removed_packages: list[str]
    has_drift: bool


# ── Helpers ───────────────────────────────────────────────────────────────────


async def _get_current_ports(db: AsyncSession, asset_id: uuid.UUID) -> list[int]:
    result = await db.execute(
        select(Port).where(Port.asset_id == asset_id, Port.state == "open")
    )
    return [p.port_number for p in result.scalars().all()]


async def _get_current_cves(db: AsyncSession, asset_id: uuid.UUID) -> list[str]:
    result = await db.execute(
        select(AssetCve, Cve)
        .join(Cve, AssetCve.cve_id == Cve.id)
        .where(AssetCve.asset_id == asset_id)
    )
    return [row[1].cve_id for row in result.all()]


async def _get_latest_packages(db: AsyncSession, asset_id: uuid.UUID) -> list[str]:
    """Return packages from the most recent completed SSH scan for the asset."""
    result = await db.execute(
        select(SshScanReport)
        .where(
            SshScanReport.asset_id == asset_id,
            SshScanReport.status == "completed",
        )
        .order_by(SshScanReport.created_at.desc())
        .limit(1)
    )
    report = result.scalar_one_or_none()
    if not report:
        return []
    # SSH scan reports do not store the package list directly — we approximate
    # by returning an empty list if no structured package data is available.
    # Future: store packages_json on SshScanReport.
    return []


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", response_model=BaselineOut, status_code=status.HTTP_201_CREATED)
async def create_baseline(
    asset_id: uuid.UUID,
    body: BaselineCreate,
    db: DbDep,
    auth: AuthDep,
) -> AssetBaseline:
    """Create a new baseline snapshot for an asset."""
    asset = (
        await db.execute(select(Asset).where(Asset.id == asset_id))
    ).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    ports = await _get_current_ports(db, asset_id)
    cves = await _get_current_cves(db, asset_id)
    packages = await _get_latest_packages(db, asset_id)

    actor = actor_from_user(auth)

    baseline = AssetBaseline(
        asset_id=asset_id,
        created_by=actor,
        ports_snapshot=ports,
        packages_snapshot=packages,
        cves_snapshot=cves,
        notes=body.notes,
    )
    db.add(baseline)
    await db.flush()
    await db.commit()
    await db.refresh(baseline)
    logger.info("Baseline created", asset_id=str(asset_id), baseline_id=str(baseline.id))
    return baseline


@router.get("", response_model=list[BaselineOut])
async def list_baselines(
    asset_id: uuid.UUID,
    db: DbDep,
    _auth: AuthDep,
) -> list[AssetBaseline]:
    """List all baselines for an asset (newest first)."""
    result = await db.execute(
        select(AssetBaseline)
        .where(AssetBaseline.asset_id == asset_id)
        .order_by(AssetBaseline.created_at.desc())
    )
    return list(result.scalars().all())


@router.get("/{baseline_id}/diff", response_model=DriftOut)
async def diff_baseline(
    asset_id: uuid.UUID,
    baseline_id: uuid.UUID,
    db: DbDep,
    _auth: AuthDep,
) -> DriftOut:
    """Compare a baseline snapshot with the current asset state.

    Returns added/removed ports, CVEs, and packages since the baseline was taken.
    """
    baseline = (
        await db.execute(
            select(AssetBaseline).where(
                AssetBaseline.id == baseline_id,
                AssetBaseline.asset_id == asset_id,
            )
        )
    ).scalar_one_or_none()
    if not baseline:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Baseline not found")

    # Current state
    current_ports = set(await _get_current_ports(db, asset_id))
    current_cves = set(await _get_current_cves(db, asset_id))
    current_packages = set(await _get_latest_packages(db, asset_id))

    # Baseline state
    baseline_ports = set(baseline.ports_snapshot or [])
    baseline_cves = set(baseline.cves_snapshot or [])
    baseline_packages = set(baseline.packages_snapshot or [])

    new_ports = sorted(current_ports - baseline_ports)
    removed_ports = sorted(baseline_ports - current_ports)
    new_cves = sorted(current_cves - baseline_cves)
    resolved_cves = sorted(baseline_cves - current_cves)
    new_packages = sorted(current_packages - baseline_packages)
    removed_packages = sorted(baseline_packages - current_packages)

    has_drift = bool(new_ports or removed_ports or new_cves or resolved_cves
                     or new_packages or removed_packages)

    return DriftOut(
        new_ports=new_ports,
        removed_ports=removed_ports,
        new_cves=new_cves,
        resolved_cves=resolved_cves,
        new_packages=new_packages,
        removed_packages=removed_packages,
        has_drift=has_drift,
    )
