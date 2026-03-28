"""Scheduled network scans — CRUD + manual trigger for recurring rescans."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db, require_admin
from netlanventory.models.scheduled_scan import ScheduledScan

router = APIRouter(prefix="/scheduled-scans", tags=["scheduled-scans"])

DbDep = Annotated[AsyncSession, Depends(get_db)]


# ── Schemas ──────────────────────────────────────────────────────────────────

class ScheduledScanCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, examples=["Daily LAN rescan"])
    target: str = Field(..., min_length=3, max_length=100, examples=["192.168.1.0/24"])
    modules: str = Field(
        default="arp_sweep,port_scanner,service_detector,os_fingerprint",
        max_length=500,
        examples=["arp_sweep,port_scanner,service_detector,os_fingerprint"],
    )
    interval_hours: int = Field(default=24, ge=1, le=8760, examples=[24])
    enabled: bool = Field(default=True)


class ScheduledScanUpdate(BaseModel):
    name: str | None = None
    target: str | None = None
    modules: str | None = None
    interval_hours: int | None = Field(default=None, ge=1, le=8760)
    enabled: bool | None = None


class ScheduledScanOut(BaseModel):
    id: str
    name: str
    target: str
    modules: str
    interval_hours: int
    enabled: bool
    last_run_at: str | None
    last_status: str | None
    last_error: str | None
    last_scan_id: str | None
    run_count: int
    created_at: str | None
    updated_at: str | None

    model_config = {"from_attributes": True}


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.get("", response_model=list[ScheduledScanOut])
async def list_scheduled_scans(db: DbDep) -> list[ScheduledScan]:
    """List all scheduled scan configurations."""
    result = await db.execute(
        select(ScheduledScan).order_by(ScheduledScan.created_at.desc())
    )
    return list(result.scalars().all())


@router.post("", response_model=ScheduledScanOut, status_code=status.HTTP_201_CREATED)
async def create_scheduled_scan(
    payload: ScheduledScanCreate,
    db: DbDep,
    _admin=Depends(require_admin),
) -> ScheduledScan:
    """Create a new scheduled scan (admin only)."""
    scan = ScheduledScan(
        name=payload.name,
        target=payload.target,
        modules=payload.modules,
        interval_hours=payload.interval_hours,
        enabled=payload.enabled,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    return scan


@router.get("/{scan_id}", response_model=ScheduledScanOut)
async def get_scheduled_scan(scan_id: uuid.UUID, db: DbDep) -> ScheduledScan:
    """Get a specific scheduled scan configuration."""
    result = await db.execute(
        select(ScheduledScan).where(ScheduledScan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    return scan


@router.patch("/{scan_id}", response_model=ScheduledScanOut)
async def update_scheduled_scan(
    scan_id: uuid.UUID,
    payload: ScheduledScanUpdate,
    db: DbDep,
    _admin=Depends(require_admin),
) -> ScheduledScan:
    """Update a scheduled scan configuration (admin only)."""
    result = await db.execute(
        select(ScheduledScan).where(ScheduledScan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(scan, field, value)
    await db.flush()
    await db.refresh(scan)
    return scan


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scheduled_scan(
    scan_id: uuid.UUID,
    db: DbDep,
    _admin=Depends(require_admin),
) -> None:
    """Delete a scheduled scan configuration (admin only)."""
    result = await db.execute(
        select(ScheduledScan).where(ScheduledScan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    await db.delete(scan)


@router.post("/{scan_id}/trigger", status_code=status.HTTP_202_ACCEPTED)
async def trigger_scheduled_scan(
    scan_id: uuid.UUID,
    db: DbDep,
    _admin=Depends(require_admin),
) -> dict[str, Any]:
    """Manually trigger a scheduled scan now (admin only)."""
    import asyncio
    from datetime import datetime, timezone
    from netlanventory.models.scan import Scan

    result = await db.execute(
        select(ScheduledScan).where(ScheduledScan.id == scan_id)
    )
    scheduled = result.scalar_one_or_none()
    if not scheduled:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")

    modules = [m.strip() for m in scheduled.modules.split(",") if m.strip()]

    # Create a Scan record
    scan = Scan(
        target=scheduled.target,
        status="pending",
        modules_run=modules,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    # Update scheduled scan tracking
    scheduled.last_run_at = datetime.now(timezone.utc)
    scheduled.last_scan_id = str(scan.id)
    scheduled.last_status = "pending"
    scheduled.run_count = (scheduled.run_count or 0) + 1
    await db.flush()

    # Launch background task
    from netlanventory.api.routers.scans import _run_scan
    asyncio.create_task(
        _run_scan(scan.id, scheduled.target, modules, {}),
        name=f"scheduled-scan-{scheduled.id}-{scan.id}",
    )

    return {
        "scheduled_scan_id": str(scheduled.id),
        "scan_id": str(scan.id),
        "target": scheduled.target,
        "modules": modules,
        "status": "pending",
    }
