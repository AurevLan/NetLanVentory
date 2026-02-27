"""Scans API router — create, list, retrieve scans and trigger module execution."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import get_db, get_module_registry
from netlanventory.core.logging import get_logger
from netlanventory.core.registry import ModuleRegistry
from netlanventory.models.scan import Scan
from netlanventory.models.scan_result import ScanResult
from netlanventory.schemas.scan import ScanCreate, ScanList, ScanOut

router = APIRouter(prefix="/scans", tags=["scans"])
logger = get_logger(__name__)

DbDep = Annotated[AsyncSession, Depends(get_db)]
RegistryDep = Annotated[ModuleRegistry, Depends(get_module_registry)]


@router.get("", response_model=ScanList)
async def list_scans(
    db: DbDep,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=200),
    status_filter: str | None = Query(None, alias="status"),
) -> ScanList:
    query = select(Scan).options(selectinload(Scan.results))
    if status_filter:
        query = query.where(Scan.status == status_filter)
    query = query.offset(skip).limit(limit).order_by(Scan.created_at.desc())

    count_q = select(func.count()).select_from(Scan)
    if status_filter:
        count_q = count_q.where(Scan.status == status_filter)

    total = (await db.execute(count_q)).scalar_one()
    result = await db.execute(query)
    scans = result.scalars().all()
    return ScanList(total=total, items=list(scans))


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: uuid.UUID, db: DbDep) -> Scan:
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.results))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.post("", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: DbDep,
    registry: RegistryDep,
) -> Scan:
    # Validate module names upfront
    unknown = [m for m in payload.modules if registry.get(m) is None]
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown modules: {unknown}. Available: {registry.names()}",
        )

    scan = Scan(
        target=payload.target,
        status="pending",
        modules_run=payload.modules,
    )
    db.add(scan)
    await db.commit()
    # Re-query with results eagerly loaded to avoid lazy-load during serialization
    result = await db.execute(
        select(Scan).where(Scan.id == scan.id).options(selectinload(Scan.results))
    )
    scan = result.scalar_one()

    background_tasks.add_task(
        _run_scan,
        scan_id=scan.id,
        target=payload.target,
        modules=payload.modules,
        options=payload.options,
    )

    return scan


@router.post("/{scan_id}/rerun", response_model=ScanOut, status_code=status.HTTP_202_ACCEPTED)
async def rerun_scan(
    scan_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DbDep,
) -> Scan:
    """Create a new scan using the same target and modules as an existing scan."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    original = result.scalar_one_or_none()
    if not original:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")

    scan = Scan(
        target=original.target,
        status="pending",
        modules_run=original.modules_run,
    )
    db.add(scan)
    await db.commit()
    result = await db.execute(
        select(Scan).where(Scan.id == scan.id).options(selectinload(Scan.results))
    )
    scan = result.scalar_one()

    background_tasks.add_task(
        _run_scan,
        scan_id=scan.id,
        target=scan.target,
        modules=scan.modules_run or [],
        options={},
    )

    logger.info("Rerun scan queued", original_scan_id=str(scan_id), new_scan_id=str(scan.id))
    return scan


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(scan_id: uuid.UUID, db: DbDep) -> None:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    await db.delete(scan)


# ── Background scan execution ────────────────────────────────────────────────

async def _run_scan(
    scan_id: uuid.UUID,
    target: str,
    modules: list[str],
    options: dict[str, Any],
) -> None:
    """Execute all requested modules sequentially and persist results."""
    from netlanventory.core.database import get_session_factory
    from netlanventory.core.registry import get_registry

    registry = get_registry()
    factory = get_session_factory()

    async with factory() as session:
        result = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            return

        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        await session.commit()

        summary: dict[str, Any] = {"modules": {}}
        overall_status = "completed"

        for module_name in modules:
            module_cls = registry.get(module_name)
            if not module_cls:
                logger.warning("Module not found during scan", name=module_name, scan_id=scan_id)
                continue

            module_instance = module_cls()
            module_options = {"target": target, **options.get(module_name, {})}

            logger.info("Running module", module=module_name, scan_id=str(scan_id))
            try:
                module_result = await module_instance.run(session, module_options)
                await session.commit()

                scan_result = ScanResult(
                    scan_id=scan.id,
                    module_name=module_name,
                    status="success",
                    raw_output=module_result,
                )
                summary["modules"][module_name] = {
                    "status": "success",
                    "assets_found": module_result.get("assets_found", 0),
                }
            except Exception as exc:
                logger.error("Module failed", module=module_name, error=str(exc), exc_info=True)
                await session.rollback()
                scan_result = ScanResult(
                    scan_id=scan.id,
                    module_name=module_name,
                    status="error",
                    error_msg=str(exc),
                )
                summary["modules"][module_name] = {"status": "error", "error": str(exc)}
                overall_status = "completed_with_errors"

            session.add(scan_result)
            await session.commit()

        # Finalize scan
        result = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan:
            scan.status = overall_status
            scan.finished_at = datetime.now(timezone.utc)
            scan.summary = summary
            await session.commit()

        logger.info("Scan complete", scan_id=str(scan_id), status=overall_status)
