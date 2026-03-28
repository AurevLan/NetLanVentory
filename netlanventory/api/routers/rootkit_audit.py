"""Rootkit detection audit router.

Connects via SSH and runs:
  - chkrootkit (if available)
  - rkhunter (if available)
  - Manual checks for suspicious files, hidden processes/ports
"""

from __future__ import annotations

import asyncio
import re
import uuid
from datetime import datetime, timezone
from typing import Annotated

import asyncssh
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import actor_from_user, get_current_active_user, get_db
from netlanventory.core.audit import log_action
from netlanventory.core.database import get_session_factory
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.rootkit_report import RootkitReport

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/rootkit-audit", tags=["rootkit-audit"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]

_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(2)
    return _semaphore


# ── Schemas ───────────────────────────────────────────────────────────────────


class RootkitReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    asset_id: uuid.UUID
    status: str
    tool_used: str | None = None
    suspects_count: int
    warnings_count: int
    infected_count: int
    findings: dict | None = None
    error_msg: str | None = None
    created_at: datetime
    updated_at: datetime


class RootkitTriggerOut(BaseModel):
    report_id: uuid.UUID
    message: str


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", response_model=RootkitTriggerOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("3/minute")
async def trigger_rootkit_audit(
    request: Request,
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DbDep,
    current_user: UserDep,
) -> RootkitTriggerOut:
    asset = (
        await db.execute(
            select(Asset).options(selectinload(Asset.ssh_profile)).where(Asset.id == asset_id)
        )
    ).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not asset.ip:
        raise HTTPException(status_code=400, detail="Asset has no IP address")
    if not asset.has_ssh_credentials:
        raise HTTPException(status_code=400, detail="No SSH credentials configured for this asset")

    report = RootkitReport(asset_id=asset_id, status="pending")
    db.add(report)
    await db.flush()

    actor = actor_from_user(current_user)
    await log_action(db, user=actor, action="rootkit_audit.trigger", resource_type="asset", resource_id=str(asset_id))
    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(_run_rootkit_audit, report_id=report.id, asset_id=asset_id)
    return RootkitTriggerOut(report_id=report.id, message="Rootkit detection audit started")


@router.get("", response_model=list[RootkitReportOut])
async def list_rootkit_reports(asset_id: uuid.UUID, db: DbDep, _user: UserDep) -> list[RootkitReport]:
    result = await db.execute(
        select(RootkitReport)
        .where(RootkitReport.asset_id == asset_id)
        .order_by(RootkitReport.created_at.desc())
        .limit(50)
    )
    return list(result.scalars().all())


@router.get("/{report_id}", response_model=RootkitReportOut)
async def get_rootkit_report(asset_id: uuid.UUID, report_id: uuid.UUID, db: DbDep, _user: UserDep) -> RootkitReport:
    result = await db.execute(
        select(RootkitReport).where(RootkitReport.id == report_id, RootkitReport.asset_id == asset_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Rootkit report not found")
    return report


# ── Background task ───────────────────────────────────────────────────────────


async def _run_cmd(conn: asyncssh.SSHClientConnection, cmd: str, timeout: int = 60) -> str:
    try:
        result = await asyncio.wait_for(conn.run(cmd, check=False), timeout=timeout)
        return (result.stdout or "").strip()
    except Exception:
        return ""


async def _run_rootkit_audit(report_id: uuid.UUID, asset_id: uuid.UUID) -> None:
    from netlanventory.api.routers.ssh_scan import _build_ssh_kwargs

    factory = get_session_factory()

    async with _get_semaphore():
        async with factory() as session:
            report = (await session.execute(select(RootkitReport).where(RootkitReport.id == report_id))).scalar_one_or_none()
            asset = (await session.execute(
                select(Asset).options(selectinload(Asset.ssh_profile)).where(Asset.id == asset_id)
            )).scalar_one_or_none()

            if not report or not asset:
                return

            report.status = "running"
            await session.commit()

        try:
            ssh_kwargs = _build_ssh_kwargs(asset)
            host = str(asset.ip)
            port = asset.ssh_port or (asset.ssh_profile.ssh_port if asset.ssh_profile else None) or 22
            user = asset.ssh_user or (asset.ssh_profile.ssh_user if asset.ssh_profile else None) or "root"

            async with asyncssh.connect(host, port=port, username=user, known_hosts=None, **ssh_kwargs) as conn:
                # Check tool availability
                chk_avail, rkh_avail = await asyncio.gather(
                    _run_cmd(conn, "which chkrootkit 2>/dev/null", timeout=10),
                    _run_cmd(conn, "which rkhunter 2>/dev/null", timeout=10),
                )

                has_chkrootkit = bool(chk_avail)
                has_rkhunter = bool(rkh_avail)

                chkrootkit_result = {}
                rkhunter_result = {}

                # Run chkrootkit
                if has_chkrootkit:
                    chk_out = await _run_cmd(conn, "chkrootkit 2>/dev/null", timeout=300)
                    chkrootkit_result = _parse_chkrootkit(chk_out)

                # Run rkhunter (update DB first)
                if has_rkhunter:
                    await _run_cmd(conn, "rkhunter --update 2>/dev/null", timeout=60)
                    rkh_out = await _run_cmd(conn, "rkhunter --check --skip-keypress --report-warnings-only 2>/dev/null", timeout=600)
                    rkhunter_result = _parse_rkhunter(rkh_out)

                # Manual checks (always run)
                (
                    hidden_procs,
                    hidden_ports,
                    suspicious_dev,
                    suspicious_tmp,
                    kernel_modules,
                    proc_cwd_check,
                ) = await asyncio.gather(
                    # Hidden processes: compare ps output with /proc
                    _run_cmd(conn, r"diff <(ps -eo pid --no-headers | sort -n) <(ls /proc | grep -E '^[0-9]+$' | sort -n) 2>/dev/null | grep '^>' | head -20", timeout=30),
                    # Hidden ports: check for deleted binaries listening
                    _run_cmd(conn, "ss -tlnp 2>/dev/null | grep -i 'deleted' | head -20", timeout=15),
                    # Suspicious files in /dev
                    _run_cmd(conn, r"find /dev -type f ! -name 'MAKEDEV' 2>/dev/null | head -20", timeout=30),
                    # Suspicious hidden files in /tmp
                    _run_cmd(conn, "find /tmp /var/tmp -name '.*' -type f 2>/dev/null | head -30", timeout=30),
                    # Loaded kernel modules (look for unusual ones)
                    _run_cmd(conn, "lsmod 2>/dev/null | tail -n +2 | awk '{print $1}'", timeout=15),
                    # Processes with deleted executables
                    _run_cmd(conn, r"ls -la /proc/*/exe 2>/dev/null | grep '(deleted)' | head -20", timeout=30),
                )

            suspicious_files = []
            if suspicious_dev:
                suspicious_files.extend([f"/dev: {f}" for f in suspicious_dev.splitlines()[:10]])
            if suspicious_tmp:
                suspicious_files.extend([f for f in suspicious_tmp.splitlines()[:20]])

            hidden_proc_list = [l.strip() for l in hidden_procs.splitlines() if l.strip()] if hidden_procs else []
            hidden_port_list = [l.strip() for l in hidden_ports.splitlines() if l.strip()] if hidden_ports else []
            deleted_procs = [l.strip() for l in proc_cwd_check.splitlines() if l.strip()] if proc_cwd_check else []

            # Aggregate counts
            total_infected = len(chkrootkit_result.get("infected", [])) + len(rkhunter_result.get("infected", []))
            total_suspects = len(chkrootkit_result.get("suspects", [])) + len(hidden_proc_list) + len(deleted_procs)
            total_warnings = len(rkhunter_result.get("warnings", []))

            # Tool used
            tools = []
            if has_chkrootkit:
                tools.append("chkrootkit")
            if has_rkhunter:
                tools.append("rkhunter")
            tool_used = "+".join(tools) if tools else "manual"

            findings = {
                "chkrootkit": {
                    "available": has_chkrootkit,
                    **chkrootkit_result,
                },
                "rkhunter": {
                    "available": has_rkhunter,
                    **rkhunter_result,
                },
                "suspicious_files": suspicious_files,
                "hidden_processes": hidden_proc_list,
                "hidden_ports": hidden_port_list,
                "deleted_executables": deleted_procs,
                "loaded_kernel_modules": kernel_modules.splitlines() if kernel_modules else [],
            }

            async with factory() as session:
                report = (await session.execute(select(RootkitReport).where(RootkitReport.id == report_id))).scalar_one()
                report.status = "completed"
                report.tool_used = tool_used
                report.suspects_count = total_suspects
                report.warnings_count = total_warnings
                report.infected_count = total_infected
                report.findings = findings
                await session.commit()

        except Exception as exc:
            logger.error("Rootkit audit failed", report_id=str(report_id), error=str(exc), exc_info=True)
            async with factory() as session:
                report = (await session.execute(select(RootkitReport).where(RootkitReport.id == report_id))).scalar_one_or_none()
                if report:
                    report.status = "failed"
                    report.error_msg = str(exc)[:500]
                    await session.commit()


# ── Parsing helpers ───────────────────────────────────────────────────────────


def _parse_chkrootkit(raw: str) -> dict:
    infected = []
    suspects = []
    not_infected = []
    for line in raw.splitlines():
        line = line.strip()
        if "INFECTED" in line:
            infected.append(line)
        elif "not infected" in line or "not found" in line or "nothing found" in line:
            not_infected.append(line)
        elif "SUSPECT" in line or "Possible" in line.title():
            suspects.append(line)
    return {
        "infected": infected,
        "suspects": suspects,
        "not_infected_count": len(not_infected),
    }


def _parse_rkhunter(raw: str) -> dict:
    warnings = []
    infected = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if "Warning:" in line or "[ Warning ]" in line:
            warnings.append(line)
        elif "[ Infected ]" in line or "rootkit" in line.lower() and "found" in line.lower():
            infected.append(line)
    return {
        "warnings": warnings,
        "infected": infected,
    }
