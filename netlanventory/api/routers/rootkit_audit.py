"""Rootkit detection audit router — 100% agentless.

Connects via SSH and runs pure shell commands to detect:
  - Hidden processes (ps vs /proc discrepancies)
  - Hidden/suspicious ports (deleted binaries listening)
  - Suspicious files in /dev, /tmp, /var/tmp
  - Known rootkit signatures in filesystem
  - Loaded kernel modules anomalies
  - Processes with deleted executables
  - Modified system binaries (package manager verification)

No installation required on the target — all checks use standard system commands.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from datetime import datetime, timezone
from typing import Annotated

import asyncssh

from netlanventory.core.ssh import ssh_connect
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
    except Exception as exc:
        logger.debug("ssh_cmd_failed", cmd=cmd[:80], error=str(exc))
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

            # Extract SSH params while session is open (avoids greenlet_spawn)
            ssh_kwargs = _build_ssh_kwargs(asset)
            host = str(asset.ip)
            port = asset.ssh_port or (asset.ssh_profile.ssh_port if asset.ssh_profile else None) or 22
            user = asset.ssh_user or (asset.ssh_profile.ssh_user if asset.ssh_profile else None) or "root"
            await session.commit()

        try:

            async with ssh_connect(host, port=port, username=user, **ssh_kwargs) as conn:
                # All checks run via standard system commands — no tool installation needed

                # ── Phase 1: Parallel lightweight checks ─────────────────────
                (
                    hidden_procs,
                    hidden_ports,
                    suspicious_dev,
                    suspicious_tmp,
                    kernel_modules,
                    proc_deleted,
                    immutable_files,
                    promiscuous_ifaces,
                    crontab_entries,
                    known_rootkit_files,
                ) = await asyncio.gather(
                    # Hidden processes: compare ps with /proc PIDs
                    _run_cmd(conn, r"diff <(ps -eo pid --no-headers | sort -n) <(ls /proc | grep -E '^[0-9]+$' | sort -n) 2>/dev/null | grep '^>' | head -20", timeout=30),
                    # Deleted binaries listening on ports
                    _run_cmd(conn, "ss -tlnp 2>/dev/null | grep -i 'deleted' | head -20", timeout=15),
                    # Files in /dev (should be device nodes, not regular files)
                    _run_cmd(conn, r"find /dev -type f ! -name 'MAKEDEV' 2>/dev/null | head -20", timeout=30),
                    # Hidden files in /tmp, /var/tmp
                    _run_cmd(conn, "find /tmp /var/tmp -name '.*' -type f 2>/dev/null | head -30", timeout=30),
                    # Loaded kernel modules
                    _run_cmd(conn, "lsmod 2>/dev/null | tail -n +2 | awk '{print $1}'", timeout=15),
                    # Processes with deleted executables
                    _run_cmd(conn, r"ls -la /proc/*/exe 2>/dev/null | grep '(deleted)' | head -20", timeout=30),
                    # Immutable files (could be rootkit persistence)
                    _run_cmd(conn, "lsattr -R /usr/bin /usr/sbin /bin /sbin 2>/dev/null | grep -E '^....i' | head -20", timeout=30),
                    # Promiscuous network interfaces (possible sniffer)
                    _run_cmd(conn, "ip link 2>/dev/null | grep -i promisc | head -10", timeout=10),
                    # Suspicious crontab entries (base64, curl|sh, wget|sh patterns)
                    _run_cmd(conn, r"cat /var/spool/cron/crontabs/* /etc/crontab /etc/cron.d/* 2>/dev/null | grep -iE 'base64|curl.*\|.*sh|wget.*\|.*sh|/dev/tcp|nc\s+-' | head -20", timeout=15),
                    # Known rootkit file signatures
                    _run_cmd(conn, "ls -la /usr/bin/.sshd /usr/sbin/.sshd /tmp/.ICE-unix/.* /dev/.udev/.* /dev/shm/.* 2>/dev/null | head -20", timeout=15),
                )

                # ── Phase 2: Package integrity verification ──────────────────
                pkg_verify = ""
                pkg_mgr = await _run_cmd(conn, "which dpkg 2>/dev/null && echo dpkg || (which rpm 2>/dev/null && echo rpm) || echo none", timeout=10)
                if "dpkg" in (pkg_mgr or ""):
                    # Debian/Ubuntu: verify package checksums
                    pkg_verify = await _run_cmd(conn, "dpkg --verify 2>/dev/null | head -30", timeout=60) or ""
                elif "rpm" in (pkg_mgr or ""):
                    # RHEL/CentOS: verify package checksums
                    pkg_verify = await _run_cmd(conn, "rpm -Va --nomtime 2>/dev/null | grep -E '^..5' | head -30", timeout=60) or ""

            # ── Aggregate findings ───────────────────────────────────────
            suspicious_files = []
            if suspicious_dev:
                suspicious_files.extend([f"/dev: {f}" for f in suspicious_dev.splitlines()[:10]])
            if suspicious_tmp:
                suspicious_files.extend(suspicious_tmp.splitlines()[:20])
            if known_rootkit_files:
                suspicious_files.extend([f"rootkit-sig: {f}" for f in known_rootkit_files.splitlines()[:10]])

            hidden_proc_list = [l.strip() for l in hidden_procs.splitlines() if l.strip()] if hidden_procs else []
            hidden_port_list = [l.strip() for l in hidden_ports.splitlines() if l.strip()] if hidden_ports else []
            deleted_procs = [l.strip() for l in proc_deleted.splitlines() if l.strip()] if proc_deleted else []
            immutable_list = [l.strip() for l in immutable_files.splitlines() if l.strip()] if immutable_files else []
            promisc_list = [l.strip() for l in promiscuous_ifaces.splitlines() if l.strip()] if promiscuous_ifaces else []
            suspicious_cron = [l.strip() for l in crontab_entries.splitlines() if l.strip()] if crontab_entries else []
            modified_pkgs = [l.strip() for l in pkg_verify.splitlines() if l.strip()] if pkg_verify else []

            total_infected = len([f for f in suspicious_files if "rootkit-sig" in f])
            total_suspects = len(hidden_proc_list) + len(deleted_procs) + len(suspicious_cron) + len(promisc_list)
            total_warnings = len(immutable_list) + len(modified_pkgs)

            findings = {
                "method": "agentless",
                "suspicious_files": suspicious_files,
                "hidden_processes": hidden_proc_list,
                "hidden_ports": hidden_port_list,
                "deleted_executables": deleted_procs,
                "loaded_kernel_modules": kernel_modules.splitlines() if kernel_modules else [],
                "immutable_files": immutable_list,
                "promiscuous_interfaces": promisc_list,
                "suspicious_crontabs": suspicious_cron,
                "modified_packages": modified_pkgs[:30],
            }

            async with factory() as session:
                report = (await session.execute(select(RootkitReport).where(RootkitReport.id == report_id))).scalar_one()
                report.status = "completed"
                report.tool_used = "agentless"
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
