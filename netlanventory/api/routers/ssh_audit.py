"""ssh-audit router — SSH server configuration audit.

Flow:
  POST /assets/{asset_id}/ssh-audit  →  202 Accepted, background scan starts
  GET  /assets/{asset_id}/ssh-audit  →  list reports (newest first)
  GET  /assets/{asset_id}/ssh-audit/{report_id}  →  full report

Uses jtesta/ssh-audit (https://github.com/jtesta/ssh-audit) invoked with
--json output flag. Detects:
  - Weak/deprecated kex, encryption, MAC algorithms
  - Weak host key types (DSA, short RSA)
  - Known CVEs (Terrapin CVE-2023-48795, etc.)
  - Compliance deviations (NIST, BSI, Distro)

Requires ssh-audit binary at path configured via SSH_AUDIT_BINARY (default: ssh-audit).
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import actor_from_user, get_current_active_user, get_db
from netlanventory.core.audit import log_action
from netlanventory.core.config import get_settings
from netlanventory.core.database import get_session_factory
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.ssh_audit_report import SshAuditReport

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/ssh-audit", tags=["ssh-audit-config"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
AuthDep = Annotated[object, Depends(get_current_active_user)]

_semaphore: asyncio.Semaphore | None = None

# ssh-audit severity levels
_LEVEL_CRITICAL = {"critical"}  # ssh-audit uses "critical" for CVEs like Terrapin
_LEVEL_HIGH = {"fail"}          # algorithms that should never be used
_LEVEL_MEDIUM = {"warn"}        # deprecated but not immediately dangerous
_LEVEL_LOW = {"info"}           # informational


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(2)
    return _semaphore


# ── Schemas ───────────────────────────────────────────────────────────────────


class SshAuditReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    host: str | None
    port: int
    status: str | None
    banner: str | None
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    error_msg: str | None
    created_at: datetime
    updated_at: datetime


class SshAuditReportDetail(SshAuditReportOut):
    kex_algorithms: list | None
    encryption_algorithms: list | None
    mac_algorithms: list | None
    host_key_algorithms: list | None
    recommendations: list | None
    raw_output: dict | None


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", response_model=SshAuditReportOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("10/minute")
async def trigger_ssh_audit(
    request: Request,
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DbDep,
    current_user: AuthDep,
    port: int = Query(default=22, ge=1, le=65535),
) -> SshAuditReport:
    """Launch an SSH configuration audit using ssh-audit (async, 202 Accepted).

    Tests kex algorithms, encryption ciphers, MAC algorithms, host key types,
    and known SSH CVEs (Terrapin, etc.).
    """
    import shutil

    settings = get_settings()
    ssh_audit_bin = getattr(settings, "ssh_audit_binary", "ssh-audit")

    if not shutil.which(ssh_audit_bin):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                f"ssh-audit binary not found: {ssh_audit_bin!r}. "
                "Install ssh-audit: pip install ssh-audit  or  apt install ssh-audit"
            ),
        )

    asset = (
        await db.execute(select(Asset).where(Asset.id == asset_id))
    ).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    host = asset.ip or asset.hostname
    if not host:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Asset has no IP address or hostname",
        )

    # Validate host and port to prevent command injection
    if not re.match(r"^[a-zA-Z0-9._-]+$", host):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid host or port",
        )
    try:
        port_int = int(port)
        if not (1 <= port_int <= 65535):
            raise ValueError
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid host or port",
        )

    report = SshAuditReport(asset_id=asset_id, host=host, port=port, status="pending")
    db.add(report)
    await db.flush()

    actor = actor_from_user(current_user)
    await log_action(
        db,
        user=actor,
        action="ssh_audit.trigger",
        resource_type="asset",
        resource_id=str(asset_id),
        detail={"host": host, "port": port},
    )

    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(
        _run_ssh_audit,
        report_id=report.id,
        asset_id=asset_id,
        host=host,
        port=port,
    )
    logger.info("ssh-audit queued", report_id=str(report.id), host=host, port=port)
    return report


@router.get("", response_model=list[SshAuditReportOut])
async def list_ssh_audit_reports(
    asset_id: uuid.UUID,
    db: DbDep,
    _auth: AuthDep,
) -> list[SshAuditReport]:
    """List SSH audit reports for an asset (newest first)."""
    result = await db.execute(
        select(SshAuditReport)
        .where(SshAuditReport.asset_id == asset_id)
        .order_by(SshAuditReport.created_at.desc())
    )
    return list(result.scalars().all())


@router.get("/{report_id}", response_model=SshAuditReportDetail)
async def get_ssh_audit_report(
    asset_id: uuid.UUID,
    report_id: uuid.UUID,
    db: DbDep,
    _auth: AuthDep,
) -> SshAuditReportDetail:
    """Get a specific SSH audit report with full algorithm details."""
    report = (
        await db.execute(
            select(SshAuditReport).where(
                SshAuditReport.id == report_id,
                SshAuditReport.asset_id == asset_id,
            )
        )
    ).scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    return SshAuditReportDetail(
        id=report.id,
        asset_id=report.asset_id,
        host=report.host,
        port=report.port,
        status=report.status,
        banner=report.banner,
        critical_count=report.critical_count,
        high_count=report.high_count,
        medium_count=report.medium_count,
        low_count=report.low_count,
        error_msg=report.error_msg,
        created_at=report.created_at,
        updated_at=report.updated_at,
        kex_algorithms=report.kex_algorithms,
        encryption_algorithms=report.encryption_algorithms,
        mac_algorithms=report.mac_algorithms,
        host_key_algorithms=report.host_key_algorithms,
        recommendations=report.recommendations,
        raw_output=report.raw_output,
    )


# ── Background task ───────────────────────────────────────────────────────────


def _parse_ssh_audit_output(data: dict) -> dict:
    """Parse ssh-audit JSON output into structured fields.

    ssh-audit --json produces:
      {
        "banner": {"raw": "SSH-2.0-OpenSSH_8.4", ...},
        "kex": [{"algorithm": "...", "notes": {...}}, ...],
        "enc": [...],
        "mac": [...],
        "key": [...],
        "cves": [{"name": "CVE-...", "cvss": ..., "description": "..."}, ...],
        "recommendations": {"critical": [...], "warning": [...], ...}
      }
    """
    result: dict = {
        "banner": None,
        "kex_algorithms": [],
        "encryption_algorithms": [],
        "mac_algorithms": [],
        "host_key_algorithms": [],
        "recommendations": [],
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
    }

    # Banner
    banner_info = data.get("banner") or {}
    result["banner"] = banner_info.get("raw") or None

    def _algo_list(items: list[dict], label: str) -> list[dict]:
        """Extract algorithm name + worst level from a list of ssh-audit entries."""
        out = []
        for item in (items or []):
            algo = item.get("algorithm") or item.get("name") or ""
            notes = item.get("notes") or {}
            # notes contains keys like "fail", "warn", "info" each being list of strings
            level = "info"
            if notes.get("fail"):
                level = "fail"
            elif notes.get("warn"):
                level = "warn"
            out.append({"algorithm": algo, "level": level, "notes": notes})
        return out

    result["kex_algorithms"] = _algo_list(data.get("kex") or [], "kex")
    result["encryption_algorithms"] = _algo_list(data.get("enc") or [], "enc")
    result["mac_algorithms"] = _algo_list(data.get("mac") or [], "mac")
    result["host_key_algorithms"] = _algo_list(data.get("key") or [], "key")

    # CVEs are critical findings
    cves = data.get("cves") or []
    result["critical_count"] = len(cves)

    # Count fail/warn/info across all algorithm lists
    for algo_list in (
        result["kex_algorithms"],
        result["encryption_algorithms"],
        result["mac_algorithms"],
        result["host_key_algorithms"],
    ):
        for algo in algo_list:
            lvl = algo.get("level", "")
            if lvl == "fail":
                result["high_count"] += 1
            elif lvl == "warn":
                result["medium_count"] += 1
            else:
                result["low_count"] += 1

    # Recommendations
    recs_raw = data.get("recommendations") or {}
    recs: list[dict] = []
    for severity, items in recs_raw.items():
        if isinstance(items, dict):
            for category, algo_list in items.items():
                for algo in (algo_list or []):
                    recs.append({"severity": severity, "category": category, "algorithm": algo})
        elif isinstance(items, list):
            for item in items:
                recs.append({"severity": severity, "item": item})
    result["recommendations"] = recs

    return result


async def _run_ssh_audit(
    report_id: uuid.UUID,
    asset_id: uuid.UUID,
    host: str,
    port: int,
) -> None:
    """Execute ssh-audit and persist results."""
    settings = get_settings()
    ssh_audit_bin = getattr(settings, "ssh_audit_binary", "ssh-audit")
    factory = get_session_factory()

    async with _get_semaphore():
        async with factory() as session:
            report = await _fetch_report(session, report_id)
            if not report:
                return
            report.status = "running"
            await session.commit()

            try:
                cmd: list[str] = [
                    ssh_audit_bin,
                    "--json",
                    "--timeout=10",
                    "-p", str(port),
                    host,
                ]

                logger.info(
                    "Running ssh-audit",
                    report_id=str(report_id),
                    host=host,
                    port=port,
                )

                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                try:
                    stdout_bytes, stderr_bytes = await asyncio.wait_for(
                        proc.communicate(), timeout=60
                    )
                except TimeoutError:
                    proc.kill()
                    stdout_bytes, stderr_bytes = await proc.communicate()
                    logger.warning("ssh-audit timed out", report_id=str(report_id))

                # Parse JSON from stdout
                raw_data: dict = {}
                try:
                    raw_data = json.loads(stdout_bytes.decode("utf-8", errors="replace"))
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    logger.warning("ssh-audit JSON parse error", error=str(exc))

                parsed = _parse_ssh_audit_output(raw_data)

                report = await _fetch_report(session, report_id)
                if not report:
                    return

                report.status = "completed"
                report.banner = parsed["banner"]
                report.critical_count = parsed["critical_count"]
                report.high_count = parsed["high_count"]
                report.medium_count = parsed["medium_count"]
                report.low_count = parsed["low_count"]
                report.kex_algorithms = parsed["kex_algorithms"]
                report.encryption_algorithms = parsed["encryption_algorithms"]
                report.mac_algorithms = parsed["mac_algorithms"]
                report.host_key_algorithms = parsed["host_key_algorithms"]
                report.recommendations = parsed["recommendations"]
                report.raw_output = raw_data if raw_data else None

                await session.commit()
                logger.info(
                    "ssh-audit completed",
                    report_id=str(report_id),
                    critical=parsed["critical_count"],
                    high=parsed["high_count"],
                    medium=parsed["medium_count"],
                )

            except Exception as exc:
                logger.error(
                    "ssh-audit failed",
                    report_id=str(report_id),
                    error=str(exc),
                    exc_info=True,
                )
                report = await _fetch_report(session, report_id)
                if report:
                    report.status = "failed"
                    report.error_msg = str(exc)[:500]
                    await session.commit()


async def _fetch_report(session: AsyncSession, report_id: uuid.UUID) -> SshAuditReport | None:
    result = await session.execute(
        select(SshAuditReport).where(SshAuditReport.id == report_id)
    )
    return result.scalar_one_or_none()
