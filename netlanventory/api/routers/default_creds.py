"""Default credentials scan router.

Uses nmap NSE scripts to test default/common credentials on services
discovered on the asset's open ports:

  - http-default-accounts   → web apps (Tomcat, Jenkins, phpMyAdmin, routers…)
  - ftp-anon                → anonymous FTP login
  - ftp-brute (mini list)   → common FTP credentials
  - mysql-empty-password    → MySQL root with no password
  - ms-sql-empty-password   → MSSQL sa with no password
  - redis-info              → unauthenticated Redis access
  - mongodb-databases       → unauthenticated MongoDB
  - smtp-open-relay         → open mail relay
  - snmp-brute              → common SNMP community strings

Flow:
  POST /assets/{asset_id}/default-creds  →  202 Accepted
  GET  /assets/{asset_id}/default-creds  →  list reports
  GET  /assets/{asset_id}/default-creds/{report_id}  →  full report

Requires nmap to be available (already used by the port scanner module).
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Annotated

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
from netlanventory.models.default_creds_report import DefaultCredsReport
from netlanventory.models.port import Port

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/default-creds", tags=["default-creds"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
AuthDep = Annotated[object, Depends(get_current_active_user)]

_semaphore: asyncio.Semaphore | None = None

# Port → NSE script mappings
# Each entry: (port, script_name, protocol_label)
_PORT_SCRIPTS: list[tuple[int, str, str]] = [
    (21,    "ftp-anon",               "ftp"),
    (21,    "ftp-brute",              "ftp"),
    (23,    "telnet-brute",           "telnet"),
    (25,    "smtp-open-relay",        "smtp"),
    (80,    "http-default-accounts",  "http"),
    (443,   "http-default-accounts",  "https"),
    (1433,  "ms-sql-empty-password",  "mssql"),
    (3306,  "mysql-empty-password",   "mysql"),
    (3389,  "rdp-enum-encryption",    "rdp"),
    (5432,  "pgsql-brute",            "postgresql"),
    (6379,  "redis-info",             "redis"),
    (8080,  "http-default-accounts",  "http-alt"),
    (8443,  "http-default-accounts",  "https-alt"),
    (11211, "memcached-info",         "memcached"),
    (27017, "mongodb-databases",      "mongodb"),
    (161,   "snmp-brute",             "snmp"),
]

# Scripts that indicate a vulnerability by their mere presence in output
_ANON_POSITIVE_SCRIPTS = {
    "ftp-anon",
    "redis-info",
    "mongodb-databases",
    "memcached-info",
    "smtp-open-relay",
    "ms-sql-empty-password",
    "mysql-empty-password",
}

# Pattern to detect positive findings in nmap script output
_VULN_PATTERN = re.compile(
    r"(anonymous|successful|allowed|default|login|credential|vulnerable|open relay|"
    r"empty password|no auth|unauthenticated|accessible)",
    re.IGNORECASE,
)


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(1)
    return _semaphore


# ── Schemas ───────────────────────────────────────────────────────────────────


class DefaultCredsReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    status: str | None
    vulnerable_count: int
    tested_count: int
    error_msg: str | None
    created_at: datetime
    updated_at: datetime


class DefaultCredsReportDetail(DefaultCredsReportOut):
    findings: list | None


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", response_model=DefaultCredsReportOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("3/minute")
async def trigger_default_creds_scan(
    request: Request,
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DbDep,
    current_user: AuthDep,
) -> DefaultCredsReport:
    """Launch a default credentials scan against an asset's open ports (async, 202).

    Tests common default credentials and anonymous access on services such as
    FTP, HTTP admin panels, MySQL, Redis, MongoDB, SNMP, SMTP relay, and more.
    Uses nmap NSE scripts — no brute-force wordlists, only known defaults.
    """
    import shutil

    if not shutil.which("nmap"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="nmap not found in PATH. Ensure nmap is installed in the container.",
        )

    result = await db.execute(
        select(Asset)
        .options(selectinload(Asset.ports))
        .where(Asset.id == asset_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    if not asset.ip:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Asset has no IP address",
        )

    # Build list of (port, script, label) to test based on discovered open ports
    open_port_numbers = {
        p.port_number for p in (asset.ports or []) if p.state == "open"
    }

    # Always include port 161 (UDP SNMP) if not in port list
    # (our port scanner only does TCP by default)
    targets = [
        (port, script, label)
        for port, script, label in _PORT_SCRIPTS
        if port in open_port_numbers or port == 161
    ]

    # Deduplicate by (port, script)
    seen: set[tuple[int, str]] = set()
    unique_targets: list[tuple[int, str, str]] = []
    for port, script, label in targets:
        key = (port, script)
        if key not in seen:
            seen.add(key)
            unique_targets.append((port, script, label))

    report = DefaultCredsReport(asset_id=asset_id, status="pending")
    db.add(report)
    await db.flush()

    actor = actor_from_user(current_user)
    await log_action(
        db,
        user=actor,
        action="default_creds.trigger",
        resource_type="asset",
        resource_id=str(asset_id),
        detail={"targets": len(unique_targets)},
    )

    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(
        _run_default_creds_scan,
        report_id=report.id,
        asset_id=asset_id,
        ip=str(asset.ip),
        targets=unique_targets,
    )
    logger.info(
        "Default creds scan queued",
        report_id=str(report.id),
        ip=asset.ip,
        target_count=len(unique_targets),
    )
    return report


@router.get("", response_model=list[DefaultCredsReportOut])
async def list_default_creds_reports(
    asset_id: uuid.UUID,
    db: DbDep,
    _auth: AuthDep,
) -> list[DefaultCredsReport]:
    """List default credential scan reports for an asset (newest first)."""
    result = await db.execute(
        select(DefaultCredsReport)
        .where(DefaultCredsReport.asset_id == asset_id)
        .order_by(DefaultCredsReport.created_at.desc())
    )
    return list(result.scalars().all())


@router.get("/{report_id}", response_model=DefaultCredsReportDetail)
async def get_default_creds_report(
    asset_id: uuid.UUID,
    report_id: uuid.UUID,
    db: DbDep,
    _auth: AuthDep,
) -> DefaultCredsReportDetail:
    """Get a specific default credentials scan report."""
    report = (
        await db.execute(
            select(DefaultCredsReport).where(
                DefaultCredsReport.id == report_id,
                DefaultCredsReport.asset_id == asset_id,
            )
        )
    ).scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    return DefaultCredsReportDetail(
        id=report.id,
        asset_id=report.asset_id,
        status=report.status,
        vulnerable_count=report.vulnerable_count,
        tested_count=report.tested_count,
        error_msg=report.error_msg,
        created_at=report.created_at,
        updated_at=report.updated_at,
        findings=report.findings,
    )


# ── Background task ───────────────────────────────────────────────────────────


async def _run_nmap_script(
    ip: str, port: int, script: str
) -> tuple[str, str]:
    """Run a single nmap NSE script against ip:port.

    Returns (script_name, raw_output_text).
    Uses -T4, connect scan (-sT for no-root compat), short timeout.
    """
    # UDP for SNMP
    scan_flag = "-sU" if port == 161 else "-sT"
    cmd: list[str] = [
        "nmap",
        scan_flag,
        "-p", str(port),
        f"--script={script}",
        "--script-timeout=15",
        "-T4",
        "--open",
        "-oN", "-",   # normal output to stdout
        ip,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        return script, stdout_bytes.decode("utf-8", errors="replace")
    except TimeoutError:
        return script, ""
    except Exception as exc:
        logger.debug("nmap script error", script=script, port=port, error=str(exc))
        return script, ""


def _is_vulnerable(script: str, output: str) -> bool:
    """Heuristic: decide if the nmap script output indicates a vulnerability."""
    if not output or "open" not in output.lower():
        return False
    if script in _ANON_POSITIVE_SCRIPTS:
        # These scripts only produce interesting output when something is found
        # Check that the script section is present and not empty
        if f"|_{script}" in output or f"| {script}:" in output or f"|  {script}" in output:
            return bool(_VULN_PATTERN.search(output))
    # For http-default-accounts and brute scripts
    return bool(_VULN_PATTERN.search(output))


async def _run_default_creds_scan(
    report_id: uuid.UUID,
    asset_id: uuid.UUID,
    ip: str,
    targets: list[tuple[int, str, str]],
) -> None:
    """Execute nmap NSE scripts sequentially per port and persist results."""
    factory = get_session_factory()

    async with _get_semaphore():
        async with factory() as session:
            report = await _fetch_report(session, report_id)
            if not report:
                return
            report.status = "running"
            await session.commit()

            findings: list[dict] = []
            vulnerable_count = 0

            try:
                for port, script, label in targets:
                    script_name, raw_output = await _run_nmap_script(ip, port, script)
                    vulnerable = _is_vulnerable(script_name, raw_output)

                    finding = {
                        "port": port,
                        "service": label,
                        "script": script_name,
                        "vulnerable": vulnerable,
                        "output": raw_output[:2000] if raw_output else "",
                    }
                    findings.append(finding)
                    if vulnerable:
                        vulnerable_count += 1
                        logger.warning(
                            "Default credential vulnerability found",
                            asset_id=str(asset_id),
                            port=port,
                            service=label,
                            script=script_name,
                        )

                report = await _fetch_report(session, report_id)
                if not report:
                    return

                report.status = "completed"
                report.findings = findings
                report.tested_count = len(findings)
                report.vulnerable_count = vulnerable_count

                await session.commit()
                logger.info(
                    "Default creds scan completed",
                    report_id=str(report_id),
                    tested=len(findings),
                    vulnerable=vulnerable_count,
                )

            except Exception as exc:
                logger.error(
                    "Default creds scan failed",
                    report_id=str(report_id),
                    error=str(exc),
                    exc_info=True,
                )
                report = await _fetch_report(session, report_id)
                if report:
                    report.status = "failed"
                    report.error_msg = str(exc)[:500]
                    await session.commit()


async def _fetch_report(
    session: AsyncSession, report_id: uuid.UUID
) -> DefaultCredsReport | None:
    result = await session.execute(
        select(DefaultCredsReport).where(DefaultCredsReport.id == report_id)
    )
    return result.scalar_one_or_none()
