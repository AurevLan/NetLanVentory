"""testssl.sh router — deep TLS/SSL audit using testssl.sh.

Flow:
  POST /assets/{asset_id}/testssl  →  202 Accepted, background scan starts
  GET  /assets/{asset_id}/testssl  →  list reports (newest first)
  GET  /assets/{asset_id}/testssl/{report_id}  →  full report with findings

testssl.sh is invoked with --jsonfile to capture machine-readable output.
Severity mapping: CRITICAL / HIGH / MEDIUM / LOW / INFO / OK

Requires testssl.sh binary at the path configured via TESTSSL_BINARY (default: testssl.sh).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
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
from netlanventory.models.testssl_report import TestsslReport

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/testssl", tags=["testssl"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
AuthDep = Annotated[object, Depends(get_current_active_user)]

# Only 1 concurrent testssl scan (it's CPU+network heavy)
_testssl_semaphore: asyncio.Semaphore | None = None

# testssl severity levels — in descending order of criticality
_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "OK", "DEBUG")

_SEVERITY_CRITICAL = {"CRITICAL"}
_SEVERITY_HIGH = {"HIGH"}
_SEVERITY_MEDIUM = {"MEDIUM"}
_SEVERITY_LOW = {"LOW", "WARN"}


def _get_semaphore() -> asyncio.Semaphore:
    global _testssl_semaphore
    if _testssl_semaphore is None:
        _testssl_semaphore = asyncio.Semaphore(1)
    return _testssl_semaphore


# ── Schemas ───────────────────────────────────────────────────────────────────


class TestsslReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    host: str | None
    port: int
    status: str | None
    grade: str | None
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    error_msg: str | None
    created_at: datetime
    updated_at: datetime


class TestsslReportDetail(TestsslReportOut):
    findings: list | None


# ── Helpers ───────────────────────────────────────────────────────────────────


def _count_severities(findings: list[dict]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = (f.get("severity") or "").upper()
        if sev in _SEVERITY_CRITICAL:
            counts["critical"] += 1
        elif sev in _SEVERITY_HIGH:
            counts["high"] += 1
        elif sev in _SEVERITY_MEDIUM:
            counts["medium"] += 1
        elif sev in _SEVERITY_LOW:
            counts["low"] += 1
        else:
            counts["info"] += 1
    return counts


def _extract_grade(findings: list[dict]) -> str | None:
    """Extract the overall grade from testssl findings (id == 'overall_grade')."""
    for f in findings:
        if f.get("id") == "overall_grade":
            return f.get("finding") or None
    return None


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", response_model=TestsslReportOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
async def trigger_testssl_scan(
    request: Request,
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DbDep,
    current_user: AuthDep,
    port: int = Query(default=443, ge=1, le=65535),
) -> TestsslReport:
    """Launch a deep TLS/SSL audit using testssl.sh (async, 202 Accepted).

    testssl.sh tests: protocol support, cipher suites, key exchange, certificate
    chain, known TLS vulnerabilities (BEAST, POODLE, Heartbleed, ROBOT, etc.).
    """
    import shutil

    settings = get_settings()
    testssl_bin = getattr(settings, "testssl_binary", "testssl.sh")

    if not shutil.which(testssl_bin):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                f"testssl.sh binary not found: {testssl_bin!r}. "
                "Install testssl.sh and ensure it is in PATH."
            ),
        )

    asset = (
        await db.execute(select(Asset).where(Asset.id == asset_id))
    ).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    host = asset.hostname or asset.ip
    if not host:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Asset has neither hostname nor IP address",
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

    report = TestsslReport(asset_id=asset_id, host=host, port=port, status="pending")
    db.add(report)
    await db.flush()

    actor = actor_from_user(current_user)
    await log_action(
        db,
        user=actor,
        action="testssl.trigger",
        resource_type="asset",
        resource_id=str(asset_id),
        detail={"host": host, "port": port},
    )

    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(
        _run_testssl,
        report_id=report.id,
        asset_id=asset_id,
        host=host,
        port=port,
    )
    logger.info("testssl scan queued", report_id=str(report.id), host=host, port=port)
    return report


@router.get("", response_model=list[TestsslReportOut])
async def list_testssl_reports(
    asset_id: uuid.UUID,
    db: DbDep,
    _auth: AuthDep,
) -> list[TestsslReport]:
    """List testssl reports for an asset (newest first)."""
    result = await db.execute(
        select(TestsslReport)
        .where(TestsslReport.asset_id == asset_id)
        .order_by(TestsslReport.created_at.desc())
    )
    return list(result.scalars().all())


@router.get("/{report_id}", response_model=TestsslReportDetail)
async def get_testssl_report(
    asset_id: uuid.UUID,
    report_id: uuid.UUID,
    db: DbDep,
    _auth: AuthDep,
) -> TestsslReportDetail:
    """Get a specific testssl report with full findings."""
    report = (
        await db.execute(
            select(TestsslReport).where(
                TestsslReport.id == report_id,
                TestsslReport.asset_id == asset_id,
            )
        )
    ).scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

    return TestsslReportDetail(
        id=report.id,
        asset_id=report.asset_id,
        host=report.host,
        port=report.port,
        status=report.status,
        grade=report.grade,
        critical_count=report.critical_count,
        high_count=report.high_count,
        medium_count=report.medium_count,
        low_count=report.low_count,
        info_count=report.info_count,
        error_msg=report.error_msg,
        created_at=report.created_at,
        updated_at=report.updated_at,
        findings=report.findings,
    )


# ── Background task ───────────────────────────────────────────────────────────


async def _run_testssl(
    report_id: uuid.UUID,
    asset_id: uuid.UUID,
    host: str,
    port: int,
) -> None:
    """Execute testssl.sh and persist results."""
    settings = get_settings()
    testssl_bin = getattr(settings, "testssl_binary", "testssl.sh")
    factory = get_session_factory()

    output_file: str | None = None

    async with _get_semaphore():
        async with factory() as session:
            report = await _fetch_report(session, report_id)
            if not report:
                return
            report.status = "running"
            await session.commit()

            try:
                out_fd, output_file = tempfile.mkstemp(suffix=".json", prefix="testssl-")
                os.close(out_fd)

                cmd: list[str] = [
                    testssl_bin,
                    "--jsonfile", output_file,
                    "--color", "0",
                    "--quiet",
                    "--warnings", "off",
                    "--sneaky",          # use a more common UA to avoid blocking
                    "--connect-timeout", "10",
                    "--openssl-timeout", "10",
                    f"{host}:{port}",
                ]

                logger.info(
                    "Running testssl.sh",
                    report_id=str(report_id),
                    host=host,
                    port=port,
                )

                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                )

                scan_timeout = getattr(settings, "testssl_scan_timeout", 300)
                timed_out = False
                try:
                    _, stderr_bytes = await asyncio.wait_for(
                        proc.communicate(), timeout=scan_timeout
                    )
                except TimeoutError:
                    proc.kill()
                    _, stderr_bytes = await proc.communicate()
                    timed_out = True
                    logger.warning(
                        "testssl scan timed out",
                        report_id=str(report_id),
                        timeout=scan_timeout,
                    )

                # Parse JSON output
                findings: list[dict] = []
                if output_file and os.path.exists(output_file):
                    try:
                        with open(output_file, encoding="utf-8", errors="replace") as fh:
                            raw = json.load(fh)
                            # testssl --jsonfile produces a JSON array at top level
                            if isinstance(raw, list):
                                findings = raw
                            elif isinstance(raw, dict):
                                # some versions wrap in {"scanResult": [...]}
                                findings = raw.get("scanResult", [raw])
                    except (json.JSONDecodeError, OSError) as exc:
                        logger.warning("testssl output parse error", error=str(exc))

                counts = _count_severities(findings)
                grade = _extract_grade(findings)

                report = await _fetch_report(session, report_id)
                if not report:
                    return

                report.status = "completed"
                report.grade = grade
                report.findings = findings
                report.critical_count = counts["critical"]
                report.high_count = counts["high"]
                report.medium_count = counts["medium"]
                report.low_count = counts["low"]
                report.info_count = counts["info"]
                if timed_out:
                    report.error_msg = (
                        f"Scan stopped after {scan_timeout}s — partial results saved."
                    )

                await session.commit()
                logger.info(
                    "testssl scan completed",
                    report_id=str(report_id),
                    grade=grade,
                    critical=counts["critical"],
                    high=counts["high"],
                )

            except Exception as exc:
                logger.error(
                    "testssl scan failed",
                    report_id=str(report_id),
                    error=str(exc),
                    exc_info=True,
                )
                report = await _fetch_report(session, report_id)
                if report:
                    report.status = "failed"
                    report.error_msg = str(exc)[:500]
                    await session.commit()
            finally:
                if output_file and os.path.exists(output_file):
                    os.unlink(output_file)


async def _fetch_report(session: AsyncSession, report_id: uuid.UUID) -> TestsslReport | None:
    result = await session.execute(
        select(TestsslReport).where(TestsslReport.id == report_id)
    )
    return result.scalar_one_or_none()
