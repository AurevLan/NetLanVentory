"""Nikto web scanner router — agentless DAST complementary to ZAP.

Nikto runs locally against a remote HTTP target. No installation on the
target server is required. Detects server misconfigurations, dangerous
files/CGIs, outdated software, and CMS-specific issues.

Requires the `nikto` binary to be available on the NetLanVentory server.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import get_current_active_user, get_db
from netlanventory.core.http_safe import SsrfBlockedError, assert_url_safe
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/nikto", tags=["nikto"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]

NIKTO_BINARY = "nikto"
NIKTO_TIMEOUT = 600  # 10 minutes max per scan


class NiktoTriggerOut(BaseModel):
    status: str
    message: str
    target: str | None = None


class NiktoFinding(BaseModel):
    id: str | None
    method: str | None
    url: str
    msg: str
    osvdb_id: str | None = None


class NiktoResultOut(BaseModel):
    target: str
    port: int
    findings: list[NiktoFinding]
    total_findings: int
    scan_duration_seconds: float | None = None
    error: str | None = None


@router.post("", response_model=NiktoTriggerOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
async def trigger_nikto_scan(
    request: Request,
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DbDep,
    _user: UserDep,
    target_url: str | None = None,
    port: int = 80,
) -> NiktoTriggerOut:
    """Launch a Nikto web scan against an asset. Runs locally — agentless."""
    if not shutil.which(NIKTO_BINARY):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Nikto binary not found on the NetLanVentory server. Install with: apt install nikto",
        )

    asset = (await db.execute(
        select(Asset).where(Asset.id == asset_id)
    )).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    target = target_url or f"http://{asset.ip}:{port}"
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    try:
        assert_url_safe(target, allow_private=True)
    except SsrfBlockedError as exc:
        raise HTTPException(status_code=400, detail=f"Target rejected: {exc}") from exc

    background_tasks.add_task(_run_nikto, asset_id=asset_id, target=target)
    return NiktoTriggerOut(status="pending", message="Nikto scan queued", target=target)


@router.get("/last", response_model=NiktoResultOut | None)
async def get_last_nikto_result(
    asset_id: uuid.UUID,
    db: DbDep,
    _user: UserDep,
) -> NiktoResultOut | None:
    """Return the last Nikto scan result for an asset (stored in asset.extra_data)."""
    asset = (await db.execute(
        select(Asset).where(Asset.id == asset_id)
    )).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    nikto_data = (asset.extra_data or {}).get("nikto_last_scan")
    if not nikto_data:
        return None
    return NiktoResultOut(**nikto_data)


async def _run_nikto(asset_id: uuid.UUID, target: str) -> None:
    """Run Nikto in a subprocess and persist results."""
    from netlanventory.core.database import get_session_factory

    start = datetime.now(timezone.utc)

    # Validate target URL
    if not re.match(r"^https?://", target):
        target = f"http://{target}"

    cmd = [
        NIKTO_BINARY,
        "-h", target,
        "-Format", "json",
        "-output", "/dev/stdout",
        "-nointeractive",
        "-C", "all",  # check all CGI directories
        "-Tuning", "123456789abc",  # all test types
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=NIKTO_TIMEOUT
            )
        except TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.warning("Nikto scan timed out", target=target)
            return
    except Exception as exc:
        logger.error("Nikto subprocess error", target=target, error=str(exc))
        return

    findings: list[dict] = []
    nikto_port = 80

    if stdout_bytes:
        try:
            raw = stdout_bytes.decode("utf-8", errors="replace")
            # Nikto JSON may have multiple objects — try parsing as array or single
            data = json.loads(raw) if raw.strip().startswith("[") else [json.loads(raw)]

            for host_block in data:
                nikto_port = host_block.get("port", 80)
                for vuln in host_block.get("vulnerabilities", []):
                    findings.append({
                        "id": vuln.get("id"),
                        "method": vuln.get("method"),
                        "url": vuln.get("url", ""),
                        "msg": vuln.get("msg", ""),
                        "osvdb_id": vuln.get("OSVDB"),
                    })
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("Nikto JSON parse error", error=str(exc))

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()

    result = {
        "target": target,
        "port": nikto_port,
        "findings": findings,
        "total_findings": len(findings),
        "scan_duration_seconds": round(elapsed, 1),
    }

    # Persist in asset.extra_data
    factory = get_session_factory()
    async with factory() as session:
        asset = (await session.execute(select(Asset).where(Asset.id == asset_id))).scalar_one_or_none()
        if asset:
            extra = asset.extra_data or {}
            extra["nikto_last_scan"] = result
            asset.extra_data = extra
            await session.commit()

    logger.info("Nikto scan complete", asset_id=str(asset_id), findings=len(findings))
