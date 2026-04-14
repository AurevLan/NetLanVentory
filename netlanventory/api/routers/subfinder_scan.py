"""Subfinder subdomain enumeration router — agentless DNS reconnaissance.

Runs the `subfinder` binary locally to enumerate subdomains for a given
domain (e.g., from an asset's DNS entries). Discovered subdomains are
upserted as AssetDns entries.

100% agentless — runs locally, queries public DNS sources.
Requires the `subfinder` binary on the NetLanVentory server.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_current_active_user, get_db
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.asset_dns import AssetDns

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/subfinder", tags=["subfinder"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]

SUBFINDER_BINARY = "subfinder"
SUBFINDER_TIMEOUT = 120  # 2 minutes

# Strict FQDN: labels of [a-z0-9-], TLD ≥ 2 chars. Refuse IP literals, schemes,
# paths, wildcards — defeats injection of subfinder flags or scan diversion.
_FQDN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$"
)


class SubfinderTriggerOut(BaseModel):
    status: str
    message: str
    domain: str


class SubfinderResultOut(BaseModel):
    domain: str
    subdomains: list[str]
    new_count: int
    total_count: int


@router.post("", response_model=SubfinderTriggerOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
async def trigger_subfinder(
    request: Request,
    asset_id: uuid.UUID,
    domain: str,
    background_tasks: BackgroundTasks,
    db: DbDep,
    _user: UserDep,
) -> SubfinderTriggerOut:
    """Launch subdomain enumeration for a domain. Runs locally — agentless."""
    if not shutil.which(SUBFINDER_BINARY):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="subfinder binary not found. Install from: https://github.com/projectdiscovery/subfinder",
        )

    asset = (await db.execute(
        select(Asset).where(Asset.id == asset_id)
    )).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Validate domain (strict FQDN, no flags/paths/IPs)
    domain = domain.strip().lower()
    if not _FQDN_RE.match(domain):
        raise HTTPException(status_code=400, detail="Invalid domain (must be a strict FQDN)")

    background_tasks.add_task(_run_subfinder, asset_id=asset_id, domain=domain)
    return SubfinderTriggerOut(status="pending", message="Subfinder enumeration queued", domain=domain)


@router.get("/last", response_model=SubfinderResultOut | None)
async def get_last_subfinder_result(
    asset_id: uuid.UUID,
    db: DbDep,
    _user: UserDep,
) -> SubfinderResultOut | None:
    """Return the last subfinder result for an asset."""
    asset = (await db.execute(
        select(Asset).where(Asset.id == asset_id)
    )).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    data = (asset.extra_data or {}).get("subfinder_last_scan")
    if not data:
        return None
    return SubfinderResultOut(**data)


async def _run_subfinder(asset_id: uuid.UUID, domain: str) -> None:
    """Run subfinder and upsert discovered subdomains as AssetDns entries."""
    from netlanventory.core.database import get_session_factory

    cmd = [
        SUBFINDER_BINARY,
        "-d", domain,
        "-silent",
        "-all",
        "-timeout", "30",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=SUBFINDER_TIMEOUT
            )
        except TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.warning("Subfinder timed out", domain=domain)
            return
    except Exception as exc:
        logger.error("Subfinder subprocess error", domain=domain, error=str(exc))
        return

    subdomains = []
    if stdout_bytes:
        for line in stdout_bytes.decode("utf-8", errors="replace").splitlines():
            sub = line.strip().lower()
            if sub and "." in sub:
                subdomains.append(sub)

    # Deduplicate
    subdomains = sorted(set(subdomains))

    # Upsert as AssetDns entries
    factory = get_session_factory()
    new_count = 0

    async with factory() as session:
        for fqdn in subdomains:
            existing = (await session.execute(
                select(AssetDns).where(
                    AssetDns.asset_id == asset_id,
                    AssetDns.fqdn == fqdn,
                )
            )).scalar_one_or_none()

            if not existing:
                session.add(AssetDns(
                    asset_id=asset_id,
                    fqdn=fqdn,
                    record_type="CNAME",
                    source="subfinder",
                ))
                new_count += 1

        # Store result summary
        asset = (await session.execute(select(Asset).where(Asset.id == asset_id))).scalar_one_or_none()
        if asset:
            extra = asset.extra_data or {}
            extra["subfinder_last_scan"] = {
                "domain": domain,
                "subdomains": subdomains,
                "new_count": new_count,
                "total_count": len(subdomains),
            }
            asset.extra_data = extra

        await session.commit()

    logger.info(
        "Subfinder complete",
        asset_id=str(asset_id),
        domain=domain,
        subdomains=len(subdomains),
        new=new_count,
    )
