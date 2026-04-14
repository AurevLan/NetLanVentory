"""Metasploit exploit validation router.

Uses the Metasploit RPC daemon (msfrpcd) to:
  1. Search for a Metasploit module matching each CVE on the asset
  2. Run the module in check-only mode (no actual exploitation)
  3. Parse the console output to determine if the target is vulnerable
  4. Update exploit_verified on AssetCve rows

Requirements:
  - msfrpcd running: `msfrpcd -P <password> -S -f`
  - Settings: MSFRPC_HOST, MSFRPC_PORT, MSFRPC_USER, MSFRPC_PASS, MSFRPC_SSL

The module uses the Metasploit JSON-RPC API directly via httpx (no third-party library needed).
Only CVEs with standard CVE-YYYY-NNNNN IDs can be tested.
"""

from __future__ import annotations

import asyncio
import re
import uuid
from datetime import datetime, timezone
from typing import Annotated

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import actor_from_user, get_current_active_user, get_db
from netlanventory.core.audit import log_action
from netlanventory.core.config import get_settings
from netlanventory.core.database import get_session_factory
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve
from netlanventory.models.msf_validation_report import MsfValidationReport

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/metasploit-validate", tags=["msf-validation"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)

# One Metasploit validation at a time — msfrpcd is single-threaded
_msf_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    global _msf_semaphore
    if _msf_semaphore is None:
        _msf_semaphore = asyncio.Semaphore(1)
    return _msf_semaphore


# ── Schemas ───────────────────────────────────────────────────────────────────

class MsfValidationReportOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    asset_id: uuid.UUID
    status: str
    cves_tested: int = 0
    cves_confirmed: int = 0
    cves_not_confirmed: int = 0
    cves_no_module: int = 0
    results: dict | None = None
    error_msg: str | None = None
    created_at: datetime
    updated_at: datetime


class MsfValidationTriggerOut(BaseModel):
    report_id: uuid.UUID
    queued: int
    message: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("", response_model=MsfValidationTriggerOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("3/minute")
async def trigger_msf_validation(
    request: Request,
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DbDep,
    current_user: UserDep,
) -> MsfValidationTriggerOut:
    """Validate exploitability of CVEs using Metasploit check mode.

    For each CVE linked to the asset (with a standard CVE-YYYY-NNNNN ID),
    searches for a matching Metasploit module and runs it in check-only mode.
    Updates exploit_verified on AssetCve rows with the result.
    """
    settings = get_settings()

    if not settings.msfrpc_pass:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Metasploit RPC not configured. Set MSFRPC_PASS (and optionally MSFRPC_HOST, MSFRPC_PORT).",
        )

    result = await db.execute(
        select(Asset)
        .options(selectinload(Asset.cves).selectinload(AssetCve.cve))
        .where(Asset.id == asset_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not asset.ip:
        raise HTTPException(status_code=400, detail="Asset has no IP address")

    # Eligible CVEs: standard format, not yet confirmed exploitable
    eligible: list[tuple[uuid.UUID, str]] = []
    for link in (asset.cves or []):
        cve: Cve | None = link.cve
        if cve and _CVE_RE.match(cve.cve_id):
            eligible.append((link.id, cve.cve_id))

    if not eligible:
        raise HTTPException(
            status_code=400,
            detail="No standard CVEs (CVE-YYYY-NNNNN) found on this asset.",
        )

    report = MsfValidationReport(asset_id=asset_id, status="pending")
    db.add(report)
    await db.flush()

    actor = actor_from_user(current_user)
    await log_action(
        db,
        user=actor,
        action="msf_validation.trigger",
        resource_type="asset",
        resource_id=str(asset_id),
        detail=f"{len(eligible)} CVEs queued for Metasploit check",
    )
    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(
        _run_msf_validation,
        report_id=report.id,
        asset_id=asset_id,
        asset_ip=asset.ip,
        eligible=eligible,
    )

    logger.info(
        "Metasploit validation queued",
        report_id=str(report.id),
        asset_id=str(asset_id),
        cve_count=len(eligible),
    )

    return MsfValidationTriggerOut(
        report_id=report.id,
        queued=len(eligible),
        message=f"{len(eligible)} CVE(s) will be tested via Metasploit check mode.",
    )


@router.get("", response_model=list[MsfValidationReportOut])
async def list_msf_reports(
    asset_id: uuid.UUID,
    db: DbDep,
    _user: UserDep,
) -> list[MsfValidationReport]:
    """List all Metasploit validation reports for an asset (newest first)."""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Asset not found")

    reports = await db.execute(
        select(MsfValidationReport)
        .where(MsfValidationReport.asset_id == asset_id)
        .order_by(MsfValidationReport.created_at.desc())
    )
    return list(reports.scalars().all())


@router.get("/{report_id}", response_model=MsfValidationReportOut)
async def get_msf_report(
    asset_id: uuid.UUID,
    report_id: uuid.UUID,
    db: DbDep,
    _user: UserDep,
) -> MsfValidationReport:
    """Get a specific Metasploit validation report."""
    result = await db.execute(
        select(MsfValidationReport).where(
            MsfValidationReport.id == report_id,
            MsfValidationReport.asset_id == asset_id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Metasploit validation report not found")
    return report


# ── Background task ───────────────────────────────────────────────────────────

async def _run_msf_validation(
    report_id: uuid.UUID,
    asset_id: uuid.UUID,
    asset_ip: str,
    eligible: list[tuple[uuid.UUID, str]],  # (asset_cve_id, cve_id_str)
) -> None:
    """Run Metasploit check mode for each CVE and persist results."""
    factory = get_session_factory()
    settings = get_settings()

    async with _get_semaphore():
        async with factory() as session:
            report = (
                await session.execute(
                    select(MsfValidationReport).where(MsfValidationReport.id == report_id)
                )
            ).scalar_one_or_none()
            if not report:
                return

            report.status = "running"
            await session.flush()
            await session.commit()

        # Build msfrpcd base URL
        scheme = "https" if settings.msfrpc_ssl else "http"
        base_url = f"{scheme}://{settings.msfrpc_host}:{settings.msfrpc_port}"

        per_cve_results: list[dict] = []
        confirmed_ids: set[str] = set()
        not_confirmed_ids: set[str] = set()
        no_module_ids: set[str] = set()
        auth_token: str | None = None

        try:
            async with httpx.AsyncClient(
                base_url=base_url,
                verify=False,  # msfrpcd often uses self-signed cert
                timeout=30.0,
            ) as client:
                # 1. Authenticate
                auth_token = await _msf_login(client, settings.msfrpc_user, settings.msfrpc_pass)

                # 2. Process each CVE
                for link_id, cve_id_str in eligible:
                    cve_result = await _validate_cve(
                        client, auth_token, asset_ip, cve_id_str
                    )
                    per_cve_results.append({"cve_id": cve_id_str, **cve_result})

                    if cve_result["result"] == "vulnerable":
                        confirmed_ids.add(cve_id_str)
                    elif cve_result["result"] == "no_module":
                        no_module_ids.add(cve_id_str)
                    else:
                        not_confirmed_ids.add(cve_id_str)

                # 3. Logout
                await _msf_call(client, auth_token, "auth.logout", [auth_token])

        except httpx.ConnectError as exc:
            async with factory() as session:
                report = (
                    await session.execute(
                        select(MsfValidationReport).where(MsfValidationReport.id == report_id)
                    )
                ).scalar_one_or_none()
                if report:
                    report.status = "failed"
                    report.error_msg = f"Cannot connect to msfrpcd at {base_url}: {exc}"
                    await session.commit()
            logger.error("Cannot reach msfrpcd", base_url=base_url, error=str(exc))
            return
        except Exception as exc:
            async with factory() as session:
                report = (
                    await session.execute(
                        select(MsfValidationReport).where(MsfValidationReport.id == report_id)
                    )
                ).scalar_one_or_none()
                if report:
                    report.status = "failed"
                    report.error_msg = str(exc)
                    await session.commit()
            logger.error("Metasploit validation failed", error=str(exc), exc_info=True)
            return

    # 4. Persist results (outside semaphore)
    now = datetime.now(timezone.utc)
    link_map = {cve_id: link_id for link_id, cve_id in eligible}
    all_link_ids = list(link_map.values())

    async with factory() as session:
        # Bulk-fetch all AssetCve rows in one query instead of N per-row queries
        links_result = await session.execute(
            select(AssetCve).where(AssetCve.id.in_(all_link_ids))
        )
        links_by_id = {link.id: link for link in links_result.scalars().all()}

        for cve_id_str, link_id in link_map.items():
            link = links_by_id.get(link_id)
            if not link:
                continue

            if cve_id_str in confirmed_ids:
                link.exploit_verified = True
            elif cve_id_str in no_module_ids:
                pass  # No MSF module — don't override existing nuclei result
            else:
                link.exploit_verified = False

            link.exploit_verified_at = now
            link.exploit_verified_method = "metasploit"

        report = (
            await session.execute(
                select(MsfValidationReport).where(MsfValidationReport.id == report_id)
            )
        ).scalar_one_or_none()
        if report:
            report.status = "completed"
            report.cves_tested = len(eligible)
            report.cves_confirmed = len(confirmed_ids)
            report.cves_not_confirmed = len(not_confirmed_ids)
            report.cves_no_module = len(no_module_ids)
            report.results = {"items": per_cve_results}

        await session.commit()

    logger.info(
        "Metasploit validation persisted",
        report_id=str(report_id),
        confirmed=len(confirmed_ids),
        tested=len(eligible),
    )


# ── Metasploit RPC helpers ────────────────────────────────────────────────────

async def _msf_call(client: httpx.AsyncClient, token: str, method: str, params: list) -> dict:
    """Make a Metasploit RPC call and return the result dict."""
    payload = {"method": method, "token": token, "params": params}
    resp = await client.post("/api/", json=payload, timeout=30.0)
    resp.raise_for_status()
    data = resp.json()
    if data.get("error"):
        raise RuntimeError(f"MSF RPC error: {data.get('error_message', data)}")
    return data.get("result", {})


async def _msf_login(client: httpx.AsyncClient, user: str, password: str) -> str:
    """Authenticate with msfrpcd and return the auth token."""
    payload = {"method": "auth.login", "params": [user, password]}
    resp = await client.post("/api/", json=payload, timeout=15.0)
    resp.raise_for_status()
    data = resp.json()
    if data.get("result", {}).get("result") != "success":
        raise RuntimeError(
            f"Metasploit authentication failed: {data.get('result', {}).get('error', 'unknown')}"
        )
    return data["result"]["token"]


async def _validate_cve(
    client: httpx.AsyncClient,
    token: str,
    target_ip: str,
    cve_id: str,
) -> dict:
    """Search for a Metasploit module for this CVE and run check mode.

    Returns a dict with keys: module, result, output.
    result values: vulnerable | not_vulnerable | check_unsupported | no_module | error
    """
    # Search for an exploit module matching the CVE
    try:
        search_result = await _msf_call(client, token, "module.search", [cve_id])
    except Exception as exc:
        return {"module": None, "result": "error", "output": str(exc)}

    modules = search_result if isinstance(search_result, list) else []
    exploit_modules = [
        m for m in modules
        if isinstance(m, dict) and m.get("type") == "exploit"
    ]

    if not exploit_modules:
        logger.debug("No Metasploit module found", cve_id=cve_id)
        return {"module": None, "result": "no_module", "output": "No exploit module found in Metasploit"}

    # Use the first exploit module found
    module_name = exploit_modules[0].get("fullname") or exploit_modules[0].get("name", "")

    # Create an interactive console
    console_result = await _msf_call(client, token, "console.create", [{}])
    console_id = str(console_result.get("id", "0"))

    try:
        # Send commands: select module, set RHOSTS, run check
        commands = (
            f"use {module_name}\n"
            f"set RHOSTS {target_ip}\n"
            "check\n"
        )
        await _msf_call(client, token, "console.write", [console_id, commands])

        # Poll for output (wait until not busy)
        output = await _poll_console(client, token, console_id, max_wait=120)

        result = _parse_check_output(output)
        return {"module": module_name, "result": result, "output": output[-2000:] if output else ""}

    finally:
        # Always destroy the console
        try:
            await _msf_call(client, token, "console.destroy", [console_id])
        except Exception as exc:
            logger.debug("msf_console_destroy_failed", console_id=console_id, error=str(exc))


async def _poll_console(
    client: httpx.AsyncClient,
    token: str,
    console_id: str,
    max_wait: int = 120,
) -> str:
    """Poll a Metasploit console until the prompt is idle and return accumulated output."""
    accumulated = ""
    idle_count = 0

    for _ in range(max_wait):
        await asyncio.sleep(1)
        try:
            result = await _msf_call(client, token, "console.read", [console_id])
        except Exception as exc:
            logger.debug("msf_console_read_failed", console_id=console_id, error=str(exc))
            break

        data = result.get("data", "")
        busy = result.get("busy", False)
        accumulated += data

        if not busy:
            idle_count += 1
            # Wait for 3 consecutive idle reads to confirm the command finished
            if idle_count >= 3:
                break
        else:
            idle_count = 0

    return accumulated


def _parse_check_output(output: str) -> str:
    """Parse Metasploit check output to determine vulnerability status.

    Returns one of: vulnerable | not_vulnerable | check_unsupported | error
    """
    if not output:
        return "check_unsupported"

    output_lower = output.lower()

    # Positive indicators
    if any(kw in output_lower for kw in [
        "the target is vulnerable",
        "vulnerable",
        "target appears to be vulnerable",
    ]):
        # Make sure it's not a negation
        if "not vulnerable" not in output_lower and "is not exploitable" not in output_lower:
            return "vulnerable"

    # Negative indicators
    if any(kw in output_lower for kw in [
        "the target is not exploitable",
        "not vulnerable",
        "target is not vulnerable",
        "does not appear to be vulnerable",
    ]):
        return "not_vulnerable"

    # Check not supported by this module
    if any(kw in output_lower for kw in [
        "check is not supported",
        "this module does not support check",
        "cannot reliably check",
        "no check code",
    ]):
        return "check_unsupported"

    return "check_unsupported"
