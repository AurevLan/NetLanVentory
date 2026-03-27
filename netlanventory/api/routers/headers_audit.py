"""HTTP Security Headers audit router.

Fetches the target URL and audits the presence and configuration of HTTP security headers:
  - Strict-Transport-Security (HSTS)
  - Content-Security-Policy (CSP)
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
  - Access-Control-Allow-Origin (CORS — wildcard = misconfigured)

Optionally triggers a ZAP active scan after the headers check.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import AnyHttpUrl, BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import actor_from_user, get_current_active_user, get_db
from netlanventory.core.audit import log_action
from netlanventory.core.config import get_settings
from netlanventory.core.database import get_session_factory
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.headers_audit_report import HeadersAuditReport

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/headers-audit", tags=["headers-audit"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]

# ── Header rules ──────────────────────────────────────────────────────────────

# Each entry: (required, validator_fn or None, misconfiguration description)
_HEADERS_SPEC: dict[str, tuple[bool, object, str]] = {
    "Strict-Transport-Security": (
        True,
        lambda v: "max-age=" in v.lower(),
        "HSTS header must include max-age directive",
    ),
    "Content-Security-Policy": (
        True,
        None,
        "CSP header is missing",
    ),
    "X-Frame-Options": (
        True,
        lambda v: v.strip().upper() in ("DENY", "SAMEORIGIN"),
        "X-Frame-Options must be DENY or SAMEORIGIN",
    ),
    "X-Content-Type-Options": (
        True,
        lambda v: v.strip().lower() == "nosniff",
        "X-Content-Type-Options must be 'nosniff'",
    ),
    "Referrer-Policy": (
        True,
        None,
        "Referrer-Policy header is missing",
    ),
    "Permissions-Policy": (
        False,  # not required but recommended
        None,
        "Permissions-Policy header is missing (recommended)",
    ),
    "Access-Control-Allow-Origin": (
        False,
        lambda v: v.strip() != "*",
        "CORS wildcard (*) allows any origin — potential data exposure",
    ),
}

_REQUIRED_HEADERS = [h for h, (req, _, _d) in _HEADERS_SPEC.items() if req]


# ── Schemas ───────────────────────────────────────────────────────────────────

class HeadersAuditRequest(BaseModel):
    target_url: AnyHttpUrl = Field(..., description="URL to audit (e.g. https://192.168.1.1)")
    active_zap_scan: bool = Field(
        False,
        description="Trigger a ZAP active scan after headers check (requires ZAP running)",
    )


class HeadersAuditReportOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    asset_id: uuid.UUID
    target_url: str | None
    status: str
    score: int | None = None
    findings: dict | None = None
    error_msg: str | None = None
    created_at: datetime
    updated_at: datetime


class HeadersAuditTriggerOut(BaseModel):
    report_id: uuid.UUID
    message: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("", response_model=HeadersAuditTriggerOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("10/minute")
async def trigger_headers_audit(
    request: Request,
    asset_id: uuid.UUID,
    payload: HeadersAuditRequest,
    background_tasks: BackgroundTasks,
    db: DbDep,
    current_user: UserDep,
) -> HeadersAuditTriggerOut:
    """Audit HTTP security headers for an asset and optionally trigger a ZAP active scan."""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    target_url_str = str(payload.target_url)

    report = HeadersAuditReport(
        asset_id=asset_id,
        status="pending",
        target_url=target_url_str,
    )
    db.add(report)
    await db.flush()

    actor = actor_from_user(current_user)
    await log_action(
        db,
        user=actor,
        action="headers_audit.trigger",
        resource_type="asset",
        resource_id=str(asset_id),
        detail={"target_url": target_url_str, "active_zap_scan": payload.active_zap_scan},
    )
    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(
        _run_headers_audit,
        report_id=report.id,
        asset_id=asset_id,
        target_url=target_url_str,
        active_zap_scan=payload.active_zap_scan,
    )
    logger.info("Headers audit queued", report_id=str(report.id), target=target_url_str)

    return HeadersAuditTriggerOut(
        report_id=report.id,
        message="Headers audit queued. Poll GET /headers-audit for results.",
    )


@router.get("", response_model=list[HeadersAuditReportOut])
async def list_headers_audit_reports(
    asset_id: uuid.UUID,
    db: DbDep,
    _user: UserDep,
) -> list[HeadersAuditReport]:
    """List all headers audit reports for an asset (newest first)."""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Asset not found")

    reports = await db.execute(
        select(HeadersAuditReport)
        .where(HeadersAuditReport.asset_id == asset_id)
        .order_by(HeadersAuditReport.created_at.desc())
    )
    return list(reports.scalars().all())


@router.get("/{report_id}", response_model=HeadersAuditReportOut)
async def get_headers_audit_report(
    asset_id: uuid.UUID,
    report_id: uuid.UUID,
    db: DbDep,
    _user: UserDep,
) -> HeadersAuditReport:
    """Get a specific headers audit report."""
    result = await db.execute(
        select(HeadersAuditReport).where(
            HeadersAuditReport.id == report_id,
            HeadersAuditReport.asset_id == asset_id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Headers audit report not found")
    return report


# ── Background task ───────────────────────────────────────────────────────────

async def _run_headers_audit(
    report_id: uuid.UUID,
    asset_id: uuid.UUID,
    target_url: str,
    active_zap_scan: bool,
) -> None:
    """Fetch the target URL and audit HTTP security headers."""
    factory = get_session_factory()

    async with factory() as session:
        report = (
            await session.execute(
                select(HeadersAuditReport).where(HeadersAuditReport.id == report_id)
            )
        ).scalar_one_or_none()
        if not report:
            return

        report.status = "running"
        await session.flush()

        try:
            findings = await _check_headers(target_url)

            # Optionally trigger ZAP active scan
            if active_zap_scan:
                zap_alerts = await _run_zap_active_scan(target_url)
                findings["active_scan"] = True
                findings["active_scan_alerts"] = zap_alerts
            else:
                findings["active_scan"] = False

            # Score: required-headers present + correctly configured
            present_required = [
                h for h in _REQUIRED_HEADERS
                if h in findings.get("present", [])
            ]
            score = round(100 * len(present_required) / len(_REQUIRED_HEADERS)) if _REQUIRED_HEADERS else 0

            report.score = score
            report.findings = findings
            report.status = "completed"

        except httpx.ConnectError as exc:
            report.status = "failed"
            report.error_msg = f"Connection failed: {exc}"
        except Exception as exc:
            logger.error("Headers audit failed", report_id=str(report_id), error=str(exc), exc_info=True)
            report.status = "failed"
            report.error_msg = str(exc)

        await session.commit()
    logger.info("Headers audit completed", report_id=str(report_id))


async def _check_headers(target_url: str) -> dict:
    """Fetch the URL and classify each security header."""
    present: list[str] = []
    missing: list[str] = []
    misconfigured: list[dict] = []
    details: dict[str, str] = {}

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=15.0,
        verify=False,  # self-signed certs common on internal assets
    ) as client:
        response = await client.get(target_url)

    response_headers = {k.lower(): v for k, v in response.headers.items()}
    details["http_status"] = str(response.status_code)
    details["final_url"] = str(response.url)

    for header_name, (required, validator, misconfig_desc) in _HEADERS_SPEC.items():
        key = header_name.lower()
        value = response_headers.get(key)

        if value is None:
            # Header not present at all
            if required:
                missing.append(header_name)
            details[header_name] = None
        else:
            details[header_name] = value
            if validator is not None:
                try:
                    valid = validator(value)
                except Exception:
                    valid = False
                if not valid:
                    misconfigured.append({
                        "header": header_name,
                        "value": value,
                        "reason": misconfig_desc,
                    })
                else:
                    present.append(header_name)
            else:
                present.append(header_name)

    return {
        "present": present,
        "missing": missing,
        "misconfigured": misconfigured,
        "details": details,
    }


async def _run_zap_active_scan(target_url: str) -> list[dict]:
    """Trigger a ZAP active scan and return its alerts."""
    settings = get_settings()
    api_key = settings.zap_api_key

    try:
        async with httpx.AsyncClient(base_url=settings.zap_api_url, timeout=30.0) as zap:
            # New ZAP session
            await zap.get("/JSON/core/action/newSession/", params={"apikey": api_key})

            # Spider first
            resp = await zap.get(
                "/JSON/spider/action/scan/",
                params={"url": target_url, "apikey": api_key},
            )
            spider_id = resp.json().get("scan", "0")
            await _poll_zap(
                zap, "/JSON/spider/view/status/",
                params={"scanId": spider_id, "apikey": api_key},
                max_wait=120,
            )

            # Active scan
            resp = await zap.get(
                "/JSON/ascan/action/scan/",
                params={"url": target_url, "recurse": "true", "apikey": api_key},
            )
            ascan_id = resp.json().get("scan", "0")
            await _poll_zap(
                zap, "/JSON/ascan/view/status/",
                params={"scanId": ascan_id, "apikey": api_key},
                max_wait=1800,
            )

            # Fetch alerts
            resp = await zap.get(
                "/JSON/core/view/alerts/",
                params={"baseurl": target_url, "start": "0", "count": "2000", "apikey": api_key},
            )
            return resp.json().get("alerts", [])

    except httpx.ConnectError:
        logger.warning("ZAP not reachable — active scan skipped", target=target_url)
        return []
    except Exception as exc:
        logger.error("ZAP active scan failed", error=str(exc))
        return []


async def _poll_zap(
    zap: httpx.AsyncClient,
    path: str,
    params: dict,
    max_wait: int = 300,
) -> None:
    """Poll a ZAP status endpoint until complete (status = 100) or timeout."""
    import asyncio
    for _ in range(max_wait // 3):
        await asyncio.sleep(3)
        try:
            resp = await zap.get(path, params=params)
            pct = int(resp.json().get("status", 0))
            if pct >= 100:
                return
        except Exception as exc:
            logger.warning("ZAP poll error — aborting poll", path=path, error=str(exc))
            return
