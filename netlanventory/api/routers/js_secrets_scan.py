"""JavaScript bundle secret/API key leak scanner.

Crawls a web page, extracts all referenced JS files, and scans them for
leaked API keys, tokens, and credentials using regex patterns.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated
from urllib.parse import urljoin

import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import AnyHttpUrl, BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import actor_from_user, get_current_active_user, get_db
from netlanventory.core.audit import log_action
from netlanventory.core.database import get_session_factory
from netlanventory.core.http_safe import SafeAsyncClient, SsrfBlockedError, assert_url_safe
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.js_secrets_report import JsSecretsReport

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/js-secrets", tags=["js-secrets"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]

# ── Secret patterns ──────────────────────────────────────────────────────────
# Each: (name, severity, compiled_regex)
# Patterns are designed to match real keys, not placeholders

# All quantifiers are bounded to defeat ReDoS on adversarial JS bundles.
_SECRET_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("AWS Access Key", "critical", re.compile(r'AKIA[0-9A-Z]{16}')),
    ("AWS Secret Key", "critical", re.compile(r'(?:aws_secret_access_key|AWS_SECRET)["\s:=]{1,5}([A-Za-z0-9/+=]{40})')),
    ("Stripe Secret Key", "critical", re.compile(r'sk_live_[0-9a-zA-Z]{24,80}')),
    ("Stripe Publishable Key", "low", re.compile(r'pk_live_[0-9a-zA-Z]{24,80}')),
    ("GitHub Token", "critical", re.compile(r'gh[ps]_[A-Za-z0-9_]{36,80}')),
    ("GitHub OAuth", "high", re.compile(r'gho_[A-Za-z0-9_]{36,80}')),
    ("GitLab Token", "critical", re.compile(r'glpat-[A-Za-z0-9\-_]{20,80}')),
    ("Google API Key", "high", re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("Firebase Config", "medium", re.compile(r'firebase[A-Za-z]{0,20}["\s:=]{1,5}["\'][A-Za-z0-9\-_.]{1,80}\.firebaseapp\.com')),
    ("Supabase Anon Key", "medium", re.compile(r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,500}')),
    ("Supabase Service Role", "critical", re.compile(r'(?:service_role|SERVICE_ROLE)["\s:=]{1,5}eyJ[A-Za-z0-9_-]{50,500}')),
    ("Slack Token", "critical", re.compile(r'xox[bprs]-[0-9]{10,30}-[0-9a-zA-Z]{10,80}')),
    ("Slack Webhook", "high", re.compile(r'hooks\.slack\.com/services/T[A-Z0-9]{1,20}/B[A-Z0-9]{1,20}/[A-Za-z0-9]{1,40}')),
    ("Twilio API Key", "high", re.compile(r'SK[0-9a-fA-F]{32}')),
    ("SendGrid API Key", "critical", re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}')),
    ("Mailgun API Key", "critical", re.compile(r'key-[0-9a-zA-Z]{32}')),
    ("Heroku API Key", "high", re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')),
    ("Private Key", "critical", re.compile(r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----')),
    ("JWT Secret", "critical", re.compile(r'(?:jwt_secret|JWT_SECRET|secret_key|SECRET_KEY)["\s:=]{1,5}["\'][A-Za-z0-9+/=]{16,200}')),
    ("Generic API Key", "medium", re.compile(r'(?:api[_-]?key|apikey|API_KEY)["\s:=]{1,5}["\'][A-Za-z0-9]{20,200}["\']')),
    ("Generic Secret", "medium", re.compile(r'(?:secret|SECRET|password|PASSWORD)["\s:=]{1,5}["\'][^\s"\']{8,200}["\']')),
    ("Bearer Token", "high", re.compile(r'Bearer\s{1,3}[A-Za-z0-9\-._~+/]{20,500}={0,3}')),
]

# False positive filters
_FP_PATTERNS = [
    re.compile(r'YOUR_|EXAMPLE_|REPLACE_|TODO|xxx|placeholder|sample|fake|mock|dummy|test_|demo', re.IGNORECASE),
    re.compile(r'process\.env\.|import\.meta\.env\.|ENV\[', re.IGNORECASE),
    re.compile(r'\$\{|<%=|{{'),  # template variables
]

# Max JS file size to scan (512KB)
_MAX_JS_SIZE = 512 * 1024


# ── Schemas ──────────────────────────────────────────────────────────────────


class JsSecretsRequest(BaseModel):
    target_url: AnyHttpUrl = Field(..., description="URL to crawl for JS bundles")


class JsSecretsReportOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    asset_id: uuid.UUID
    target_url: str | None
    status: str
    scripts_scanned: int | None = None
    secrets_found: int | None = None
    findings: dict | None = None
    error_msg: str | None = None
    created_at: datetime
    updated_at: datetime


class JsSecretsTriggerOut(BaseModel):
    report_id: uuid.UUID
    message: str


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", response_model=JsSecretsTriggerOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
async def trigger_js_secrets_scan(
    request: Request,
    asset_id: uuid.UUID,
    payload: JsSecretsRequest,
    background_tasks: BackgroundTasks,
    db: DbDep,
    current_user: UserDep,
) -> JsSecretsTriggerOut:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Asset not found")

    target_url = str(payload.target_url)
    try:
        assert_url_safe(target_url, allow_private=True)
    except SsrfBlockedError as exc:
        raise HTTPException(status_code=400, detail=f"Target rejected: {exc}") from exc

    report = JsSecretsReport(asset_id=asset_id, status="pending", target_url=target_url)
    db.add(report)
    await db.flush()

    actor = actor_from_user(current_user)
    await log_action(
        db, user=actor, action="js_secrets.trigger",
        resource_type="asset", resource_id=str(asset_id),
        detail={"target_url": target_url},
    )
    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(_run_js_secrets_scan, report_id=report.id, target_url=target_url)
    logger.info("JS secrets scan queued", report_id=str(report.id), target=target_url)

    return JsSecretsTriggerOut(
        report_id=report.id,
        message="JS secrets scan queued. Poll GET /js-secrets for results.",
    )


@router.get("", response_model=list[JsSecretsReportOut])
async def list_js_secrets_reports(
    asset_id: uuid.UUID, db: DbDep, _user: UserDep,
) -> list[JsSecretsReport]:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Asset not found")
    reports = await db.execute(
        select(JsSecretsReport)
        .where(JsSecretsReport.asset_id == asset_id)
        .order_by(JsSecretsReport.created_at.desc())
        .limit(50)
    )
    return list(reports.scalars().all())


@router.get("/{report_id}", response_model=JsSecretsReportOut)
async def get_js_secrets_report(
    asset_id: uuid.UUID, report_id: uuid.UUID, db: DbDep, _user: UserDep,
) -> JsSecretsReport:
    result = await db.execute(
        select(JsSecretsReport).where(
            JsSecretsReport.id == report_id, JsSecretsReport.asset_id == asset_id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="JS secrets report not found")
    return report


# ── Background task ──────────────────────────────────────────────────────────


def _is_false_positive(match_text: str) -> bool:
    """Filter out placeholders, env references, and template variables."""
    # Get surrounding context (the match plus some chars around it)
    return any(fp.search(match_text) for fp in _FP_PATTERNS)


def _extract_context(content: str, match: re.Match, context_chars: int = 60) -> str:
    """Extract context around a regex match, masking the middle of the secret."""
    start = max(0, match.start() - context_chars)
    end = min(len(content), match.end() + context_chars)
    snippet = content[start:end]
    # Mask the actual secret value (show first 4 and last 4 chars)
    secret = match.group(0)
    if len(secret) > 12:
        masked = secret[:6] + "…" + secret[-4:]
    else:
        masked = secret[:4] + "…"
    return snippet.replace(secret, masked)


async def _run_js_secrets_scan(report_id: uuid.UUID, target_url: str) -> None:
    factory = get_session_factory()

    async with factory() as session:
        report = (
            await session.execute(
                select(JsSecretsReport).where(JsSecretsReport.id == report_id)
            )
        ).scalar_one_or_none()
        if not report:
            return

        report.status = "running"
        await session.flush()

        try:
            findings = await _scan_js_secrets(target_url)

            report.findings = findings
            report.scripts_scanned = len(findings.get("scripts_scanned", []))
            report.secrets_found = len(findings.get("secrets", []))
            report.status = "completed"

        except httpx.ConnectError as exc:
            report.status = "failed"
            report.error_msg = f"Connection failed: {exc}"
        except Exception as exc:
            logger.error("JS secrets scan failed", report_id=str(report_id), error=str(exc), exc_info=True)
            report.status = "failed"
            report.error_msg = str(exc)[:500]

        await session.commit()
    logger.info("JS secrets scan completed", report_id=str(report_id))


async def _scan_js_secrets(target_url: str) -> dict:
    secrets: list[dict] = []
    scripts_scanned: list[str] = []

    async with SafeAsyncClient(
        timeout=15.0, verify=False, allow_private=True,
    ) as client:
        # Step 1: Fetch the HTML page
        resp = await client.get(target_url)
        html = resp.text

        # Step 2: Extract JS URLs from <script src="..."> tags
        script_urls: list[str] = []
        for match in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE):
            src = match.group(1)
            full_url = urljoin(str(resp.url), src)
            script_urls.append(full_url)

        # Also scan inline scripts in the HTML itself
        inline_scripts = re.findall(r'<script[^>]*>([\s\S]*?)</script[^>]*>', html, re.IGNORECASE)
        inline_content = "\n".join(s for s in inline_scripts if len(s.strip()) > 10)
        if inline_content:
            for name, severity, pattern in _SECRET_PATTERNS:
                for m in pattern.finditer(inline_content):
                    match_text = m.group(0)
                    if not _is_false_positive(match_text):
                        secrets.append({
                            "type": name,
                            "severity": severity,
                            "match": match_text[:80] + ("…" if len(match_text) > 80 else ""),
                            "script_url": "(inline)",
                            "context": _extract_context(inline_content, m),
                        })

        # Step 3: Fetch and scan each JS file (limit to 50 scripts)
        for js_url in script_urls[:50]:
            try:
                js_resp = await client.get(js_url, timeout=10.0)
                if js_resp.status_code != 200:
                    continue
                # Skip files that are too large
                if len(js_resp.content) > _MAX_JS_SIZE:
                    scripts_scanned.append(f"{js_url} (skipped: too large)")
                    continue

                js_content = js_resp.text
                scripts_scanned.append(js_url)

                for name, severity, pattern in _SECRET_PATTERNS:
                    for m in pattern.finditer(js_content):
                        match_text = m.group(0)
                        if not _is_false_positive(match_text):
                            secrets.append({
                                "type": name,
                                "severity": severity,
                                "match": match_text[:80] + ("…" if len(match_text) > 80 else ""),
                                "script_url": js_url,
                                "context": _extract_context(js_content, m),
                            })

            except httpx.HTTPError:
                logger.debug("Failed to fetch JS file", url=js_url)

    # Deduplicate by (type, match)
    seen: set[tuple[str, str]] = set()
    unique_secrets: list[dict] = []
    for s in secrets:
        key = (s["type"], s["match"])
        if key not in seen:
            seen.add(key)
            unique_secrets.append(s)

    return {
        "secrets": unique_secrets,
        "scripts_scanned": scripts_scanned,
        "inline_scripts_checked": bool(inline_content),
    }
