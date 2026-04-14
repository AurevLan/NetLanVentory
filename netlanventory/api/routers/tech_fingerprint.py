"""Technology fingerprinting router.

Detects the technology stack of a web application by analyzing:
  - HTTP response headers (Server, X-Powered-By, X-Generator, …)
  - HTML meta tags and generators
  - Cookie names (PHPSESSID, JSESSIONID, …)
  - Script/link references in HTML (frameworks, CDNs)
  - Common file probes (/wp-login.php, /robots.txt, …)
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Annotated

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
from netlanventory.models.tech_fingerprint_report import TechFingerprintReport

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/tech-fingerprint", tags=["tech-fingerprint"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]

# ── Signature database ───────────────────────────────────────────────────────

# (name, category, detection_type, pattern)
# detection_type: header, header_value, cookie, html, script, meta, probe
_SIGNATURES: list[tuple[str, str, str, str]] = [
    # --- Servers ---
    ("Nginx", "web-server", "header", "server:nginx"),
    ("Apache", "web-server", "header", "server:apache"),
    ("LiteSpeed", "web-server", "header", "server:litespeed"),
    ("IIS", "web-server", "header", "server:microsoft-iis"),
    ("Caddy", "web-server", "header", "server:caddy"),
    ("Cloudflare", "cdn", "header", "server:cloudflare"),
    # --- Frameworks / runtimes ---
    ("PHP", "language", "header", "x-powered-by:php"),
    ("ASP.NET", "framework", "header", "x-powered-by:asp.net"),
    ("Express", "framework", "header", "x-powered-by:express"),
    ("Next.js", "framework", "header", "x-powered-by:next.js"),
    # --- Cookies ---
    ("PHP", "language", "cookie", "PHPSESSID"),
    ("Java", "language", "cookie", "JSESSIONID"),
    ("ASP.NET", "framework", "cookie", "ASP.NET_SessionId"),
    ("Django", "framework", "cookie", "csrftoken"),
    ("Laravel", "framework", "cookie", "laravel_session"),
    ("Rails", "framework", "cookie", "_rails_session"),
    # --- HTML patterns ---
    ("WordPress", "cms", "html", r'wp-content/|wp-includes/'),
    ("Drupal", "cms", "html", r'Drupal\.settings|sites/default/files'),
    ("Joomla", "cms", "html", r'/media/jui/|/components/com_'),
    ("Shopify", "ecommerce", "html", r'cdn\.shopify\.com'),
    ("Wix", "cms", "html", r'static\.wixstatic\.com'),
    ("Squarespace", "cms", "html", r'squarespace\.com|sqsp\.'),
    ("React", "js-framework", "html", r'__NEXT_DATA__|_next/static|react-root|__react'),
    ("Vue.js", "js-framework", "html", r'__vue_app__|vue\.runtime|v-cloak'),
    ("Angular", "js-framework", "html", r'ng-version=|ng-app=|angular\.min\.js'),
    ("Svelte", "js-framework", "html", r'__svelte|svelte-'),
    ("jQuery", "js-library", "html", r'jquery[.-][\d.]+\.min\.js|jquery\.min\.js'),
    ("Bootstrap", "css-framework", "html", r'bootstrap[.-][\d.]*\.min\.(css|js)'),
    ("Tailwind CSS", "css-framework", "html", r'tailwindcss|tailwind\.min\.css'),
    ("Google Analytics", "analytics", "html", r'google-analytics\.com/|gtag/js\?id=|GoogleAnalyticsObject'),
    ("Google Tag Manager", "analytics", "html", r'googletagmanager\.com/gtm\.js'),
    ("Matomo", "analytics", "html", r'matomo\.js|piwik\.js'),
    ("Cloudflare", "cdn", "html", r'cdnjs\.cloudflare\.com'),
    ("Vercel", "hosting", "html", r'vercel\.app|__vercel'),
    ("Netlify", "hosting", "html", r'netlify\.app|netlify-'),
    ("Firebase", "backend", "html", r'firebaseapp\.com|firebase\.js'),
    ("Supabase", "backend", "html", r'supabase\.co|supabase\.js'),
    # --- Meta generator ---
    ("WordPress", "cms", "meta", r'WordPress'),
    ("Drupal", "cms", "meta", r'Drupal'),
    ("Joomla", "cms", "meta", r'Joomla'),
    ("Hugo", "ssg", "meta", r'Hugo'),
    ("Ghost", "cms", "meta", r'Ghost'),
    ("Gatsby", "ssg", "meta", r'Gatsby'),
]

# File probes: (path, expected_content_substring, technology, category)
_PROBES: list[tuple[str, str, str, str]] = [
    ("/wp-login.php", "wp-login", "WordPress", "cms"),
    ("/wp-json/wp/v2/", '"namespace"', "WordPress REST API", "cms"),
    ("/robots.txt", "", "", ""),  # just collect the content
    ("/.well-known/security.txt", "Contact:", "security.txt", "security"),
    ("/sitemap.xml", "urlset", "XML Sitemap", "seo"),
    ("/graphql", '"data"', "GraphQL", "api"),
    ("/api/health", "", "Health endpoint", "api"),
]


# ── Schemas ──────────────────────────────────────────────────────────────────


class TechFingerprintRequest(BaseModel):
    target_url: AnyHttpUrl = Field(..., description="URL to fingerprint (e.g. https://example.com)")


class TechFingerprintReportOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    asset_id: uuid.UUID
    target_url: str | None
    status: str
    technologies_count: int | None = None
    findings: dict | None = None
    error_msg: str | None = None
    created_at: datetime
    updated_at: datetime


class TechFingerprintTriggerOut(BaseModel):
    report_id: uuid.UUID
    message: str


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", response_model=TechFingerprintTriggerOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("10/minute")
async def trigger_tech_fingerprint(
    request: Request,
    asset_id: uuid.UUID,
    payload: TechFingerprintRequest,
    background_tasks: BackgroundTasks,
    db: DbDep,
    current_user: UserDep,
) -> TechFingerprintTriggerOut:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Asset not found")

    target_url = str(payload.target_url)
    try:
        assert_url_safe(target_url, allow_private=True)
    except SsrfBlockedError as exc:
        raise HTTPException(status_code=400, detail=f"Target rejected: {exc}") from exc

    report = TechFingerprintReport(asset_id=asset_id, status="pending", target_url=target_url)
    db.add(report)
    await db.flush()

    actor = actor_from_user(current_user)
    await log_action(
        db, user=actor, action="tech_fingerprint.trigger",
        resource_type="asset", resource_id=str(asset_id),
        detail={"target_url": target_url},
    )
    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(_run_tech_fingerprint, report_id=report.id, target_url=target_url)
    logger.info("Tech fingerprint queued", report_id=str(report.id), target=target_url)

    return TechFingerprintTriggerOut(
        report_id=report.id,
        message="Tech fingerprint queued. Poll GET /tech-fingerprint for results.",
    )


@router.get("", response_model=list[TechFingerprintReportOut])
async def list_tech_fingerprint_reports(
    asset_id: uuid.UUID, db: DbDep, _user: UserDep,
) -> list[TechFingerprintReport]:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Asset not found")
    reports = await db.execute(
        select(TechFingerprintReport)
        .where(TechFingerprintReport.asset_id == asset_id)
        .order_by(TechFingerprintReport.created_at.desc())
        .limit(50)
    )
    return list(reports.scalars().all())


@router.get("/{report_id}", response_model=TechFingerprintReportOut)
async def get_tech_fingerprint_report(
    asset_id: uuid.UUID, report_id: uuid.UUID, db: DbDep, _user: UserDep,
) -> TechFingerprintReport:
    result = await db.execute(
        select(TechFingerprintReport).where(
            TechFingerprintReport.id == report_id,
            TechFingerprintReport.asset_id == asset_id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Tech fingerprint report not found")
    return report


# ── Background task ──────────────────────────────────────────────────────────


async def _run_tech_fingerprint(report_id: uuid.UUID, target_url: str) -> None:
    factory = get_session_factory()

    async with factory() as session:
        report = (
            await session.execute(
                select(TechFingerprintReport).where(TechFingerprintReport.id == report_id)
            )
        ).scalar_one_or_none()
        if not report:
            return

        report.status = "running"
        await session.flush()

        try:
            findings = await _fingerprint(target_url)
            techs = findings.get("technologies", [])

            report.findings = findings
            report.technologies_count = len(techs)
            report.status = "completed"

        except httpx.ConnectError as exc:
            report.status = "failed"
            report.error_msg = f"Connection failed: {exc}"
        except Exception as exc:
            logger.error("Tech fingerprint failed", report_id=str(report_id), error=str(exc), exc_info=True)
            report.status = "failed"
            report.error_msg = str(exc)[:500]

        await session.commit()
    logger.info("Tech fingerprint completed", report_id=str(report_id))


async def _fingerprint(target_url: str) -> dict:
    detected: dict[str, dict] = {}  # name -> {category, confidence, evidence}

    async with SafeAsyncClient(
        timeout=15.0, verify=False, allow_private=True,
    ) as client:
        resp = await client.get(target_url)
        body = resp.text
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}
        cookies = {c.name: c.value for c in resp.cookies.jar}

        # Header-based detection
        for name, category, det_type, pattern in _SIGNATURES:
            if det_type == "header":
                hdr_name, hdr_val = pattern.split(":", 1)
                actual = resp_headers.get(hdr_name, "").lower()
                if hdr_val in actual:
                    detected[name] = {
                        "category": category, "confidence": "high",
                        "evidence": f"Header {hdr_name}: {resp_headers.get(hdr_name, '')}",
                    }

            elif det_type == "cookie":
                if pattern in cookies:
                    detected.setdefault(name, {
                        "category": category, "confidence": "high",
                        "evidence": f"Cookie: {pattern}",
                    })

            elif det_type == "html":
                if re.search(pattern, body, re.IGNORECASE):
                    detected.setdefault(name, {
                        "category": category, "confidence": "medium",
                        "evidence": f"HTML pattern: {pattern[:60]}",
                    })

            elif det_type == "meta":
                generator_match = re.search(
                    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                    body, re.IGNORECASE,
                )
                if generator_match and re.search(pattern, generator_match.group(1), re.IGNORECASE):
                    detected.setdefault(name, {
                        "category": category, "confidence": "high",
                        "evidence": f"Meta generator: {generator_match.group(1)}",
                    })

        # File probes
        probes_results: list[dict] = []
        base = target_url.rstrip("/")
        for path, expected, tech_name, cat in _PROBES:
            try:
                probe_resp = await client.get(f"{base}{path}", timeout=5.0)
                if probe_resp.status_code == 200:
                    probe_body = probe_resp.text[:2000]
                    if expected and expected in probe_body:
                        if tech_name:
                            detected.setdefault(tech_name, {
                                "category": cat, "confidence": "high",
                                "evidence": f"Probe {path} returned 200 with expected content",
                            })
                    probes_results.append({
                        "path": path, "status": probe_resp.status_code,
                        "found": bool(expected and expected in probe_body) if expected else True,
                    })
                else:
                    probes_results.append({"path": path, "status": probe_resp.status_code, "found": False})
            except httpx.HTTPError:
                probes_results.append({"path": path, "status": None, "found": False})

    technologies = [
        {"name": name, **info}
        for name, info in sorted(detected.items())
    ]

    return {
        "technologies": technologies,
        "raw_headers": dict(resp_headers),
        "probes": probes_results,
    }
