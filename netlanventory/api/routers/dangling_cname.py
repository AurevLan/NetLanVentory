"""Dangling CNAME / subdomain takeover detection router.

Enumerates common subdomains via DNS, checks for CNAME records, and identifies
dangling CNAMEs that point to unclaimed services (subdomain takeover risk).
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import actor_from_user, get_current_active_user, get_db
from netlanventory.core.audit import log_action
from netlanventory.core.database import get_session_factory
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.dangling_cname_report import DanglingCnameReport

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/dangling-cname", tags=["dangling-cname"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]

# ── Common subdomains to enumerate ───────────────────────────────────────────

_COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "blog", "forum",
    "shop", "store", "api", "dev", "staging", "test", "beta", "admin",
    "portal", "app", "m", "mobile", "docs", "wiki", "support", "help",
    "status", "cdn", "media", "static", "assets", "img", "images",
    "vpn", "remote", "gateway", "proxy", "ns1", "ns2", "ns3",
    "mx", "mx1", "mx2", "autodiscover", "autoconfig",
    "git", "ci", "jenkins", "grafana", "monitor", "prometheus",
    "auth", "sso", "login", "id", "accounts",
    "s3", "bucket", "storage", "files", "download", "upload",
    "labs", "demo", "sandbox", "preview", "stage", "uat",
    "intranet", "internal", "corp", "office",
    "analytics", "tracking", "ads", "marketing",
    "calendar", "meet", "chat", "slack",
]

# Known vulnerable services — CNAME targets that may be claimable
_VULNERABLE_SERVICES: dict[str, str] = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku",
    "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3 Website",
    "cloudfront.net": "AWS CloudFront",
    "azurewebsites.net": "Azure App Service",
    "azure-api.net": "Azure API Management",
    "cloudapp.azure.com": "Azure VM",
    "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob Storage",
    "netlify.app": "Netlify",
    "netlify.com": "Netlify",
    "vercel.app": "Vercel",
    "now.sh": "Vercel (legacy)",
    "ghost.io": "Ghost",
    "myshopify.com": "Shopify",
    "shopifypreview.com": "Shopify",
    "wordpress.com": "WordPress.com",
    "wpcomstaging.com": "WordPress.com",
    "pantheonsite.io": "Pantheon",
    "fly.dev": "Fly.io",
    "bitbucket.io": "Bitbucket",
    "gitlab.io": "GitLab Pages",
    "zendesk.com": "Zendesk",
    "freshdesk.com": "Freshdesk",
    "helpscoutdocs.com": "HelpScout",
    "helpjuice.com": "Helpjuice",
    "statuspage.io": "Statuspage",
    "tictail.com": "Tictail",
    "surge.sh": "Surge.sh",
    "readme.io": "ReadMe",
    "cargo.site": "Cargo",
    "getresponse.com": "GetResponse",
    "unbounce.com": "Unbounce",
    "launchrock.com": "LaunchRock",
    "cargocollective.com": "Cargo",
    "feedpress.me": "FeedPress",
    "agilecrm.com": "Agile CRM",
    "aha.io": "Aha!",
    "desk.com": "Desk.com",
}


# ── Schemas ──────────────────────────────────────────────────────────────────


class DanglingCnameRequest(BaseModel):
    domain: str = Field(
        ..., min_length=3, max_length=255,
        description="Base domain to check (e.g. example.com)",
    )
    extra_subdomains: list[str] = Field(
        default_factory=list,
        max_length=100,
        description="Additional subdomains to check beyond the default list",
    )


class DanglingCnameReportOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    asset_id: uuid.UUID
    domain: str | None
    status: str
    subdomains_checked: int | None = None
    dangling_count: int | None = None
    findings: dict | None = None
    error_msg: str | None = None
    created_at: datetime
    updated_at: datetime


class DanglingCnameTriggerOut(BaseModel):
    report_id: uuid.UUID
    message: str


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", response_model=DanglingCnameTriggerOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
async def trigger_dangling_cname_scan(
    request: Request,
    asset_id: uuid.UUID,
    payload: DanglingCnameRequest,
    background_tasks: BackgroundTasks,
    db: DbDep,
    current_user: UserDep,
) -> DanglingCnameTriggerOut:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Asset not found")

    domain = payload.domain.strip().lower()

    report = DanglingCnameReport(asset_id=asset_id, status="pending", domain=domain)
    db.add(report)
    await db.flush()

    actor = actor_from_user(current_user)
    await log_action(
        db, user=actor, action="dangling_cname.trigger",
        resource_type="asset", resource_id=str(asset_id),
        detail={"domain": domain, "extra_subdomains": payload.extra_subdomains},
    )
    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(
        _run_dangling_cname_scan,
        report_id=report.id,
        domain=domain,
        extra_subdomains=payload.extra_subdomains,
    )
    logger.info("Dangling CNAME scan queued", report_id=str(report.id), domain=domain)

    return DanglingCnameTriggerOut(
        report_id=report.id,
        message="Dangling CNAME scan queued. Poll GET /dangling-cname for results.",
    )


@router.get("", response_model=list[DanglingCnameReportOut])
async def list_dangling_cname_reports(
    asset_id: uuid.UUID, db: DbDep, _user: UserDep,
) -> list[DanglingCnameReport]:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Asset not found")
    reports = await db.execute(
        select(DanglingCnameReport)
        .where(DanglingCnameReport.asset_id == asset_id)
        .order_by(DanglingCnameReport.created_at.desc())
        .limit(50)
    )
    return list(reports.scalars().all())


@router.get("/{report_id}", response_model=DanglingCnameReportOut)
async def get_dangling_cname_report(
    asset_id: uuid.UUID, report_id: uuid.UUID, db: DbDep, _user: UserDep,
) -> DanglingCnameReport:
    result = await db.execute(
        select(DanglingCnameReport).where(
            DanglingCnameReport.id == report_id,
            DanglingCnameReport.asset_id == asset_id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Dangling CNAME report not found")
    return report


# ── Background task ──────────────────────────────────────────────────────────


async def _resolve_cname(fqdn: str) -> str | None:
    """Resolve CNAME record for a FQDN. Returns target or None."""
    import dns.asyncresolver
    import dns.exception

    try:
        answers = await dns.asyncresolver.resolve(fqdn, "CNAME")
        for rdata in answers:
            return str(rdata.target).rstrip(".")
    except (dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoAnswer,
            dns.asyncresolver.NoNameservers, dns.exception.DNSException):
        return None
    return None


async def _resolves_to_ip(fqdn: str) -> bool:
    """Check if a FQDN resolves to at least one A/AAAA record."""
    import dns.asyncresolver
    import dns.exception

    for rdtype in ("A", "AAAA"):
        try:
            answers = await dns.asyncresolver.resolve(fqdn, rdtype)
            if answers:
                return True
        except (dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoAnswer,
                dns.asyncresolver.NoNameservers, dns.exception.DNSException):
            continue
    return False


def _identify_service(cname_target: str) -> str | None:
    """Check if CNAME target matches a known vulnerable service."""
    target_lower = cname_target.lower()
    for pattern, service_name in _VULNERABLE_SERVICES.items():
        if pattern in target_lower:
            return service_name
    return None


async def _check_subdomain(subdomain: str, domain: str) -> dict | None:
    """Check a single subdomain for dangling CNAME."""
    fqdn = f"{subdomain}.{domain}"

    cname_target = await _resolve_cname(fqdn)
    if not cname_target:
        return None  # No CNAME record — not interesting

    # Check if the CNAME target actually resolves
    target_resolves = await _resolves_to_ip(cname_target)
    service = _identify_service(cname_target)

    if not target_resolves:
        # Dangling CNAME — the target doesn't resolve
        return {
            "subdomain": fqdn,
            "cname_target": cname_target,
            "service": service,
            "dangling": True,
            "takeover_risk": "high" if service else "medium",
            "detail": f"CNAME points to {cname_target} which does not resolve"
                      + (f" (known vulnerable: {service})" if service else ""),
        }

    if service:
        # CNAME resolves but points to a known claimable service — worth noting
        return {
            "subdomain": fqdn,
            "cname_target": cname_target,
            "service": service,
            "dangling": False,
            "takeover_risk": "low",
            "detail": f"CNAME resolves to {service} — verify the service is still claimed",
        }

    return None


async def _run_dangling_cname_scan(
    report_id: uuid.UUID,
    domain: str,
    extra_subdomains: list[str],
) -> None:
    factory = get_session_factory()

    async with factory() as session:
        report = (
            await session.execute(
                select(DanglingCnameReport).where(DanglingCnameReport.id == report_id)
            )
        ).scalar_one_or_none()
        if not report:
            return

        report.status = "running"
        await session.flush()

        try:
            # Combine default + extra subdomains, deduplicate
            all_subs = list(dict.fromkeys(
                _COMMON_SUBDOMAINS + [s.strip().lower() for s in extra_subdomains if s.strip()]
            ))

            # Throttled concurrent DNS resolution (semaphore of 20)
            sem = asyncio.Semaphore(20)

            async def _throttled_check(sub: str) -> dict | None:
                async with sem:
                    return await _check_subdomain(sub, domain)

            results = await asyncio.gather(
                *[_throttled_check(sub) for sub in all_subs],
                return_exceptions=True,
            )

            dangling: list[dict] = []
            notable: list[dict] = []
            checked: list[str] = []

            for sub, result in zip(all_subs, results):
                checked.append(f"{sub}.{domain}")
                if isinstance(result, Exception):
                    logger.debug("Subdomain check error", subdomain=sub, error=str(result))
                    continue
                if result is None:
                    continue
                if result.get("dangling"):
                    dangling.append(result)
                else:
                    notable.append(result)

            report.findings = {
                "dangling": dangling,
                "notable": notable,
                "subdomains_checked": checked,
            }
            report.subdomains_checked = len(checked)
            report.dangling_count = len(dangling)
            report.status = "completed"

        except Exception as exc:
            logger.error(
                "Dangling CNAME scan failed",
                report_id=str(report_id), error=str(exc), exc_info=True,
            )
            report.status = "failed"
            report.error_msg = str(exc)[:500]

        await session.commit()
    logger.info("Dangling CNAME scan completed", report_id=str(report_id))
