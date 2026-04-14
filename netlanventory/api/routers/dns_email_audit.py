"""DNS / Email security audit router.

Checks SPF, DKIM (12 common selectors), and DMARC records for a domain.
Scores the domain based on the presence and quality of these records.
"""

from __future__ import annotations

import asyncio
import re
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
from netlanventory.models.dns_email_report import DnsEmailReport

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/dns-email-audit", tags=["dns-email-audit"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]

# ── DKIM selectors to probe ─────────────────────────────────────────────────

_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "k3",
    "mail", "smtp", "dkim", "s1", "s2",
]

# ── Schemas ──────────────────────────────────────────────────────────────────


class DnsEmailAuditRequest(BaseModel):
    domain: str = Field(
        ...,
        min_length=3,
        max_length=255,
        description="Domain to audit (e.g. example.com)",
    )


class DnsEmailReportOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    asset_id: uuid.UUID
    domain: str | None
    status: str
    score: int | None = None
    findings: dict | None = None
    error_msg: str | None = None
    created_at: datetime
    updated_at: datetime


class DnsEmailTriggerOut(BaseModel):
    report_id: uuid.UUID
    message: str


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", response_model=DnsEmailTriggerOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("10/minute")
async def trigger_dns_email_audit(
    request: Request,
    asset_id: uuid.UUID,
    payload: DnsEmailAuditRequest,
    background_tasks: BackgroundTasks,
    db: DbDep,
    current_user: UserDep,
) -> DnsEmailTriggerOut:
    """Audit SPF/DKIM/DMARC records for a domain."""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    domain = payload.domain.strip().lower()

    report = DnsEmailReport(asset_id=asset_id, status="pending", domain=domain)
    db.add(report)
    await db.flush()

    actor = actor_from_user(current_user)
    await log_action(
        db, user=actor, action="dns_email_audit.trigger",
        resource_type="asset", resource_id=str(asset_id),
        detail={"domain": domain},
    )
    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(_run_dns_email_audit, report_id=report.id, domain=domain)
    logger.info("DNS/email audit queued", report_id=str(report.id), domain=domain)

    return DnsEmailTriggerOut(
        report_id=report.id,
        message="DNS/email audit queued. Poll GET /dns-email-audit for results.",
    )


@router.get("", response_model=list[DnsEmailReportOut])
async def list_dns_email_reports(
    asset_id: uuid.UUID, db: DbDep, _user: UserDep,
) -> list[DnsEmailReport]:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Asset not found")
    reports = await db.execute(
        select(DnsEmailReport)
        .where(DnsEmailReport.asset_id == asset_id)
        .order_by(DnsEmailReport.created_at.desc())
        .limit(50)
    )
    return list(reports.scalars().all())


@router.get("/{report_id}", response_model=DnsEmailReportOut)
async def get_dns_email_report(
    asset_id: uuid.UUID, report_id: uuid.UUID, db: DbDep, _user: UserDep,
) -> DnsEmailReport:
    result = await db.execute(
        select(DnsEmailReport).where(
            DnsEmailReport.id == report_id, DnsEmailReport.asset_id == asset_id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="DNS/email audit report not found")
    return report


# ── Background task ──────────────────────────────────────────────────────────


async def _resolve_txt(domain: str) -> list[str]:
    """Resolve TXT records for a domain using dnspython (async)."""
    import dns.asyncresolver
    import dns.exception

    try:
        answers = await dns.asyncresolver.resolve(domain, "TXT")
        return [
            b"".join(rdata.strings).decode("utf-8", errors="replace")
            for rdata in answers
        ]
    except (dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoAnswer, dns.exception.DNSException):
        return []


async def _check_spf(domain: str) -> dict:
    """Check SPF record."""
    txt_records = await _resolve_txt(domain)
    spf_records = [r for r in txt_records if r.startswith("v=spf1")]

    if not spf_records:
        return {"present": False, "record": None, "valid": False, "issues": ["No SPF record found"]}

    record = spf_records[0]
    issues: list[str] = []

    if len(spf_records) > 1:
        issues.append(f"Multiple SPF records found ({len(spf_records)}) — only one allowed per RFC 7208")

    if "+all" in record:
        issues.append("SPF uses '+all' (pass all) — effectively disables SPF protection")
    elif "~all" in record:
        issues.append("SPF uses '~all' (softfail) — messages from unauthorized senders may still be delivered")
    elif "?all" in record:
        issues.append("SPF uses '?all' (neutral) — no policy enforcement")

    # Count DNS lookups (max 10 per RFC)
    lookup_mechs = re.findall(r'\b(include|a|mx|ptr|redirect)\b', record, re.IGNORECASE)
    if len(lookup_mechs) > 10:
        issues.append(f"SPF exceeds 10 DNS lookup limit ({len(lookup_mechs)} mechanisms)")

    valid = len(issues) == 0 or (len(issues) == 1 and "~all" in issues[0])

    return {"present": True, "record": record, "valid": valid, "issues": issues}


async def _check_dkim(domain: str) -> dict:
    """Check DKIM records for common selectors."""
    found_selectors: list[dict] = []

    async def _probe_selector(selector: str) -> dict | None:
        dkim_domain = f"{selector}._domainkey.{domain}"
        records = await _resolve_txt(dkim_domain)
        for r in records:
            if "v=DKIM1" in r or "p=" in r:
                key_length = None
                p_match = re.search(r'p=([A-Za-z0-9+/=]+)', r)
                if p_match:
                    # Rough key length estimation from base64 public key
                    key_bytes = len(p_match.group(1)) * 3 // 4
                    key_length = key_bytes * 8
                return {
                    "selector": selector,
                    "record": r[:200],
                    "key_bits": key_length,
                }
        return None

    tasks = [_probe_selector(s) for s in _DKIM_SELECTORS]
    results = await asyncio.gather(*tasks)
    found_selectors = [r for r in results if r is not None]

    issues: list[str] = []
    if not found_selectors:
        issues.append("No DKIM records found for any common selector")
    else:
        for sel in found_selectors:
            if sel.get("key_bits") and sel["key_bits"] < 1024:
                issues.append(f"Selector '{sel['selector']}' uses a weak key ({sel['key_bits']} bits < 1024)")

    return {
        "present": len(found_selectors) > 0,
        "selectors_found": found_selectors,
        "issues": issues,
    }


async def _check_dmarc(domain: str) -> dict:
    """Check DMARC record."""
    records = await _resolve_txt(f"_dmarc.{domain}")
    dmarc_records = [r for r in records if r.startswith("v=DMARC1")]

    if not dmarc_records:
        return {
            "present": False, "record": None, "policy": None,
            "issues": ["No DMARC record found — domain is vulnerable to email spoofing"],
        }

    record = dmarc_records[0]
    issues: list[str] = []

    # Extract policy
    policy_match = re.search(r'\bp=(\w+)', record)
    policy = policy_match.group(1).lower() if policy_match else "unknown"

    if policy == "none":
        issues.append("DMARC policy is 'none' — spoofed emails are still delivered (monitoring only)")
    elif policy == "quarantine":
        issues.append("DMARC policy is 'quarantine' — consider upgrading to 'reject' for full protection")

    # Check subdomain policy
    sp_match = re.search(r'\bsp=(\w+)', record)
    if not sp_match:
        issues.append("No subdomain policy (sp=) — subdomains inherit parent policy but explicit is better")

    # Check percentage
    pct_match = re.search(r'\bpct=(\d+)', record)
    if pct_match and int(pct_match.group(1)) < 100:
        issues.append(f"DMARC pct={pct_match.group(1)} — not all messages are checked")

    # Check reporting
    has_rua = "rua=" in record
    has_ruf = "ruf=" in record
    if not has_rua:
        issues.append("No aggregate reporting (rua=) configured — no visibility on DMARC results")

    return {
        "present": True,
        "record": record,
        "policy": policy,
        "has_rua": has_rua,
        "has_ruf": has_ruf,
        "issues": issues,
    }


async def _run_dns_email_audit(report_id: uuid.UUID, domain: str) -> None:
    factory = get_session_factory()

    async with factory() as session:
        report = (
            await session.execute(
                select(DnsEmailReport).where(DnsEmailReport.id == report_id)
            )
        ).scalar_one_or_none()
        if not report:
            return

        report.status = "running"
        await session.flush()

        try:
            spf, dkim, dmarc = await asyncio.gather(
                _check_spf(domain),
                _check_dkim(domain),
                _check_dmarc(domain),
            )

            # Score: 0-100
            # SPF present + valid = 30, DKIM present = 30, DMARC present + reject = 40
            score = 0
            if spf["present"]:
                score += 15
                if spf.get("valid"):
                    score += 15
            if dkim["present"]:
                score += 30
            if dmarc["present"]:
                score += 20
                if dmarc.get("policy") == "reject":
                    score += 20
                elif dmarc.get("policy") == "quarantine":
                    score += 10

            report.findings = {"spf": spf, "dkim": dkim, "dmarc": dmarc}
            report.score = score
            report.status = "completed"

        except Exception as exc:
            logger.error("DNS/email audit failed", report_id=str(report_id), error=str(exc), exc_info=True)
            report.status = "failed"
            report.error_msg = str(exc)[:500]

        await session.commit()
    logger.info("DNS/email audit completed", report_id=str(report_id))
