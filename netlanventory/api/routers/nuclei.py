"""Nuclei scan router — trigger Nuclei multi-protocol scans on assets and retrieve results."""

from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
import uuid
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db
from netlanventory.core.config import get_settings
from netlanventory.core.cve_enrichment import enrich_cves
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve
from netlanventory.models.nuclei_report import NucleiReport
from netlanventory.schemas.nuclei import NucleiReportDetail, NucleiReportOut, _parse_nuclei_finding

router = APIRouter(prefix="/assets/{asset_id}/nuclei", tags=["nuclei"])
logger = get_logger(__name__)

DbDep = Annotated[AsyncSession, Depends(get_db)]

# Semaphore to bound concurrent Nuclei scans (initialised lazily on first use)
_nuclei_semaphore: asyncio.Semaphore | None = None

# Matches CVE-YYYY-NNNNN
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Port → service categorisation for target / tag building
_WEB_PORTS_HTTPS = {443, 8443, 4443, 9443}
_WEB_PORTS_HTTP = {80, 8080, 3000, 8000, 8888, 9090}
_WEB_SERVICE_NAMES = {"http", "https", "http-alt", "http-proxy", "www"}

_SERVICE_PORT_MAP: dict[int, str] = {
    21: "ftp",
    990: "ftp",
    25: "smtp",
    465: "smtp",
    587: "smtp",
    139: "smb",
    445: "smb",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
    3389: "rdp",
    11211: "memcached",
}


def _get_nuclei_semaphore() -> asyncio.Semaphore:
    global _nuclei_semaphore
    if _nuclei_semaphore is None:
        _nuclei_semaphore = asyncio.Semaphore(get_settings().max_concurrent_nuclei_scans)
    return _nuclei_semaphore


def _build_nuclei_targets_and_tags(asset: Asset) -> tuple[list[str], list[str]]:
    """Auto-determine scan targets and Nuclei template tags from discovered ports/services.

    Returns:
        targets: List of URLs, IPs, or IP:port strings to scan.
        tags:    List of Nuclei template tag strings.
    """
    targets: list[str] = []
    # Base tags: misconfig and exposure are scoped (fast); "cve" is intentionally
    # omitted here — it matches ~13 000 templates and makes every scan time out.
    # Service-specific tags (http, smb, ssl …) already include their own CVE templates.
    tags: set[str] = {"misconfig", "exposure"}
    has_web = False

    for port in (asset.ports or []):
        if port.state != "open":
            continue
        pn: int = port.port_number
        svc: str = (port.service_name or "").lower()

        if pn in _WEB_PORTS_HTTPS or "https" in svc or (svc == "ssl" and pn not in {22}):
            targets.append(f"https://{asset.ip}:{pn}")
            tags |= {"http", "ssl", "tls"}
            has_web = True
        elif pn in _WEB_PORTS_HTTP or svc in _WEB_SERVICE_NAMES:
            targets.append(f"http://{asset.ip}:{pn}")
            tags.add("http")
            has_web = True
        elif pn == 53 or svc == "domain":
            # DNS resolver scan
            if asset.ip:
                targets.append(str(asset.ip))
            tags.add("dns")
        elif pn in _SERVICE_PORT_MAP or svc in set(_SERVICE_PORT_MAP.values()):
            if asset.ip:
                targets.append(f"{asset.ip}:{pn}")
            tag = _SERVICE_PORT_MAP.get(pn, svc)
            tags.add(tag)

    # For web services, also scan FQDN entries so virtual-host templates fire
    if has_web and asset.dns_entries:
        for dns_entry in asset.dns_entries:
            targets.append(dns_entry.fqdn)

    # Fallback: scan bare IP if nothing else matched
    if not targets and asset.ip:
        targets.append(str(asset.ip))

    # Deduplicate while preserving insertion order
    seen: set[str] = set()
    deduped: list[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            deduped.append(t)

    return deduped, sorted(tags)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("", response_model=NucleiReportOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("10/minute")
async def start_nuclei_scan(
    request: Request,
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DbDep,
) -> NucleiReport:
    """Trigger a Nuclei scan for an asset.

    Targets and template tags are auto-determined from the asset's discovered
    ports and services. The scan runs in the background.
    """
    settings = get_settings()

    # Verify nuclei binary is available
    import shutil
    if not shutil.which(settings.nuclei_binary):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Nuclei binary not found: {settings.nuclei_binary!r}. "
                   "Ensure it is installed in the container.",
        )

    # Load ports and DNS entries to build targets
    from sqlalchemy.orm import selectinload as _sli
    result = await db.execute(
        select(Asset)
        .options(_sli(Asset.ports), _sli(Asset.dns_entries))
        .where(Asset.id == asset_id)
    )
    full_asset = result.scalar_one_or_none()
    if not full_asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    if not full_asset.ip:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Asset has no IP address — cannot determine scan targets.",
        )

    targets, tags = _build_nuclei_targets_and_tags(full_asset)

    report = NucleiReport(
        asset_id=asset_id,
        status="pending",
        targets=targets,
        tags=tags,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(
        _run_nuclei_scan,
        report_id=report.id,
        asset_id=asset_id,
        targets=targets,
        tags=tags,
    )
    logger.info(
        "Nuclei scan queued",
        report_id=str(report.id),
        targets=len(targets),
        tags=tags,
    )
    return report


@router.get("", response_model=list[NucleiReportOut])
async def list_nuclei_reports(asset_id: uuid.UUID, db: DbDep) -> list[NucleiReport]:
    """List all Nuclei reports for an asset, newest first."""
    await _get_asset_or_404(asset_id, db)
    result = await db.execute(
        select(NucleiReport)
        .where(NucleiReport.asset_id == asset_id)
        .order_by(NucleiReport.created_at.desc())
    )
    return list(result.scalars().all())


@router.get("/{report_id}", response_model=NucleiReportDetail)
async def get_nuclei_report(
    asset_id: uuid.UUID, report_id: uuid.UUID, db: DbDep
) -> NucleiReportDetail:
    """Get a specific Nuclei report with full findings list."""
    await _get_asset_or_404(asset_id, db)
    result = await db.execute(
        select(NucleiReport).where(
            NucleiReport.id == report_id,
            NucleiReport.asset_id == asset_id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Nuclei report not found")

    stored = report.report or {}
    raw_findings = stored.get("findings", [])
    parsed_findings = [_parse_nuclei_finding(f) for f in raw_findings]

    return NucleiReportDetail(
        id=report.id,
        status=report.status,
        targets=report.targets,
        tags=report.tags,
        findings_count=len(parsed_findings),
        cve_count=report.cve_count,
        risk_summary=report.risk_summary,
        error_msg=report.error_msg,
        created_at=report.created_at,
        updated_at=report.updated_at,
        findings=parsed_findings,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_asset_or_404(asset_id: uuid.UUID, db: AsyncSession) -> Asset:
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


def _build_nuclei_risk_summary(findings: list[dict]) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        sev = (finding.get("info", {}).get("severity") or "info").lower()
        if sev in summary:
            summary[sev] += 1
        else:
            summary["info"] += 1
    return summary


async def _persist_nuclei_cves(
    session: AsyncSession, asset_id: uuid.UUID, findings: list[dict]
) -> int:
    """Upsert Cve rows and create/update AssetCve links for each Nuclei finding.

    Supports multi-source tracking: if a CVE was already found by ZAP or SSH,
    the source column is updated to append "nuclei" (e.g. "zap" → "zap,nuclei").

    Returns the total number of unique CVE IDs found across all findings.
    """
    all_cve_ids: set[str] = set()

    for finding in findings:
        info = finding.get("info", {})
        classification = info.get("classification", {})

        # Most reliable source: info.classification.cve-id
        raw_cve_ids = classification.get("cve-id") or []
        if isinstance(raw_cve_ids, str):
            raw_cve_ids = [raw_cve_ids]
        cve_ids = {c.upper() for c in raw_cve_ids if c}

        # Fallback: template-id might be the CVE directly
        template_id = finding.get("template-id", "")
        if template_id.upper().startswith("CVE-"):
            cve_ids.add(template_id.upper())

        # Fallback: scan references in info.reference
        references = info.get("reference") or []
        if isinstance(references, str):
            references = [references]
        for ref in references:
            cve_ids.update(c.upper() for c in _CVE_RE.findall(ref))

        if not cve_ids:
            continue

        severity = info.get("severity", "info").capitalize()
        description = info.get("description") or info.get("name") or None
        cvss_score: float | None = None
        try:
            raw_score = classification.get("cvss-score")
            if raw_score is not None:
                cvss_score = float(raw_score)
        except (TypeError, ValueError):
            pass

        all_cve_ids.update(cve_ids)

        for cve_id_str in cve_ids:
            # Upsert Cve row — create or enrich existing
            cve_result = await session.execute(
                select(Cve).where(Cve.cve_id == cve_id_str)
            )
            cve = cve_result.scalar_one_or_none()
            if not cve:
                cve = Cve(
                    cve_id=cve_id_str,
                    severity=severity,
                    description=description,
                    cvss_score=cvss_score,
                )
                session.add(cve)
                await session.flush()
            else:
                # Enrich fields that were previously unknown or empty
                if (not cve.severity or cve.severity == "Unknown") and severity and severity != "Unknown":
                    cve.severity = severity
                if not cve.description and description:
                    cve.description = description
                if cve.cvss_score is None and cvss_score is not None:
                    cve.cvss_score = cvss_score

            # Check for existing AssetCve link (any source)
            existing_result = await session.execute(
                select(AssetCve).where(
                    AssetCve.asset_id == asset_id,
                    AssetCve.cve_id == cve.id,
                )
            )
            existing_link = existing_result.scalar_one_or_none()

            if existing_link:
                # Append "nuclei" to sources if not already present
                sources = [s for s in (existing_link.source or "").split(",") if s]
                if "nuclei" not in sources:
                    existing_link.source = ",".join(sources + ["nuclei"])
            else:
                link = AssetCve(
                    asset_id=asset_id,
                    cve_id=cve.id,
                    source="nuclei",
                )
                session.add(link)

    await session.commit()
    return len(all_cve_ids)


# ── Background task ───────────────────────────────────────────────────────────

async def _run_nuclei_scan(
    report_id: uuid.UUID,
    asset_id: uuid.UUID,
    targets: list[str],
    tags: list[str],
) -> None:
    """Execute a Nuclei scan against the given targets and persist results."""
    from netlanventory.core.database import get_session_factory

    settings = get_settings()
    factory = get_session_factory()

    targets_file: str | None = None
    output_file: str | None = None
    cve_ids_to_enrich: list[str] = []

    async with _get_nuclei_semaphore():
        async with factory() as session:
            report = await _fetch_report(session, report_id)
            if not report:
                return
            report.status = "running"
            await session.commit()

            try:
                # Write targets to a temp file
                fd, targets_file = tempfile.mkstemp(suffix=".txt", prefix="nuclei-")
                with os.fdopen(fd, "w") as f:
                    f.write("\n".join(targets))

                # Write findings to a temp file so partial results survive a timeout
                out_fd, output_file = tempfile.mkstemp(
                    suffix=".jsonl", prefix="nuclei-out-"
                )
                os.close(out_fd)

                cmd: list[str] = [
                    settings.nuclei_binary,
                    "-list", targets_file,
                    "-tags", ",".join(tags),
                    "-output", output_file,  # write JSONL findings to file
                    "-jsonl",
                    "-timeout", str(settings.nuclei_timeout),
                    "-rate-limit", str(settings.nuclei_rate_limit),
                    "-no-interactsh",  # disable OAST callbacks (useless on internal networks)
                    "-silent",
                    "-no-color",
                ]
                if settings.nuclei_templates_dir:
                    cmd.extend(["-t", settings.nuclei_templates_dir])

                logger.info(
                    "Running Nuclei",
                    report_id=str(report_id),
                    targets=targets,
                    tags=tags,
                )

                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.DEVNULL,  # findings go to output_file
                    stderr=asyncio.subprocess.PIPE,
                )

                timed_out = False
                scan_timeout = settings.nuclei_scan_timeout
                try:
                    _, stderr_bytes = await asyncio.wait_for(
                        proc.communicate(),
                        timeout=scan_timeout,
                    )
                except TimeoutError:
                    proc.kill()
                    _, stderr_bytes = await proc.communicate()
                    timed_out = True
                    logger.warning(
                        "Nuclei scan timed out — using partial results",
                        report_id=str(report_id),
                        timeout=scan_timeout,
                    )

                if stderr_bytes:
                    stderr_text = stderr_bytes.decode("utf-8", errors="replace").strip()
                    if stderr_text:
                        logger.debug(
                            "Nuclei stderr",
                            report_id=str(report_id),
                            stderr=stderr_text[:500],
                        )

                # Parse JSONL output file (findings written incrementally by Nuclei)
                findings: list[dict] = []
                if output_file and os.path.exists(output_file):
                    with open(output_file, encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                findings.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass

                # Persist CVEs with multi-source support
                report = await _fetch_report(session, report_id)
                if not report:
                    return
                cve_count = await _persist_nuclei_cves(session, asset_id, findings)

                # Collect CVE IDs for post-semaphore enrichment
                for finding in findings:
                    info = finding.get("info", {})
                    classification = info.get("classification", {})
                    raw_ids = classification.get("cve-id") or []
                    if isinstance(raw_ids, str):
                        raw_ids = [raw_ids]
                    cve_ids_to_enrich.extend(c.upper() for c in raw_ids if c)
                    tid = finding.get("template-id", "")
                    if tid.upper().startswith("CVE-"):
                        cve_ids_to_enrich.append(tid.upper())

                # Build risk summary
                risk_summary = _build_nuclei_risk_summary(findings)

                # Update report (partial results are still saved on timeout)
                report.status = "completed"
                report.report = {"findings": findings}
                report.risk_summary = risk_summary
                report.cve_count = cve_count
                report.findings_count = len(findings)
                if timed_out:
                    report.error_msg = (
                        f"Scan stopped after {scan_timeout}s — "
                        f"{len(findings)} partial results saved."
                    )

                await session.commit()

            # Semaphore released here — other scans can start immediately
                logger.info(
                    "Nuclei scan completed",
                    report_id=str(report_id),
                    findings=len(findings),
                    cves=cve_count,
                    partial=timed_out,
                )

            except Exception as exc:
                logger.error(
                    "Nuclei scan failed",
                    report_id=str(report_id),
                    error=str(exc),
                    exc_info=True,
                )
                await _fail_report(session, report_id, str(exc)[:500])
            finally:
                if targets_file and os.path.exists(targets_file):
                    os.unlink(targets_file)
                if output_file and os.path.exists(output_file):
                    os.unlink(output_file)
    # Semaphore released — other scans can start

    # Phase 2 — CVE enrichment (independent session, no semaphore held)
    if cve_ids_to_enrich:
        async with factory() as session:
            await enrich_cves(session, list(set(cve_ids_to_enrich)), nvd_api_key=settings.nvd_api_key)
            await session.commit()


async def _fetch_report(session: AsyncSession, report_id: uuid.UUID) -> NucleiReport | None:
    result = await session.execute(
        select(NucleiReport).where(NucleiReport.id == report_id)
    )
    return result.scalar_one_or_none()


async def _fail_report(session: AsyncSession, report_id: uuid.UUID, msg: str) -> None:
    report = await _fetch_report(session, report_id)
    if report:
        report.status = "failed"
        report.error_msg = msg
        await session.commit()
