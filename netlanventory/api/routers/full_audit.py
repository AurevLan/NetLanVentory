"""Full audit orchestration router.

Triggers a complete, sequential security audit of a single asset:

  Step 1 — port_scan       nmap TCP (+ basic service detection)
  Step 2 — testssl         deep TLS audit on discovered HTTPS ports
  Step 3 — ssh_audit       SSH config audit on port 22 (or asset.ssh_port)
  Step 4 — default_creds   nmap NSE default credential check
  Step 5 — ssh_scan        SSH package→CVE scan (if credentials configured)
  Step 6 — nuclei          multi-protocol vuln scan (based on open ports)
  Step 7 — exploit_val     Nuclei CVE validation (if CVEs were found)
  Step 8 — risk_score      recompute unified risk score

Each step updates the job's `steps` JSONB column with status + detail.
Sub-report IDs are stored on the job for traceability.

Endpoints:
  POST /assets/{id}/full-audit          → 202, start job
  GET  /assets/{id}/full-audit          → list jobs (newest first)
  GET  /assets/{id}/full-audit/{job_id} → job detail + step statuses
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
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
from netlanventory.models.default_creds_report import DefaultCredsReport
from netlanventory.models.full_audit_job import FullAuditJob
from netlanventory.models.nuclei_report import NucleiReport
from netlanventory.models.ssh_audit_report import SshAuditReport
from netlanventory.models.ssh_scan_report import SshScanReport
from netlanventory.models.testssl_report import TestsslReport

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/full-audit", tags=["full-audit"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
AuthDep = Annotated[object, Depends(get_current_active_user)]

# Only 1 full audit at a time per instance (each step acquires its own semaphore)
_full_audit_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    global _full_audit_semaphore
    if _full_audit_semaphore is None:
        _full_audit_semaphore = asyncio.Semaphore(1)
    return _full_audit_semaphore


# ── Schemas ───────────────────────────────────────────────────────────────────


class FullAuditJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    status: str
    steps: dict | None
    testssl_report_id: uuid.UUID | None
    ssh_audit_report_id: uuid.UUID | None
    default_creds_report_id: uuid.UUID | None
    ssh_scan_report_id: uuid.UUID | None
    nuclei_report_id: uuid.UUID | None
    error_msg: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", response_model=FullAuditJobOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("3/minute")
async def trigger_full_audit(
    request: Request,
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DbDep,
    current_user: AuthDep,
) -> FullAuditJob:
    """Launch a full sequential security audit on an asset (async, 202 Accepted).

    Runs: port scan → testssl → ssh-audit → default creds → SSH CVE scan
          → Nuclei → exploit validation → risk score refresh.

    Each step is skipped gracefully when prerequisites are missing
    (e.g. no HTTPS ports → testssl skipped; no SSH creds → ssh-scan skipped).
    """
    asset = (
        await db.execute(
            select(Asset)
            .options(selectinload(Asset.ports))
            .where(Asset.id == asset_id)
        )
    ).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    if not asset.ip:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Asset has no IP address"
        )

    job = FullAuditJob(
        asset_id=asset_id,
        status="pending",
        steps={},
    )
    db.add(job)
    await db.flush()

    actor = actor_from_user(current_user)
    await log_action(
        db,
        user=actor,
        action="full_audit.trigger",
        resource_type="asset",
        resource_id=str(asset_id),
    )

    await db.commit()
    await db.refresh(job)

    background_tasks.add_task(_run_full_audit, job_id=job.id, asset_id=asset_id)
    logger.info("Full audit queued", job_id=str(job.id), asset_id=str(asset_id))
    return job


@router.get("", response_model=list[FullAuditJobOut])
async def list_full_audit_jobs(
    asset_id: uuid.UUID,
    db: DbDep,
    _auth: AuthDep,
) -> list[FullAuditJob]:
    """List full audit jobs for an asset (newest first)."""
    result = await db.execute(
        select(FullAuditJob)
        .where(FullAuditJob.asset_id == asset_id)
        .order_by(FullAuditJob.created_at.desc())
    )
    return list(result.scalars().all())


@router.get("/{job_id}", response_model=FullAuditJobOut)
async def get_full_audit_job(
    asset_id: uuid.UUID,
    job_id: uuid.UUID,
    db: DbDep,
    _auth: AuthDep,
) -> FullAuditJob:
    """Get a specific full audit job with per-step details."""
    job = (
        await db.execute(
            select(FullAuditJob).where(
                FullAuditJob.id == job_id,
                FullAuditJob.asset_id == asset_id,
            )
        )
    ).scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    return job


# ── Orchestration background task ─────────────────────────────────────────────


async def _run_full_audit(job_id: uuid.UUID, asset_id: uuid.UUID) -> None:
    """Sequential orchestration: run all audit steps, update job after each."""
    factory = get_session_factory()
    settings = get_settings()

    # Helpers ─────────────────────────────────────────────────────────────────

    async def _update_job(job: FullAuditJob, session, **kwargs) -> None:
        for k, v in kwargs.items():
            setattr(job, k, v)
        await session.commit()

    async def _set_step(job: FullAuditJob, session, step: str, info: dict) -> None:
        steps = dict(job.steps or {})
        steps[step] = {**info, "updated_at": datetime.now(timezone.utc).isoformat()}
        job.steps = steps
        await session.commit()

    # ── Start ──────────────────────────────────────────────────────────────────
    async with _get_semaphore():
        async with factory() as session:
            job = (
                await session.execute(select(FullAuditJob).where(FullAuditJob.id == job_id))
            ).scalar_one_or_none()
            if not job:
                return

            asset = (
                await session.execute(
                    select(Asset)
                    .options(selectinload(Asset.ports), selectinload(Asset.ssh_profile))
                    .where(Asset.id == asset_id)
                )
            ).scalar_one_or_none()
            if not asset:
                return

            job.status = "running"
            job.started_at = datetime.now(timezone.utc)
            await session.commit()

        try:
            # ── Step 1 — Port Scan ─────────────────────────────────────────────
            await _step_port_scan(factory, job_id, asset_id, str(asset.ip))

            # Reload asset ports after scan
            async with factory() as session:
                asset = (
                    await session.execute(
                        select(Asset)
                        .options(
                            selectinload(Asset.ports),
                            selectinload(Asset.ssh_profile),
                            selectinload(Asset.cves).selectinload(AssetCve.cve),
                        )
                        .where(Asset.id == asset_id)
                    )
                ).scalar_one()

            open_ports = [p for p in (asset.ports or []) if p.state == "open"]
            open_port_numbers = {p.port_number for p in open_ports}
            https_ports = [p.port_number for p in open_ports if _is_https_port(p)]
            has_ssh = _ssh_port(asset) in open_port_numbers or 22 in open_port_numbers
            has_creds = asset.has_ssh_credentials

            # ── Step 2 — testssl.sh ────────────────────────────────────────────
            testssl_report_id = await _step_testssl(
                factory, job_id, asset_id, asset, https_ports, settings
            )

            # ── Step 3 — SSH Audit ─────────────────────────────────────────────
            ssh_audit_report_id = await _step_ssh_audit(
                factory, job_id, asset_id, asset, has_ssh, settings
            )

            # ── Step 4 — Default Credentials ──────────────────────────────────
            default_creds_report_id = await _step_default_creds(
                factory, job_id, asset_id, open_ports, settings
            )

            # ── Step 5 — SSH CVE Scan ──────────────────────────────────────────
            ssh_scan_report_id = await _step_ssh_scan(
                factory, job_id, asset_id, has_ssh, has_creds
            )

            # ── Step 6 — Nuclei ────────────────────────────────────────────────
            nuclei_report_id = await _step_nuclei(
                factory, job_id, asset_id, asset, open_ports, settings
            )

            # Reload CVEs for exploit validation
            async with factory() as session:
                cve_links = (
                    await session.execute(
                        select(AssetCve)
                        .options(selectinload(AssetCve.cve))
                        .where(AssetCve.asset_id == asset_id)
                    )
                ).scalars().all()

            # ── Step 7 — Exploit Validation ────────────────────────────────────
            await _step_exploit_validation(
                factory, job_id, asset_id, asset, open_ports, cve_links, settings
            )

            # ── Step 8 — Risk Score ────────────────────────────────────────────
            await _step_risk_score(factory, job_id, asset_id)

            # ── Finalise ───────────────────────────────────────────────────────
            async with factory() as session:
                job = (
                    await session.execute(
                        select(FullAuditJob).where(FullAuditJob.id == job_id)
                    )
                ).scalar_one()
                job.status = "completed"
                job.finished_at = datetime.now(timezone.utc)
                job.testssl_report_id = testssl_report_id
                job.ssh_audit_report_id = ssh_audit_report_id
                job.default_creds_report_id = default_creds_report_id
                job.ssh_scan_report_id = ssh_scan_report_id
                job.nuclei_report_id = nuclei_report_id
                await session.commit()

            logger.info("Full audit completed", job_id=str(job_id), asset_id=str(asset_id))

        except Exception as exc:
            logger.error(
                "Full audit failed", job_id=str(job_id), error=str(exc), exc_info=True
            )
            async with factory() as session:
                job = (
                    await session.execute(
                        select(FullAuditJob).where(FullAuditJob.id == job_id)
                    )
                ).scalar_one_or_none()
                if job:
                    job.status = "failed"
                    job.finished_at = datetime.now(timezone.utc)
                    job.error_msg = str(exc)[:500]
                    await session.commit()


# ── Step implementations ───────────────────────────────────────────────────────


async def _step_port_scan(factory, job_id: uuid.UUID, asset_id: uuid.UUID, ip: str) -> None:
    """Run nmap port scan targeting the asset IP."""
    import shutil

    async with factory() as session:
        job = await _load_job(session, job_id)
        if not job:
            return
        await _set_step_inline(job, session, "port_scan", {"status": "running"})

    try:
        from netlanventory.modules.port_scanner import PortScannerModule
        module = PortScannerModule()
        async with factory() as session:
            result = await module.run(session, {"target": ip, "scan_type": "connect"})
            await session.commit()

        ports_found = result.get("details", {}).get("total_open_ports", 0)
        async with factory() as session:
            job = await _load_job(session, job_id)
            if job:
                await _set_step_inline(
                    job, session, "port_scan",
                    {"status": "completed", "detail": f"{ports_found} open ports found"},
                )
    except Exception as exc:
        async with factory() as session:
            job = await _load_job(session, job_id)
            if job:
                await _set_step_inline(
                    job, session, "port_scan",
                    {"status": "failed", "detail": str(exc)[:200]},
                )


async def _step_testssl(
    factory, job_id, asset_id, asset, https_ports: list[int], settings
) -> uuid.UUID | None:
    """Run testssl.sh on the first discovered HTTPS port."""
    import shutil

    testssl_bin = getattr(settings, "testssl_binary", "testssl.sh")

    if not https_ports:
        async with factory() as session:
            job = await _load_job(session, job_id)
            if job:
                await _set_step_inline(job, session, "testssl",
                    {"status": "skipped", "reason": "no HTTPS ports discovered"})
        return None

    if not shutil.which(testssl_bin):
        async with factory() as session:
            job = await _load_job(session, job_id)
            if job:
                await _set_step_inline(job, session, "testssl",
                    {"status": "skipped", "reason": f"binary not found: {testssl_bin!r}"})
        return None

    port = https_ports[0]
    host = asset.hostname or asset.ip

    async with factory() as session:
        job = await _load_job(session, job_id)
        if job:
            await _set_step_inline(job, session, "testssl",
                {"status": "running", "detail": f"scanning {host}:{port}"})

        report = TestsslReport(asset_id=asset_id, host=host, port=port, status="pending")
        session.add(report)
        await session.flush()
        report_id = report.id
        await session.commit()

    from netlanventory.api.routers.testssl import _run_testssl
    await _run_testssl(report_id=report_id, asset_id=asset_id, host=host, port=port)

    async with factory() as session:
        report = (
            await session.execute(select(TestsslReport).where(TestsslReport.id == report_id))
        ).scalar_one_or_none()
        detail = f"grade: {report.grade or 'N/A'}, critical: {report.critical_count}, high: {report.high_count}" if report else "no result"
        job = await _load_job(session, job_id)
        if job:
            await _set_step_inline(job, session, "testssl",
                {"status": report.status if report else "failed", "detail": detail})

    return report_id


async def _step_ssh_audit(
    factory, job_id, asset_id, asset, has_ssh: bool, settings
) -> uuid.UUID | None:
    """Run ssh-audit on the SSH port."""
    import shutil

    ssh_audit_bin = getattr(settings, "ssh_audit_binary", "ssh-audit")

    if not has_ssh:
        async with factory() as session:
            job = await _load_job(session, job_id)
            if job:
                await _set_step_inline(job, session, "ssh_audit",
                    {"status": "skipped", "reason": "port 22 not open"})
        return None

    if not shutil.which(ssh_audit_bin):
        async with factory() as session:
            job = await _load_job(session, job_id)
            if job:
                await _set_step_inline(job, session, "ssh_audit",
                    {"status": "skipped", "reason": f"binary not found: {ssh_audit_bin!r}"})
        return None

    host = asset.ip
    port = asset.ssh_port or 22

    async with factory() as session:
        job = await _load_job(session, job_id)
        if job:
            await _set_step_inline(job, session, "ssh_audit",
                {"status": "running", "detail": f"scanning {host}:{port}"})

        report = SshAuditReport(asset_id=asset_id, host=host, port=port, status="pending")
        session.add(report)
        await session.flush()
        report_id = report.id
        await session.commit()

    from netlanventory.api.routers.ssh_audit import _run_ssh_audit
    await _run_ssh_audit(report_id=report_id, asset_id=asset_id, host=str(host), port=port)

    async with factory() as session:
        report = (
            await session.execute(
                select(SshAuditReport).where(SshAuditReport.id == report_id)
            )
        ).scalar_one_or_none()
        detail = (
            f"critical: {report.critical_count}, high: {report.high_count}"
            if report else "no result"
        )
        job = await _load_job(session, job_id)
        if job:
            await _set_step_inline(job, session, "ssh_audit",
                {"status": report.status if report else "failed", "detail": detail})

    return report_id


async def _step_default_creds(
    factory, job_id, asset_id, open_ports: list, settings
) -> uuid.UUID | None:
    """Run default credentials scan via nmap NSE."""
    import shutil

    if not shutil.which("nmap"):
        async with factory() as session:
            job = await _load_job(session, job_id)
            if job:
                await _set_step_inline(job, session, "default_creds",
                    {"status": "skipped", "reason": "nmap not found"})
        return None

    async with factory() as session:
        job = await _load_job(session, job_id)
        asset = (
            await session.execute(select(Asset).where(Asset.id == asset_id))
        ).scalar_one()
        if job:
            await _set_step_inline(job, session, "default_creds", {"status": "running"})

        report = DefaultCredsReport(asset_id=asset_id, status="pending")
        session.add(report)
        await session.flush()
        report_id = report.id
        await session.commit()

    from netlanventory.api.routers.default_creds import (
        _PORT_SCRIPTS,
        _run_default_creds_scan,
    )

    open_port_numbers = {p.port_number for p in open_ports}
    seen: set[tuple[int, str]] = set()
    targets = []
    for port, script, label in _PORT_SCRIPTS:
        key = (port, script)
        if key not in seen and (port in open_port_numbers or port == 161):
            seen.add(key)
            targets.append((port, script, label))

    await _run_default_creds_scan(
        report_id=report_id,
        asset_id=asset_id,
        ip=str(asset.ip),
        targets=targets,
    )

    async with factory() as session:
        report = (
            await session.execute(
                select(DefaultCredsReport).where(DefaultCredsReport.id == report_id)
            )
        ).scalar_one_or_none()
        detail = (
            f"{report.vulnerable_count} vulnerable / {report.tested_count} tested"
            if report else "no result"
        )
        job = await _load_job(session, job_id)
        if job:
            await _set_step_inline(job, session, "default_creds",
                {"status": report.status if report else "failed", "detail": detail})

    return report_id


async def _step_ssh_scan(
    factory, job_id, asset_id, has_ssh: bool, has_creds: bool
) -> uuid.UUID | None:
    """Run SSH package→CVE scan if credentials are configured."""
    if not has_ssh:
        async with factory() as session:
            job = await _load_job(session, job_id)
            if job:
                await _set_step_inline(job, session, "ssh_scan",
                    {"status": "skipped", "reason": "SSH port not open"})
        return None

    if not has_creds:
        async with factory() as session:
            job = await _load_job(session, job_id)
            if job:
                await _set_step_inline(job, session, "ssh_scan",
                    {"status": "skipped", "reason": "no SSH credentials configured"})
        return None

    async with factory() as session:
        job = await _load_job(session, job_id)
        if job:
            await _set_step_inline(job, session, "ssh_scan", {"status": "running"})

        report = SshScanReport(asset_id=asset_id, status="pending")
        session.add(report)
        await session.flush()
        report_id = report.id
        await session.commit()

    from netlanventory.api.routers.ssh_scan import _run_ssh_scan
    await _run_ssh_scan(report_id=report_id, asset_id=asset_id)

    async with factory() as session:
        report = (
            await session.execute(
                select(SshScanReport).where(SshScanReport.id == report_id)
            )
        ).scalar_one_or_none()
        detail = (
            f"{report.cves_found or 0} CVEs on {report.packages_found or 0} packages"
            if report else "no result"
        )
        job = await _load_job(session, job_id)
        if job:
            await _set_step_inline(job, session, "ssh_scan",
                {"status": report.status if report else "failed", "detail": detail})

    return report_id


async def _step_nuclei(
    factory, job_id, asset_id, asset, open_ports: list, settings
) -> uuid.UUID | None:
    """Run Nuclei scan based on discovered open ports."""
    import shutil

    nuclei_bin = settings.nuclei_binary
    if not shutil.which(nuclei_bin):
        async with factory() as session:
            job = await _load_job(session, job_id)
            if job:
                await _set_step_inline(job, session, "nuclei",
                    {"status": "skipped", "reason": f"binary not found: {nuclei_bin!r}"})
        return None

    # Build targets using the Nuclei helper (requires dns_entries too)
    async with factory() as session:
        full_asset = (
            await session.execute(
                select(Asset)
                .options(selectinload(Asset.ports), selectinload(Asset.dns_entries))
                .where(Asset.id == asset_id)
            )
        ).scalar_one()

        from netlanventory.api.routers.nuclei import _build_nuclei_targets_and_tags
        targets, tags = _build_nuclei_targets_and_tags(full_asset)

        job = await _load_job(session, job_id)
        if job:
            await _set_step_inline(job, session, "nuclei",
                {"status": "running", "detail": f"{len(targets)} targets"})

        report = NucleiReport(
            asset_id=asset_id,
            status="pending",
            targets=targets,
            tags=tags,
        )
        session.add(report)
        await session.flush()
        report_id = report.id
        await session.commit()

    from netlanventory.api.routers.nuclei import _run_nuclei_scan
    await _run_nuclei_scan(
        report_id=report_id, asset_id=asset_id, targets=targets, tags=tags
    )

    async with factory() as session:
        report = (
            await session.execute(
                select(NucleiReport).where(NucleiReport.id == report_id)
            )
        ).scalar_one_or_none()
        detail = (
            f"{report.findings_count or 0} findings, {report.cve_count or 0} CVEs"
            if report else "no result"
        )
        job = await _load_job(session, job_id)
        if job:
            await _set_step_inline(job, session, "nuclei",
                {"status": report.status if report else "failed", "detail": detail})

    return report_id


async def _step_exploit_validation(
    factory, job_id, asset_id, asset, open_ports, cve_links, settings
) -> None:
    """Run Nuclei exploit validation for all CVEs found on this asset."""
    import re
    import shutil

    _CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
    nuclei_bin = settings.nuclei_binary

    if not shutil.which(nuclei_bin):
        async with factory() as session:
            job = await _load_job(session, job_id)
            if job:
                await _set_step_inline(job, session, "exploit_validation",
                    {"status": "skipped", "reason": "nuclei binary not found"})
        return

    eligible = [
        (link.id, link.cve.cve_id)
        for link in cve_links
        if link.cve and _CVE_RE.match(link.cve.cve_id)
    ]

    if not eligible:
        async with factory() as session:
            job = await _load_job(session, job_id)
            if job:
                await _set_step_inline(job, session, "exploit_validation",
                    {"status": "skipped", "reason": "no standard CVE IDs to test"})
        return

    async with factory() as session:
        full_asset = (
            await session.execute(
                select(Asset)
                .options(selectinload(Asset.ports))
                .where(Asset.id == asset_id)
            )
        ).scalar_one()
        from netlanventory.api.routers.nuclei import _build_nuclei_targets_and_tags
        targets, _ = _build_nuclei_targets_and_tags(full_asset)
        if not targets:
            targets = [str(asset.ip)]

        job = await _load_job(session, job_id)
        if job:
            await _set_step_inline(job, session, "exploit_validation",
                {"status": "running", "detail": f"{len(eligible)} CVEs"})

    from netlanventory.api.routers.exploit_validation import _run_exploit_validation
    await _run_exploit_validation(
        asset_id=asset_id, eligible=eligible, targets=targets
    )

    # Count confirmed
    async with factory() as session:
        confirmed = (
            await session.execute(
                select(AssetCve)
                .where(AssetCve.asset_id == asset_id, AssetCve.exploit_verified.is_(True))
            )
        ).scalars().all()

        job = await _load_job(session, job_id)
        if job:
            await _set_step_inline(job, session, "exploit_validation", {
                "status": "completed",
                "detail": f"{len(confirmed)}/{len(eligible)} CVEs confirmed exploitable",
            })


async def _step_risk_score(factory, job_id: uuid.UUID, asset_id: uuid.UUID) -> None:
    """Recompute and persist the unified risk score."""
    async with factory() as session:
        job = await _load_job(session, job_id)
        if job:
            await _set_step_inline(job, session, "risk_score", {"status": "running"})

    async with factory() as session:
        from netlanventory.core.risk import refresh_asset_risk_score
        score = await refresh_asset_risk_score(session, asset_id)
        await session.commit()

        job = await _load_job(session, job_id)
        if job:
            await _set_step_inline(job, session, "risk_score", {
                "status": "completed",
                "detail": f"score: {score}" if score is not None else "no data",
            })


# ── Internal helpers ───────────────────────────────────────────────────────────


async def _load_job(session: AsyncSession, job_id: uuid.UUID) -> FullAuditJob | None:
    return (
        await session.execute(select(FullAuditJob).where(FullAuditJob.id == job_id))
    ).scalar_one_or_none()


async def _set_step_inline(job: FullAuditJob, session, step: str, info: dict) -> None:
    steps = dict(job.steps or {})
    steps[step] = {**info, "at": datetime.now(timezone.utc).isoformat()}
    job.steps = steps
    await session.commit()


def _is_https_port(port) -> bool:
    _HTTPS = {443, 8443, 4443, 9443}
    svc = (port.service_name or "").lower()
    return port.port_number in _HTTPS or "https" in svc or (svc == "ssl" and port.port_number != 22)


def _ssh_port(asset: Asset) -> int:
    return asset.ssh_port or 22
