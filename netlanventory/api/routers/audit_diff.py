"""Audit diff / comparison router.

Compares two full audit jobs (N vs N-1) to show security progression:
  - Risk score evolution
  - CVE delta (new, resolved, persistent)
  - Per-step comparison (testssl grade, hardening index, etc.)
  - Overall posture change
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import get_current_active_user, get_db
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve
from netlanventory.models.default_creds_report import DefaultCredsReport
from netlanventory.models.full_audit_job import FullAuditJob
from netlanventory.models.nuclei_report import NucleiReport
from netlanventory.models.ssh_audit_report import SshAuditReport
from netlanventory.models.ssh_scan_report import SshScanReport
from netlanventory.models.testssl_report import TestsslReport

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/audit-diff", tags=["audit-diff"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]


# ── Schemas ───────────────────────────────────────────────────────────────────


class StepDiff(BaseModel):
    step: str
    before: dict | None = None
    after: dict | None = None
    change: str  # improved | degraded | unchanged | new | removed


class CveDelta(BaseModel):
    new_cves: list[str]
    resolved_cves: list[str]
    persistent_cves: list[str]
    new_count: int
    resolved_count: int
    persistent_count: int


class AuditDiffOut(BaseModel):
    asset_id: uuid.UUID
    before_job_id: uuid.UUID
    after_job_id: uuid.UUID
    before_date: datetime
    after_date: datetime

    # Risk score
    risk_score_before: float | None = None
    risk_score_after: float | None = None
    risk_score_change: float | None = None

    # CVE delta
    cve_delta: CveDelta

    # Per-step comparison
    step_diffs: list[StepDiff]

    # Overall posture
    posture: str  # improved | degraded | unchanged


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("", response_model=AuditDiffOut)
@limiter.limit("10/minute")
async def get_audit_diff(
    request: Request,
    asset_id: uuid.UUID,
    db: DbDep,
    _user: UserDep,
    before_job_id: uuid.UUID | None = None,
    after_job_id: uuid.UUID | None = None,
) -> AuditDiffOut:
    """Compare two full audit jobs for the same asset.

    If before/after job IDs are not provided, automatically compares
    the two most recent completed jobs.
    """
    # Find jobs
    if before_job_id and after_job_id:
        before_job = await _load_job(db, before_job_id, asset_id)
        after_job = await _load_job(db, after_job_id, asset_id)
        if not before_job:
            raise HTTPException(status_code=404, detail="Before job not found")
        if not after_job:
            raise HTTPException(status_code=404, detail="After job not found")
    else:
        # Get two most recent completed jobs
        result = await db.execute(
            select(FullAuditJob)
            .where(
                FullAuditJob.asset_id == asset_id,
                FullAuditJob.status.in_(["completed", "completed_with_errors"]),
            )
            .order_by(FullAuditJob.created_at.desc())
            .limit(2)
        )
        jobs = list(result.scalars().all())
        if len(jobs) < 2:
            raise HTTPException(
                status_code=400,
                detail="Need at least 2 completed audit jobs to compare. "
                       f"Found {len(jobs)}.",
            )
        after_job, before_job = jobs[0], jobs[1]

    # Ensure before is older
    if before_job.created_at > after_job.created_at:
        before_job, after_job = after_job, before_job

    # Load asset for risk score
    asset = (await db.execute(select(Asset).where(Asset.id == asset_id))).scalar_one_or_none()

    # Risk scores from steps
    before_risk = _extract_risk(before_job)
    after_risk = _extract_risk(after_job)
    risk_change = None
    if before_risk is not None and after_risk is not None:
        risk_change = round(after_risk - before_risk, 2)

    # CVE delta — compare CVEs at each point in time using sub-reports
    before_cves = await _get_cves_at_job(db, before_job)
    after_cves = await _get_cves_at_job(db, after_job)

    new_cves = sorted(after_cves - before_cves)
    resolved_cves = sorted(before_cves - after_cves)
    persistent_cves = sorted(before_cves & after_cves)

    cve_delta = CveDelta(
        new_cves=new_cves,
        resolved_cves=resolved_cves,
        persistent_cves=persistent_cves,
        new_count=len(new_cves),
        resolved_count=len(resolved_cves),
        persistent_count=len(persistent_cves),
    )

    # Step-by-step diff
    step_diffs = _compare_steps(before_job.steps or {}, after_job.steps or {})

    # Detailed sub-report comparison
    sub_diffs = await _compare_sub_reports(db, before_job, after_job)
    step_diffs.extend(sub_diffs)

    # Overall posture
    improved = 0
    degraded = 0
    for sd in step_diffs:
        if sd.change == "improved":
            improved += 1
        elif sd.change == "degraded":
            degraded += 1

    if risk_change is not None and risk_change < -5:
        improved += 2
    elif risk_change is not None and risk_change > 5:
        degraded += 2

    if len(resolved_cves) > len(new_cves):
        improved += 1
    elif len(new_cves) > len(resolved_cves):
        degraded += 1

    posture = "improved" if improved > degraded else ("degraded" if degraded > improved else "unchanged")

    return AuditDiffOut(
        asset_id=asset_id,
        before_job_id=before_job.id,
        after_job_id=after_job.id,
        before_date=before_job.created_at,
        after_date=after_job.created_at,
        risk_score_before=before_risk,
        risk_score_after=after_risk,
        risk_score_change=risk_change,
        cve_delta=cve_delta,
        step_diffs=step_diffs,
        posture=posture,
    )


# ── Internal helpers ──────────────────────────────────────────────────────────


async def _load_job(db: AsyncSession, job_id: uuid.UUID, asset_id: uuid.UUID) -> FullAuditJob | None:
    result = await db.execute(
        select(FullAuditJob).where(FullAuditJob.id == job_id, FullAuditJob.asset_id == asset_id)
    )
    return result.scalar_one_or_none()


def _extract_risk(job: FullAuditJob) -> float | None:
    steps = job.steps or {}
    risk_step = steps.get("risk_score", {})
    detail = risk_step.get("detail", "")
    if "score:" in detail:
        try:
            return float(detail.split("score:")[1].strip())
        except (ValueError, IndexError):
            pass
    return None


async def _get_cves_at_job(db: AsyncSession, job: FullAuditJob) -> set[str]:
    """Get CVE IDs found by a specific job's sub-reports."""
    cve_ids: set[str] = set()

    # From SSH scan report
    if job.ssh_scan_report_id:
        report = (
            await db.execute(select(SshScanReport).where(SshScanReport.id == job.ssh_scan_report_id))
        ).scalar_one_or_none()
        if report and report.findings:
            for pkg_cves in (report.findings.get("packages", {}) or {}).values():
                if isinstance(pkg_cves, list):
                    cve_ids.update(pkg_cves)

    # From Nuclei report
    if job.nuclei_report_id:
        report = (
            await db.execute(select(NucleiReport).where(NucleiReport.id == job.nuclei_report_id))
        ).scalar_one_or_none()
        if report and report.findings:
            for finding in (report.findings if isinstance(report.findings, list) else []):
                cve_id = finding.get("cve_id") or finding.get("matcher-name", "")
                if cve_id and cve_id.startswith("CVE-"):
                    cve_ids.add(cve_id)

    # Fallback: current asset CVEs at job time
    if not cve_ids:
        result = await db.execute(
            select(AssetCve)
            .options(selectinload(AssetCve.cve))
            .where(
                AssetCve.asset_id == job.asset_id,
                AssetCve.created_at <= job.created_at,
            )
        )
        for link in result.scalars().all():
            if link.cve:
                cve_ids.add(link.cve.cve_id)

    return cve_ids


def _compare_steps(before: dict, after: dict) -> list[StepDiff]:
    all_steps = sorted(set(before.keys()) | set(after.keys()))
    diffs: list[StepDiff] = []

    for step in all_steps:
        b = before.get(step)
        a = after.get(step)

        if b and not a:
            diffs.append(StepDiff(step=step, before=b, after=None, change="removed"))
        elif a and not b:
            diffs.append(StepDiff(step=step, before=None, after=a, change="new"))
        elif b and a:
            b_status = b.get("status", "")
            a_status = a.get("status", "")
            if b_status == "failed" and a_status == "completed":
                change = "improved"
            elif b_status == "completed" and a_status == "failed":
                change = "degraded"
            else:
                change = "unchanged"
            diffs.append(StepDiff(step=step, before=b, after=a, change=change))

    return diffs


async def _compare_sub_reports(db: AsyncSession, before: FullAuditJob, after: FullAuditJob) -> list[StepDiff]:
    diffs: list[StepDiff] = []

    # testssl grade comparison
    if before.testssl_report_id and after.testssl_report_id:
        b_report = (await db.execute(select(TestsslReport).where(TestsslReport.id == before.testssl_report_id))).scalar_one_or_none()
        a_report = (await db.execute(select(TestsslReport).where(TestsslReport.id == after.testssl_report_id))).scalar_one_or_none()
        if b_report and a_report:
            grade_order = {"A+": 0, "A": 1, "A-": 2, "B": 3, "C": 4, "D": 5, "F": 6, "T": 7}
            b_grade = b_report.grade or "?"
            a_grade = a_report.grade or "?"
            b_rank = grade_order.get(b_grade, 8)
            a_rank = grade_order.get(a_grade, 8)
            change = "improved" if a_rank < b_rank else ("degraded" if a_rank > b_rank else "unchanged")
            diffs.append(StepDiff(
                step="testssl_grade",
                before={"grade": b_grade, "critical": b_report.critical_count, "high": b_report.high_count},
                after={"grade": a_grade, "critical": a_report.critical_count, "high": a_report.high_count},
                change=change,
            ))

    # ssh-audit comparison
    if before.ssh_audit_report_id and after.ssh_audit_report_id:
        b_report = (await db.execute(select(SshAuditReport).where(SshAuditReport.id == before.ssh_audit_report_id))).scalar_one_or_none()
        a_report = (await db.execute(select(SshAuditReport).where(SshAuditReport.id == after.ssh_audit_report_id))).scalar_one_or_none()
        if b_report and a_report:
            b_total = b_report.critical_count + b_report.high_count
            a_total = a_report.critical_count + a_report.high_count
            change = "improved" if a_total < b_total else ("degraded" if a_total > b_total else "unchanged")
            diffs.append(StepDiff(
                step="ssh_audit_issues",
                before={"critical": b_report.critical_count, "high": b_report.high_count},
                after={"critical": a_report.critical_count, "high": a_report.high_count},
                change=change,
            ))

    # default_creds comparison
    if before.default_creds_report_id and after.default_creds_report_id:
        b_report = (await db.execute(select(DefaultCredsReport).where(DefaultCredsReport.id == before.default_creds_report_id))).scalar_one_or_none()
        a_report = (await db.execute(select(DefaultCredsReport).where(DefaultCredsReport.id == after.default_creds_report_id))).scalar_one_or_none()
        if b_report and a_report:
            change = "improved" if a_report.vulnerable_count < b_report.vulnerable_count else (
                "degraded" if a_report.vulnerable_count > b_report.vulnerable_count else "unchanged"
            )
            diffs.append(StepDiff(
                step="default_creds",
                before={"vulnerable": b_report.vulnerable_count, "tested": b_report.tested_count},
                after={"vulnerable": a_report.vulnerable_count, "tested": a_report.tested_count},
                change=change,
            ))

    return diffs
