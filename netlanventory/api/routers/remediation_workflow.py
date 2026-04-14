"""Remediation Workflow API (innovation #8).

Exposes the state machine: list/create draft, request dry-run, record
dry-run result, submit for approval, approve, start execution, record
execution result, rollback. The actual playbook execution is performed
by an out-of-process worker (not part of this commit) which calls back
to `/dry-run-result` and `/execution-result` endpoints.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import (
    actor_from_user,
    get_current_active_user,
    get_db,
    require_admin,
)
from netlanventory.core.audit import log_action
from netlanventory.core.logging import get_logger
from netlanventory.core.remediation_workflow import (
    DryRunSummary,
    FourEyesViolationError,
    InvalidTransitionError,
    SignatureMismatchError,
    approve,
    create_draft,
    parse_ansible_dry_run,
    record_dry_run_result,
    record_execution_result,
    request_dry_run,
    rollback,
    start_execution,
    submit_for_approval,
)
from netlanventory.models.remediation_job import RemediationJob, RemediationStatus

logger = get_logger(__name__)

router = APIRouter(prefix="/remediation/jobs", tags=["remediation-workflow"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]
AdminDep = Annotated[object, Depends(require_admin)]


# ── Schemas ───────────────────────────────────────────────────────────────────


class JobCreateIn(BaseModel):
    asset_id: uuid.UUID
    playbook_yaml: str = Field(..., min_length=10, max_length=200_000)
    cve_id: str | None = None
    rollback_yaml: str | None = Field(None, max_length=200_000)
    healthcheck_cmd: str | None = Field(None, max_length=2000)
    requires_four_eyes: bool = True


class DryRunResultIn(BaseModel):
    stdout: str = Field(..., max_length=200_000)


class ExecutionResultIn(BaseModel):
    succeeded: bool
    log: str = Field(..., max_length=200_000)
    healthcheck_passed: bool = True


class RollbackIn(BaseModel):
    log: str = Field(..., max_length=50_000)


class JobOut(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    cve_id: str | None
    status: RemediationStatus
    requires_four_eyes: bool
    dry_run_diff: dict | None
    created_by: uuid.UUID | None
    approved_by: uuid.UUID | None
    executed_at: datetime | None
    rolled_back_at: datetime | None
    created_at: datetime
    updated_at: datetime


def _to_out(job: RemediationJob) -> JobOut:
    return JobOut(
        id=job.id,
        asset_id=job.asset_id,
        cve_id=job.cve_id,
        status=job.status,
        requires_four_eyes=job.requires_four_eyes,
        dry_run_diff=job.dry_run_diff,
        created_by=job.created_by,
        approved_by=job.approved_by,
        executed_at=job.executed_at,
        rolled_back_at=job.rolled_back_at,
        created_at=job.created_at,
        updated_at=job.updated_at,
    )


def _handle_state_error(exc: Exception) -> None:
    if isinstance(exc, InvalidTransitionError):
        raise HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, SignatureMismatchError):
        raise HTTPException(status_code=409, detail="signature_mismatch: " + str(exc))
    if isinstance(exc, FourEyesViolationError):
        raise HTTPException(status_code=403, detail="four_eyes_violation: " + str(exc))
    raise


async def _load_or_404(db: AsyncSession, job_id: uuid.UUID) -> RemediationJob:
    job = (
        await db.execute(select(RemediationJob).where(RemediationJob.id == job_id))
    ).scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return job


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("", response_model=list[JobOut])
async def list_jobs(
    db: DbDep, _user: UserDep,
    asset_id: uuid.UUID | None = None,
    job_status: RemediationStatus | None = None,
    limit: int = 100,
) -> list[JobOut]:
    stmt = select(RemediationJob).order_by(RemediationJob.created_at.desc()).limit(min(limit, 500))
    if asset_id:
        stmt = stmt.where(RemediationJob.asset_id == asset_id)
    if job_status:
        stmt = stmt.where(RemediationJob.status == job_status)
    rows = (await db.execute(stmt)).scalars().all()
    return [_to_out(j) for j in rows]


@router.get("/{job_id}", response_model=JobOut)
async def get_job(job_id: uuid.UUID, db: DbDep, _user: UserDep) -> JobOut:
    return _to_out(await _load_or_404(db, job_id))


@router.post("", response_model=JobOut, status_code=status.HTTP_201_CREATED)
async def create_job(
    payload: JobCreateIn, db: DbDep, current_user: UserDep,
) -> JobOut:
    actor = actor_from_user(current_user)
    creator_id = getattr(current_user, "id", None)
    job = await create_draft(
        db,
        asset_id=payload.asset_id,
        playbook_yaml=payload.playbook_yaml,
        cve_id=payload.cve_id,
        rollback_yaml=payload.rollback_yaml,
        healthcheck_cmd=payload.healthcheck_cmd,
        created_by=creator_id,
        requires_four_eyes=payload.requires_four_eyes,
    )
    await log_action(
        db, user=actor, action="remediation.create",
        resource_type="remediation_job", resource_id=str(job.id),
        detail={"asset_id": str(payload.asset_id), "cve_id": payload.cve_id},
    )
    await db.commit()
    return _to_out(job)


@router.post("/{job_id}/dry-run", response_model=JobOut)
async def request_dry_run_endpoint(
    job_id: uuid.UUID, db: DbDep, _user: UserDep,
) -> JobOut:
    job = await _load_or_404(db, job_id)
    try:
        await request_dry_run(db, job)
    except Exception as exc:
        _handle_state_error(exc)
    await db.commit()
    return _to_out(job)


@router.post("/{job_id}/dry-run-result", response_model=JobOut)
async def post_dry_run_result(
    job_id: uuid.UUID, payload: DryRunResultIn, db: DbDep, _admin: AdminDep,
) -> JobOut:
    """Worker callback: record the parsed dry-run output."""
    job = await _load_or_404(db, job_id)
    summary = parse_ansible_dry_run(payload.stdout)
    try:
        await record_dry_run_result(db, job, summary)
    except Exception as exc:
        _handle_state_error(exc)
    await db.commit()
    return _to_out(job)


@router.post("/{job_id}/submit", response_model=JobOut)
async def submit_endpoint(job_id: uuid.UUID, db: DbDep, _user: UserDep) -> JobOut:
    job = await _load_or_404(db, job_id)
    try:
        await submit_for_approval(db, job)
    except Exception as exc:
        _handle_state_error(exc)
    await db.commit()
    return _to_out(job)


@router.post("/{job_id}/approve", response_model=JobOut)
async def approve_endpoint(
    job_id: uuid.UUID, db: DbDep, current_user: UserDep, _admin: AdminDep,
) -> JobOut:
    job = await _load_or_404(db, job_id)
    approver_id = getattr(current_user, "id", None)
    if approver_id is None:
        raise HTTPException(status_code=403, detail="cannot identify approver")
    try:
        await approve(db, job, approver_id=approver_id)
    except Exception as exc:
        _handle_state_error(exc)
    actor = actor_from_user(current_user)
    await log_action(
        db, user=actor, action="remediation.approve",
        resource_type="remediation_job", resource_id=str(job.id),
    )
    await db.commit()
    return _to_out(job)


@router.post("/{job_id}/start", response_model=JobOut)
async def start_endpoint(
    job_id: uuid.UUID, db: DbDep, _user: UserDep, _admin: AdminDep,
) -> JobOut:
    job = await _load_or_404(db, job_id)
    try:
        await start_execution(db, job)
    except Exception as exc:
        _handle_state_error(exc)
    await db.commit()
    return _to_out(job)


@router.post("/{job_id}/execution-result", response_model=JobOut)
async def post_execution_result(
    job_id: uuid.UUID, payload: ExecutionResultIn, db: DbDep, _admin: AdminDep,
) -> JobOut:
    """Worker callback: record execution outcome."""
    job = await _load_or_404(db, job_id)
    try:
        await record_execution_result(
            db, job,
            succeeded=payload.succeeded,
            log=payload.log,
            healthcheck_passed=payload.healthcheck_passed,
        )
    except Exception as exc:
        _handle_state_error(exc)
    await db.commit()
    return _to_out(job)


@router.post("/{job_id}/rollback", response_model=JobOut)
async def rollback_endpoint(
    job_id: uuid.UUID, payload: RollbackIn, db: DbDep, _admin: AdminDep,
) -> JobOut:
    job = await _load_or_404(db, job_id)
    try:
        await rollback(db, job, log=payload.log)
    except Exception as exc:
        _handle_state_error(exc)
    await db.commit()
    return _to_out(job)
