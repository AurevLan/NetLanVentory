"""Remediation Workflow engine (innovation #8).

Implements the state machine, the playbook signing, and the dry-run
parsing logic. The actual `ansible-playbook` subprocess execution is
**deferred to a separate `remediation-worker` container** (out of scope
for this commit) — the API queues jobs and accepts dry-run results from
the worker.

State machine:
    DRAFT
      ↓ request_dry_run()
    DRY_RUN_PENDING
      ↓ record_dry_run_result()
    DRY_RUN_DONE
      ↓ submit_for_approval()
    AWAITING_APPROVAL
      ↓ approve()  (admin, must differ from creator if requires_four_eyes)
    APPROVED
      ↓ start_execution()
    RUNNING
      ↓ record_execution_result()
    SUCCEEDED | FAILED | HEALTHCHECK_FAILED
      ↓ rollback() (from HEALTHCHECK_FAILED only)
    ROLLED_BACK

Design rules:
  - Every transition is validated by `_assert_transition()` — an invalid
    transition raises `InvalidTransitionError` with the offending pair.
  - Playbook content is signed (HMAC-SHA256) at creation. Any later edit
    breaks the signature and forces a re-dry-run before approval.
  - 4-eyes is enforced in `approve()` — the approver must be a different
    user than the creator when `requires_four_eyes=True`.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.core.logging import get_logger
from netlanventory.models.remediation_job import RemediationJob, RemediationStatus

logger = get_logger(__name__)


# ── Errors ────────────────────────────────────────────────────────────────────


class InvalidTransitionError(Exception):
    """Raised when a state machine transition is not allowed."""


class SignatureMismatchError(Exception):
    """Raised when a job's playbook signature no longer matches its content."""


class FourEyesViolationError(Exception):
    """Raised when an admin tries to approve a job they created themselves."""


# ── State machine ─────────────────────────────────────────────────────────────


# Allowed transitions: from_state → set of legal next states
_TRANSITIONS: dict[RemediationStatus, frozenset[RemediationStatus]] = {
    RemediationStatus.DRAFT: frozenset({RemediationStatus.DRY_RUN_PENDING}),
    RemediationStatus.DRY_RUN_PENDING: frozenset(
        {RemediationStatus.DRY_RUN_DONE, RemediationStatus.FAILED}
    ),
    RemediationStatus.DRY_RUN_DONE: frozenset(
        {RemediationStatus.AWAITING_APPROVAL, RemediationStatus.DRAFT}
    ),
    RemediationStatus.AWAITING_APPROVAL: frozenset(
        {RemediationStatus.APPROVED, RemediationStatus.DRAFT}
    ),
    RemediationStatus.APPROVED: frozenset(
        {RemediationStatus.RUNNING, RemediationStatus.DRAFT}
    ),
    RemediationStatus.RUNNING: frozenset(
        {
            RemediationStatus.SUCCEEDED,
            RemediationStatus.FAILED,
            RemediationStatus.HEALTHCHECK_FAILED,
        }
    ),
    RemediationStatus.HEALTHCHECK_FAILED: frozenset({RemediationStatus.ROLLED_BACK}),
    # Terminal states have no outgoing transitions
    RemediationStatus.SUCCEEDED: frozenset(),
    RemediationStatus.FAILED: frozenset(),
    RemediationStatus.ROLLED_BACK: frozenset(),
}


def is_terminal(status: RemediationStatus) -> bool:
    return not _TRANSITIONS.get(status, frozenset())


def allowed_next(status: RemediationStatus) -> frozenset[RemediationStatus]:
    return _TRANSITIONS.get(status, frozenset())


def _assert_transition(current: RemediationStatus, next_state: RemediationStatus) -> None:
    if next_state not in allowed_next(current):
        raise InvalidTransitionError(
            f"Cannot transition from {current.value} to {next_state.value}"
        )


# ── Playbook signature ────────────────────────────────────────────────────────


def _signing_key() -> bytes:
    """Derive the signing key from the app SECRET_KEY.

    Falls back to a fixed test key only when SECRET_KEY is the dev default
    or unset, so unit tests are deterministic.
    """
    from netlanventory.core.config import get_settings

    secret = get_settings().secret_key or "test-key"
    return hashlib.sha256(("remediation:" + secret).encode("utf-8")).digest()


def sign_playbook(playbook_yaml: str) -> str:
    """HMAC-SHA256 over the playbook body. Returned hex digest is short
    enough to fit `RemediationJob.playbook_signature` (128 chars)."""
    return hmac.new(_signing_key(), playbook_yaml.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_playbook_signature(job: RemediationJob) -> bool:
    if not job.playbook_signature:
        return False
    return hmac.compare_digest(
        job.playbook_signature, sign_playbook(job.playbook_yaml)
    )


# ── Dry-run output parsing ────────────────────────────────────────────────────


@dataclass(frozen=True)
class DryRunSummary:
    changed_count: int
    ok_count: int
    failed_count: int
    raw_diff: dict


def parse_ansible_dry_run(stdout: str) -> DryRunSummary:
    """Parse an `ansible-playbook --check --diff` output into a summary.

    This is a deliberately lightweight parser: we look for the standard
    `PLAY RECAP` line that Ansible always emits and count changed/ok/failed.
    The raw output is preserved in `raw_diff` for the UI.
    """
    changed = ok = failed = 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line or "PLAY RECAP" in line:
            continue
        # Typical line: "host : ok=12 changed=3 unreachable=0 failed=0 …"
        if "ok=" in line and "changed=" in line:
            for token in line.replace("\t", " ").split():
                if token.startswith("ok="):
                    try:
                        ok += int(token[3:])
                    except ValueError:
                        pass
                elif token.startswith("changed="):
                    try:
                        changed += int(token[8:])
                    except ValueError:
                        pass
                elif token.startswith("failed="):
                    try:
                        failed += int(token[7:])
                    except ValueError:
                        pass
    return DryRunSummary(
        changed_count=changed,
        ok_count=ok,
        failed_count=failed,
        raw_diff={"stdout_excerpt": stdout[:5000]},
    )


# ── Public state-mutation API ─────────────────────────────────────────────────


async def create_draft(
    session: AsyncSession,
    *,
    asset_id: uuid.UUID,
    playbook_yaml: str,
    cve_id: str | None = None,
    rollback_yaml: str | None = None,
    healthcheck_cmd: str | None = None,
    created_by: uuid.UUID | None = None,
    requires_four_eyes: bool = True,
) -> RemediationJob:
    """Create a new draft job with a freshly computed signature."""
    job = RemediationJob(
        asset_id=asset_id,
        cve_id=cve_id,
        playbook_yaml=playbook_yaml,
        rollback_yaml=rollback_yaml,
        healthcheck_cmd=healthcheck_cmd,
        playbook_signature=sign_playbook(playbook_yaml),
        status=RemediationStatus.DRAFT,
        requires_four_eyes=requires_four_eyes,
        created_by=created_by,
    )
    session.add(job)
    await session.flush()
    logger.info("remediation_draft_created", job_id=str(job.id), asset_id=str(asset_id))
    return job


async def request_dry_run(session: AsyncSession, job: RemediationJob) -> RemediationJob:
    _assert_transition(job.status, RemediationStatus.DRY_RUN_PENDING)
    if not verify_playbook_signature(job):
        raise SignatureMismatchError("playbook content has been edited; re-create the job")
    job.status = RemediationStatus.DRY_RUN_PENDING
    await session.flush()
    return job


async def record_dry_run_result(
    session: AsyncSession, job: RemediationJob, summary: DryRunSummary
) -> RemediationJob:
    _assert_transition(job.status, RemediationStatus.DRY_RUN_DONE)
    job.status = RemediationStatus.DRY_RUN_DONE
    job.dry_run_diff = {
        "changed_count": summary.changed_count,
        "ok_count": summary.ok_count,
        "failed_count": summary.failed_count,
        **summary.raw_diff,
    }
    await session.flush()
    return job


async def submit_for_approval(session: AsyncSession, job: RemediationJob) -> RemediationJob:
    _assert_transition(job.status, RemediationStatus.AWAITING_APPROVAL)
    if not verify_playbook_signature(job):
        raise SignatureMismatchError("playbook signature broken — re-run dry-run")
    job.status = RemediationStatus.AWAITING_APPROVAL
    await session.flush()
    return job


async def approve(
    session: AsyncSession, job: RemediationJob, *, approver_id: uuid.UUID
) -> RemediationJob:
    _assert_transition(job.status, RemediationStatus.APPROVED)
    if job.requires_four_eyes and approver_id == job.created_by:
        raise FourEyesViolationError(
            "the creator of a job cannot approve it (4-eyes policy)"
        )
    job.status = RemediationStatus.APPROVED
    job.approved_by = approver_id
    await session.flush()
    return job


async def start_execution(session: AsyncSession, job: RemediationJob) -> RemediationJob:
    _assert_transition(job.status, RemediationStatus.RUNNING)
    job.status = RemediationStatus.RUNNING
    job.executed_at = datetime.now(timezone.utc)
    await session.flush()
    return job


async def record_execution_result(
    session: AsyncSession,
    job: RemediationJob,
    *,
    succeeded: bool,
    log: str,
    healthcheck_passed: bool = True,
) -> RemediationJob:
    if not succeeded:
        next_state = RemediationStatus.FAILED
    elif not healthcheck_passed:
        next_state = RemediationStatus.HEALTHCHECK_FAILED
    else:
        next_state = RemediationStatus.SUCCEEDED
    _assert_transition(job.status, next_state)
    job.status = next_state
    job.execution_log = (log or "")[:50_000]
    await session.flush()
    return job


async def rollback(session: AsyncSession, job: RemediationJob, *, log: str) -> RemediationJob:
    _assert_transition(job.status, RemediationStatus.ROLLED_BACK)
    job.status = RemediationStatus.ROLLED_BACK
    job.rolled_back_at = datetime.now(timezone.utc)
    if log:
        existing = job.execution_log or ""
        job.execution_log = (existing + "\n--- ROLLBACK ---\n" + log)[:50_000]
    await session.flush()
    return job
