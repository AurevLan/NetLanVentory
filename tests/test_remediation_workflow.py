"""Unit tests for the Remediation Workflow state machine + signature.

Pure tests — no DB. Builds a fake `RemediationJob` via SimpleNamespace
and exercises every legal and illegal transition, plus the signature
verification and dry-run parser.
"""

from __future__ import annotations

import asyncio
import uuid
from types import SimpleNamespace

import pytest

from netlanventory.core.remediation_workflow import (
    DryRunSummary,
    FourEyesViolationError,
    InvalidTransitionError,
    SignatureMismatchError,
    _TRANSITIONS,
    allowed_next,
    is_terminal,
    parse_ansible_dry_run,
    sign_playbook,
    verify_playbook_signature,
)
from netlanventory.models.remediation_job import RemediationStatus


# ── State machine ─────────────────────────────────────────────────────────────


def test_terminal_states_have_no_outgoing():
    for s in (RemediationStatus.SUCCEEDED, RemediationStatus.FAILED, RemediationStatus.ROLLED_BACK):
        assert is_terminal(s)
        assert allowed_next(s) == frozenset()


def test_draft_can_only_go_to_dry_run_pending():
    assert allowed_next(RemediationStatus.DRAFT) == frozenset({RemediationStatus.DRY_RUN_PENDING})


def test_running_can_branch_to_three_outcomes():
    nexts = allowed_next(RemediationStatus.RUNNING)
    assert nexts == frozenset({
        RemediationStatus.SUCCEEDED,
        RemediationStatus.FAILED,
        RemediationStatus.HEALTHCHECK_FAILED,
    })


def test_healthcheck_failed_only_rolls_back():
    assert allowed_next(RemediationStatus.HEALTHCHECK_FAILED) == frozenset(
        {RemediationStatus.ROLLED_BACK}
    )


def test_every_status_has_an_entry():
    """Defensive: every enum value must appear in the transitions table."""
    for s in RemediationStatus:
        assert s in _TRANSITIONS


def test_no_transition_to_initial_draft_from_terminal():
    """Terminal states must not loop back."""
    for terminal in (RemediationStatus.SUCCEEDED, RemediationStatus.ROLLED_BACK, RemediationStatus.FAILED):
        assert RemediationStatus.DRAFT not in allowed_next(terminal)


# ── Signature ─────────────────────────────────────────────────────────────────


def test_sign_playbook_is_deterministic():
    body = "- hosts: all\n  tasks: []"
    assert sign_playbook(body) == sign_playbook(body)


def test_sign_playbook_changes_with_content():
    a = sign_playbook("- hosts: all")
    b = sign_playbook("- hosts: web")
    assert a != b


def test_verify_signature_match():
    body = "- hosts: all\n  tasks: [ apt: name=nginx state=latest ]"
    job = SimpleNamespace(playbook_yaml=body, playbook_signature=sign_playbook(body))
    assert verify_playbook_signature(job) is True


def test_verify_signature_mismatch_after_edit():
    body = "- hosts: all"
    sig = sign_playbook(body)
    job = SimpleNamespace(playbook_yaml=body + "\n# edited", playbook_signature=sig)
    assert verify_playbook_signature(job) is False


def test_verify_signature_missing_returns_false():
    job = SimpleNamespace(playbook_yaml="x", playbook_signature=None)
    assert verify_playbook_signature(job) is False


def test_signature_length_fits_column():
    """Hex SHA256 = 64 chars, column is VARCHAR(128)."""
    sig = sign_playbook("body")
    assert len(sig) == 64


# ── Dry-run parser ────────────────────────────────────────────────────────────


def test_parse_ansible_recap_counts():
    output = """\
PLAY [all] *********************************************************
TASK [Install nginx] ************************************************
changed: [host1]
changed: [host2]
PLAY RECAP **********************************************************
host1                      : ok=5    changed=2    unreachable=0    failed=0
host2                      : ok=5    changed=1    unreachable=0    failed=0
"""
    summary = parse_ansible_dry_run(output)
    assert summary.ok_count == 10
    assert summary.changed_count == 3
    assert summary.failed_count == 0


def test_parse_handles_failures():
    output = "host1 : ok=2 changed=0 failed=1"
    summary = parse_ansible_dry_run(output)
    assert summary.failed_count == 1
    assert summary.changed_count == 0


def test_parse_empty_output():
    summary = parse_ansible_dry_run("")
    assert summary.ok_count == 0
    assert summary.failed_count == 0


def test_parse_keeps_raw_excerpt():
    raw = "x" * 10000
    summary = parse_ansible_dry_run(raw)
    excerpt = summary.raw_diff["stdout_excerpt"]
    assert len(excerpt) <= 5000


# ── Async transition flows (fake session) ─────────────────────────────────────


class _FakeSession:
    """Minimal async stub — only flush() is called by the helpers."""

    async def flush(self) -> None:
        return None


def _job(**overrides):
    base = dict(
        id=uuid.uuid4(),
        asset_id=uuid.uuid4(),
        cve_id="CVE-2024-1",
        playbook_yaml="- hosts: all",
        playbook_signature=sign_playbook("- hosts: all"),
        status=RemediationStatus.DRAFT,
        requires_four_eyes=True,
        created_by=uuid.uuid4(),
        approved_by=None,
        dry_run_diff=None,
        execution_log=None,
        executed_at=None,
        rolled_back_at=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_full_happy_path_sync():
    """Drive the workflow through the full happy path using the helpers."""
    from netlanventory.core import remediation_workflow as rw

    async def go():
        sess = _FakeSession()
        creator = uuid.uuid4()
        approver = uuid.uuid4()
        job = _job(created_by=creator)

        await rw.request_dry_run(sess, job)
        assert job.status == RemediationStatus.DRY_RUN_PENDING

        await rw.record_dry_run_result(
            sess, job,
            DryRunSummary(changed_count=2, ok_count=10, failed_count=0, raw_diff={}),
        )
        assert job.status == RemediationStatus.DRY_RUN_DONE
        assert job.dry_run_diff["changed_count"] == 2

        await rw.submit_for_approval(sess, job)
        assert job.status == RemediationStatus.AWAITING_APPROVAL

        await rw.approve(sess, job, approver_id=approver)
        assert job.status == RemediationStatus.APPROVED
        assert job.approved_by == approver

        await rw.start_execution(sess, job)
        assert job.status == RemediationStatus.RUNNING

        await rw.record_execution_result(sess, job, succeeded=True, log="ok")
        assert job.status == RemediationStatus.SUCCEEDED

    asyncio.run(go())


def test_four_eyes_blocks_self_approval():
    from netlanventory.core import remediation_workflow as rw

    async def go():
        sess = _FakeSession()
        creator = uuid.uuid4()
        job = _job(created_by=creator, status=RemediationStatus.AWAITING_APPROVAL)
        with pytest.raises(FourEyesViolationError):
            await rw.approve(sess, job, approver_id=creator)

    asyncio.run(go())


def test_four_eyes_disabled_allows_self_approval():
    from netlanventory.core import remediation_workflow as rw

    async def go():
        sess = _FakeSession()
        creator = uuid.uuid4()
        job = _job(
            created_by=creator,
            status=RemediationStatus.AWAITING_APPROVAL,
            requires_four_eyes=False,
        )
        await rw.approve(sess, job, approver_id=creator)
        assert job.status == RemediationStatus.APPROVED

    asyncio.run(go())


def test_invalid_transition_raises():
    from netlanventory.core import remediation_workflow as rw

    async def go():
        sess = _FakeSession()
        job = _job(status=RemediationStatus.DRAFT)
        # Cannot jump from DRAFT directly to RUNNING
        with pytest.raises(InvalidTransitionError):
            await rw.start_execution(sess, job)

    asyncio.run(go())


def test_signature_mismatch_blocks_dry_run():
    from netlanventory.core import remediation_workflow as rw

    async def go():
        sess = _FakeSession()
        job = _job()
        job.playbook_yaml += "\n# tampered"
        with pytest.raises(SignatureMismatchError):
            await rw.request_dry_run(sess, job)

    asyncio.run(go())


def test_healthcheck_failure_routes_to_healthcheck_failed():
    from netlanventory.core import remediation_workflow as rw

    async def go():
        sess = _FakeSession()
        job = _job(status=RemediationStatus.RUNNING)
        await rw.record_execution_result(
            sess, job, succeeded=True, log="ok", healthcheck_passed=False
        )
        assert job.status == RemediationStatus.HEALTHCHECK_FAILED

    asyncio.run(go())


def test_rollback_only_from_healthcheck_failed():
    from netlanventory.core import remediation_workflow as rw

    async def go():
        sess = _FakeSession()
        # From SUCCEEDED: cannot rollback
        job = _job(status=RemediationStatus.SUCCEEDED)
        with pytest.raises(InvalidTransitionError):
            await rw.rollback(sess, job, log="x")
        # From HEALTHCHECK_FAILED: works
        job2 = _job(status=RemediationStatus.HEALTHCHECK_FAILED)
        await rw.rollback(sess, job2, log="restored")
        assert job2.status == RemediationStatus.ROLLED_BACK
        assert "ROLLBACK" in (job2.execution_log or "")

    asyncio.run(go())
