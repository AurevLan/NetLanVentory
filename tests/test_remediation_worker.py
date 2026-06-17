"""Unit tests for the standalone remediation worker.

The worker (`remediation_worker/worker.py`) imports nothing from
`netlanventory` and talks to the API over HTTP, so these tests use a fake
API client and monkeypatch `subprocess.run` — no network, no real Ansible.
The repo root is added to sys.path because the worker is not part of the
installed `netlanventory` package.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from remediation_worker import worker as w  # noqa: E402
from remediation_worker.worker import Job, _build_inventory, _run_ansible  # noqa: E402


# ── Job.from_api ─────────────────────────────────────────────────────────────


class TestJobFromApi:
    def test_full_payload(self):
        job = Job.from_api(
            {"id": "j1", "asset_id": "a1", "cve_id": "CVE-2024-1", "status": "approved"}
        )
        assert job.id == "j1"
        assert job.asset_id == "a1"
        assert job.cve_id == "CVE-2024-1"
        assert job.status == "approved"

    def test_cve_id_is_optional(self):
        job = Job.from_api({"id": "j1", "asset_id": "a1", "status": "dry_run_pending"})
        assert job.cve_id is None


# ── _build_inventory ─────────────────────────────────────────────────────────


class TestBuildInventory:
    def test_uses_ip_when_present(self):
        inv = _build_inventory({"ip": "10.0.0.5", "ssh_user": "ops", "ssh_port": 2222})
        assert "10.0.0.5" in inv
        assert "ansible_user=ops" in inv
        assert "ansible_port=2222" in inv

    def test_falls_back_to_hostname(self):
        inv = _build_inventory({"hostname": "host.example.com"})
        # exact-equality on the parsed host field (no substring/membership
        # check, which CodeQL flags as incomplete-URL-sanitization)
        host_field = inv.splitlines()[1].split()[0]
        assert host_field == "host.example.com"

    def test_falls_back_to_localhost(self):
        inv = _build_inventory({})
        assert "localhost" in inv

    def test_defaults_user_and_port(self):
        inv = _build_inventory({"ip": "10.0.0.5"})
        assert "ansible_user=ansible" in inv
        assert "ansible_port=22" in inv

    def test_hardening_args_present(self):
        inv = _build_inventory({"ip": "10.0.0.5"})
        assert "StrictHostKeyChecking=no" in inv
        assert "ansible_ssh_private_key_file=" in inv


# ── _run_ansible (subprocess monkeypatched) ──────────────────────────────────


class _FakeProc:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TestRunAnsible:
    def test_success(self, monkeypatch):
        monkeypatch.setattr(
            w.subprocess, "run", lambda *a, **k: _FakeProc(0, "ok", "")
        )
        ok, out = _run_ansible(pathlib.Path("/tmp/p.yml"), pathlib.Path("/tmp/i.ini"), check=True)
        assert ok is True
        assert "ok" in out

    def test_failure_returncode(self, monkeypatch):
        monkeypatch.setattr(
            w.subprocess, "run", lambda *a, **k: _FakeProc(2, "", "boom")
        )
        ok, out = _run_ansible(pathlib.Path("/tmp/p.yml"), pathlib.Path("/tmp/i.ini"), check=False)
        assert ok is False
        assert "boom" in out

    def test_timeout(self, monkeypatch):
        def _raise(*a, **k):
            raise subprocess.TimeoutExpired(cmd="ansible-playbook", timeout=1)

        monkeypatch.setattr(w.subprocess, "run", _raise)
        ok, out = _run_ansible(pathlib.Path("/tmp/p.yml"), pathlib.Path("/tmp/i.ini"), check=False)
        assert ok is False
        assert "timed out" in out

    def test_binary_missing(self, monkeypatch):
        def _raise(*a, **k):
            raise FileNotFoundError

        monkeypatch.setattr(w.subprocess, "run", _raise)
        ok, out = _run_ansible(pathlib.Path("/tmp/p.yml"), pathlib.Path("/tmp/i.ini"), check=False)
        assert ok is False
        assert "not found" in out


# ── process_dry_run / process_execution (fake API client) ────────────────────


class _FakeApi:
    """Records the calls the worker makes, returns canned data."""

    def __init__(self, asset: dict | None, playbook: str = "- hosts: target") -> None:
        self._asset = asset
        self._playbook = playbook
        self.dry_run_posts: list[tuple[str, str]] = []
        self.execution_posts: list[dict] = []

    async def get_asset(self, asset_id: str) -> dict | None:
        return self._asset

    async def get_playbook(self, job_id: str) -> str:
        return self._playbook

    async def post_dry_run_result(self, job_id: str, stdout: str) -> None:
        self.dry_run_posts.append((job_id, stdout))

    async def post_execution_result(
        self, job_id: str, *, succeeded: bool, log: str, healthcheck_passed: bool
    ) -> None:
        self.execution_posts.append(
            {"job_id": job_id, "succeeded": succeeded, "healthcheck": healthcheck_passed}
        )


def _job(status: str) -> Job:
    return Job(id="j1", asset_id="a1", cve_id=None, status=status)


@pytest.mark.asyncio
class TestProcessDryRun:
    async def test_happy_path_posts_stdout(self, monkeypatch):
        monkeypatch.setattr(w, "_run_ansible", lambda *a, **k: (True, "dry output"))
        api = _FakeApi(asset={"ip": "10.0.0.5"})
        await w.process_dry_run(api, _job("dry_run_pending"))
        assert api.dry_run_posts == [("j1", "dry output")]

    async def test_missing_asset_posts_nothing(self, monkeypatch):
        monkeypatch.setattr(w, "_run_ansible", lambda *a, **k: (True, "x"))
        api = _FakeApi(asset=None)
        await w.process_dry_run(api, _job("dry_run_pending"))
        assert api.dry_run_posts == []


@pytest.mark.asyncio
class TestProcessExecution:
    async def test_success_reports_passed(self, monkeypatch):
        monkeypatch.setattr(w, "_run_ansible", lambda *a, **k: (True, "applied"))
        api = _FakeApi(asset={"ip": "10.0.0.5"})
        await w.process_execution(api, _job("approved"))
        assert len(api.execution_posts) == 1
        assert api.execution_posts[0]["succeeded"] is True
        assert api.execution_posts[0]["healthcheck"] is True

    async def test_ansible_failure_reports_failed(self, monkeypatch):
        monkeypatch.setattr(w, "_run_ansible", lambda *a, **k: (False, "error"))
        api = _FakeApi(asset={"ip": "10.0.0.5"})
        await w.process_execution(api, _job("approved"))
        assert api.execution_posts[0]["succeeded"] is False

    async def test_missing_asset_reports_failed(self, monkeypatch):
        # Unlike dry-run, a missing asset on execution must report FAILED.
        api = _FakeApi(asset=None)
        await w.process_execution(api, _job("approved"))
        assert len(api.execution_posts) == 1
        assert api.execution_posts[0]["succeeded"] is False
        assert api.execution_posts[0]["healthcheck"] is False
