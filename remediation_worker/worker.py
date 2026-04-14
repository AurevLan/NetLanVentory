"""Remediation worker — polls the NetLanVentory API for jobs and runs Ansible.

Lifecycle per job:
  1. List jobs in DRY_RUN_PENDING state via GET /remediation/jobs?status=...
  2. Pull the playbook YAML
  3. Write to a tempfile and run `ansible-playbook --check --diff` against
     a single-host inventory built from the asset record
  4. POST the parsed stdout to /remediation/jobs/{id}/dry-run-result
  5. Same loop for APPROVED state, but without --check (real run), then
     POST execution result + healthcheck

Design notes:
  - This file is intentionally **standalone** — it imports nothing from
    `netlanventory.*`. The worker only knows the public REST API. That
    makes it deployable as a tiny container with just ansible-core.
  - All state transitions go through the API. The worker never touches
    the database directly.
  - SSH credentials live in a Docker secret mounted at
    /run/secrets/ssh_private_key. The worker is read-only on that path.
  - On any HTTP / Ansible failure the job is marked FAILED via
    /execution-result with the exception text in the log field.

Out of scope for V1:
  - Job locking / multi-worker coordination (the API currently does not
    expose a "claim" endpoint). For now run a single worker replica.
  - Real-time log streaming via SSE.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import httpx

API_URL = os.environ.get("NLV_API_URL", "http://app:8000/api/v1")
API_TOKEN = os.environ.get("NLV_API_TOKEN", "")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL_SECONDS", "10"))
SSH_KEY_PATH = os.environ.get("SSH_KEY_PATH", "/run/secrets/ssh_private_key")
ANSIBLE_TIMEOUT = int(os.environ.get("ANSIBLE_TIMEOUT_SECONDS", "1800"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("remediation-worker")


@dataclass
class Job:
    id: str
    asset_id: str
    cve_id: str | None
    status: str

    @classmethod
    def from_api(cls, payload: dict) -> "Job":
        return cls(
            id=payload["id"],
            asset_id=payload["asset_id"],
            cve_id=payload.get("cve_id"),
            status=payload["status"],
        )


class ApiClient:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        self._client = httpx.AsyncClient(base_url=base_url, headers=headers, timeout=30.0)

    async def list_jobs(self, status: str) -> list[Job]:
        resp = await self._client.get("/remediation/jobs", params={"job_status": status})
        resp.raise_for_status()
        return [Job.from_api(j) for j in resp.json()]

    async def get_asset(self, asset_id: str) -> dict | None:
        resp = await self._client.get(f"/assets/{asset_id}")
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        return resp.json()

    async def get_playbook(self, job_id: str) -> str:
        # The job detail endpoint exposes playbook_yaml.
        resp = await self._client.get(f"/remediation/jobs/{job_id}")
        resp.raise_for_status()
        body = resp.json()
        return body.get("playbook_yaml") or ""

    async def post_dry_run_result(self, job_id: str, stdout: str) -> None:
        resp = await self._client.post(
            f"/remediation/jobs/{job_id}/dry-run-result",
            json={"stdout": stdout},
        )
        resp.raise_for_status()

    async def post_execution_result(
        self, job_id: str, *, succeeded: bool, log: str, healthcheck_passed: bool
    ) -> None:
        resp = await self._client.post(
            f"/remediation/jobs/{job_id}/execution-result",
            json={"succeeded": succeeded, "log": log, "healthcheck_passed": healthcheck_passed},
        )
        resp.raise_for_status()

    async def aclose(self) -> None:
        await self._client.aclose()


def _build_inventory(asset: dict) -> str:
    """Build a single-host Ansible inventory file content."""
    ip = asset.get("ip") or asset.get("hostname") or "localhost"
    user = asset.get("ssh_user") or "ansible"
    port = asset.get("ssh_port") or 22
    return (
        "[target]\n"
        f"{ip} ansible_user={user} ansible_port={port} "
        f"ansible_ssh_private_key_file={SSH_KEY_PATH} "
        f"ansible_ssh_common_args='-o StrictHostKeyChecking=no'\n"
    )


def _run_ansible(playbook_path: Path, inventory_path: Path, *, check: bool) -> tuple[bool, str]:
    """Run ansible-playbook synchronously. Returns (success, stdout+stderr)."""
    cmd = [
        "ansible-playbook",
        "-i", str(inventory_path),
        str(playbook_path),
    ]
    if check:
        cmd.extend(["--check", "--diff"])
    log.info("running ansible: %s", " ".join(shlex.quote(c) for c in cmd))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=ANSIBLE_TIMEOUT,
        )
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        return proc.returncode == 0, out
    except subprocess.TimeoutExpired as exc:
        return False, f"ansible-playbook timed out after {ANSIBLE_TIMEOUT}s\n{exc}"
    except FileNotFoundError:
        return False, "ansible-playbook binary not found in PATH"


async def process_dry_run(api: ApiClient, job: Job) -> None:
    log.info("dry-run job=%s asset=%s", job.id, job.asset_id)
    asset = await api.get_asset(job.asset_id)
    if asset is None:
        log.error("asset not found for job %s", job.id)
        return
    playbook = await api.get_playbook(job.id)
    if not playbook:
        log.error("empty playbook for job %s", job.id)
        return

    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        pb_path = td / "playbook.yml"
        inv_path = td / "inventory.ini"
        pb_path.write_text(playbook)
        inv_path.write_text(_build_inventory(asset))
        ok, out = _run_ansible(pb_path, inv_path, check=True)

    try:
        await api.post_dry_run_result(job.id, out)
        log.info("dry-run result posted job=%s ok=%s", job.id, ok)
    except httpx.HTTPError as exc:
        log.error("failed to post dry-run result job=%s err=%s", job.id, exc)


async def process_execution(api: ApiClient, job: Job) -> None:
    log.info("execution job=%s asset=%s", job.id, job.asset_id)
    asset = await api.get_asset(job.asset_id)
    if asset is None:
        await api.post_execution_result(
            job.id, succeeded=False, log="asset not found", healthcheck_passed=False
        )
        return
    playbook = await api.get_playbook(job.id)

    with tempfile.TemporaryDirectory() as tmpdir:
        td = Path(tmpdir)
        pb_path = td / "playbook.yml"
        inv_path = td / "inventory.ini"
        pb_path.write_text(playbook)
        inv_path.write_text(_build_inventory(asset))
        ok, out = _run_ansible(pb_path, inv_path, check=False)

    # V1 healthcheck: success of ansible run = healthcheck pass.
    # V2: parse `healthcheck_cmd` from job and run it via SSH.
    try:
        await api.post_execution_result(
            job.id, succeeded=ok, log=out[:50_000], healthcheck_passed=ok
        )
        log.info("execution result posted job=%s ok=%s", job.id, ok)
    except httpx.HTTPError as exc:
        log.error("failed to post execution result job=%s err=%s", job.id, exc)


async def main() -> None:
    if not API_TOKEN:
        log.warning("NLV_API_TOKEN not set — API calls will be unauthenticated")
    log.info("worker starting api=%s poll=%ss", API_URL, POLL_INTERVAL)
    api = ApiClient(API_URL, API_TOKEN)
    try:
        while True:
            try:
                dry_jobs = await api.list_jobs("dry_run_pending")
                for j in dry_jobs:
                    await process_dry_run(api, j)

                exec_jobs = await api.list_jobs("approved")
                for j in exec_jobs:
                    await process_execution(api, j)
            except httpx.HTTPError as exc:
                log.error("API error: %s", exc)
            except Exception:
                log.exception("worker loop error")
            await asyncio.sleep(POLL_INTERVAL)
    finally:
        await api.aclose()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
