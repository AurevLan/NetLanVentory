"""Docker daemon security audit router (docker-bench-security style).

Connects via SSH and audits:
  - Docker daemon configuration
  - Container runtime security
  - Image security practices
  - Network configuration
  - Logging configuration
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Annotated

import asyncssh
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import actor_from_user, get_current_active_user, get_db
from netlanventory.core.audit import log_action
from netlanventory.core.database import get_session_factory
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.docker_bench_report import DockerBenchReport

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/docker-bench", tags=["docker-bench"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]

_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(2)
    return _semaphore


# ── Schemas ───────────────────────────────────────────────────────────────────


class DockerBenchReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    asset_id: uuid.UUID
    status: str
    docker_version: str | None = None
    score: float | None = None
    pass_count: int
    warn_count: int
    info_count: int
    note_count: int
    findings: dict | None = None
    error_msg: str | None = None
    created_at: datetime
    updated_at: datetime


class DockerBenchTriggerOut(BaseModel):
    report_id: uuid.UUID
    message: str


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", response_model=DockerBenchTriggerOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("3/minute")
async def trigger_docker_bench(
    request: Request,
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DbDep,
    current_user: UserDep,
) -> DockerBenchTriggerOut:
    asset = (
        await db.execute(
            select(Asset).options(selectinload(Asset.ssh_profile)).where(Asset.id == asset_id)
        )
    ).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not asset.ip:
        raise HTTPException(status_code=400, detail="Asset has no IP address")
    if not asset.has_ssh_credentials:
        raise HTTPException(status_code=400, detail="No SSH credentials configured for this asset")

    report = DockerBenchReport(asset_id=asset_id, status="pending")
    db.add(report)
    await db.flush()

    actor = actor_from_user(current_user)
    await log_action(db, user=actor, action="docker_bench.trigger", resource_type="asset", resource_id=str(asset_id))
    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(_run_docker_bench, report_id=report.id, asset_id=asset_id)
    return DockerBenchTriggerOut(report_id=report.id, message="Docker security audit started")


@router.get("", response_model=list[DockerBenchReportOut])
async def list_docker_bench_reports(asset_id: uuid.UUID, db: DbDep, _user: UserDep) -> list[DockerBenchReport]:
    result = await db.execute(
        select(DockerBenchReport)
        .where(DockerBenchReport.asset_id == asset_id)
        .order_by(DockerBenchReport.created_at.desc())
        .limit(50)
    )
    return list(result.scalars().all())


@router.get("/{report_id}", response_model=DockerBenchReportOut)
async def get_docker_bench_report(asset_id: uuid.UUID, report_id: uuid.UUID, db: DbDep, _user: UserDep) -> DockerBenchReport:
    result = await db.execute(
        select(DockerBenchReport).where(DockerBenchReport.id == report_id, DockerBenchReport.asset_id == asset_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Docker bench report not found")
    return report


# ── Background task ───────────────────────────────────────────────────────────


async def _run_cmd(conn: asyncssh.SSHClientConnection, cmd: str, timeout: int = 60) -> str:
    try:
        result = await asyncio.wait_for(conn.run(cmd, check=False), timeout=timeout)
        return (result.stdout or "").strip()
    except Exception:
        return ""


async def _run_docker_bench(report_id: uuid.UUID, asset_id: uuid.UUID) -> None:
    from netlanventory.api.routers.ssh_scan import _build_ssh_kwargs

    factory = get_session_factory()

    async with _get_semaphore():
        async with factory() as session:
            report = (await session.execute(select(DockerBenchReport).where(DockerBenchReport.id == report_id))).scalar_one_or_none()
            asset = (await session.execute(
                select(Asset).options(selectinload(Asset.ssh_profile)).where(Asset.id == asset_id)
            )).scalar_one_or_none()

            if not report or not asset:
                return

            report.status = "running"
            await session.commit()

        try:
            ssh_kwargs = _build_ssh_kwargs(asset)
            host = str(asset.ip)
            port = asset.ssh_port or (asset.ssh_profile.ssh_port if asset.ssh_profile else None) or 22
            user = asset.ssh_user or (asset.ssh_profile.ssh_user if asset.ssh_profile else None) or "root"

            async with asyncssh.connect(host, port=port, username=user, known_hosts=None, **ssh_kwargs) as conn:
                # Check if Docker is available
                docker_version = await _run_cmd(conn, "docker version --format '{{.Server.Version}}' 2>/dev/null", timeout=15)
                if not docker_version:
                    async with factory() as session:
                        report = (await session.execute(select(DockerBenchReport).where(DockerBenchReport.id == report_id))).scalar_one()
                        report.status = "completed"
                        report.findings = {"docker_available": False, "sections": {}, "risk_findings": []}
                        await session.commit()
                    return

                # Collect Docker security data in parallel
                (
                    docker_info,
                    daemon_json,
                    docker_sock_perms,
                    containers_raw,
                    images_raw,
                    network_raw,
                    docker_group,
                    user_ns,
                    content_trust,
                    live_restore,
                    logging_driver,
                    ulimits,
                    icc,
                    privileged_containers,
                    pid_host_containers,
                    net_host_containers,
                    writable_containers,
                    no_healthcheck,
                ) = await asyncio.gather(
                    _run_cmd(conn, "docker info --format json 2>/dev/null", timeout=30),
                    _run_cmd(conn, "cat /etc/docker/daemon.json 2>/dev/null", timeout=10),
                    _run_cmd(conn, "stat -c '%a %U %G' /var/run/docker.sock 2>/dev/null", timeout=10),
                    _run_cmd(conn, "docker ps --format '{{.ID}} {{.Names}} {{.Image}} {{.Status}}' 2>/dev/null", timeout=15),
                    _run_cmd(conn, "docker images --format '{{.Repository}}:{{.Tag}} {{.Size}}' 2>/dev/null | head -50", timeout=15),
                    _run_cmd(conn, "docker network ls --format '{{.Name}} {{.Driver}}' 2>/dev/null", timeout=10),
                    _run_cmd(conn, "getent group docker 2>/dev/null", timeout=10),
                    _run_cmd(conn, "docker info --format '{{.SecurityOptions}}' 2>/dev/null", timeout=10),
                    _run_cmd(conn, "echo $DOCKER_CONTENT_TRUST", timeout=5),
                    _run_cmd(conn, "docker info --format '{{.LiveRestoreEnabled}}' 2>/dev/null", timeout=10),
                    _run_cmd(conn, "docker info --format '{{.LoggingDriver}}' 2>/dev/null", timeout=10),
                    _run_cmd(conn, "docker info --format '{{.DefaultUlimits}}' 2>/dev/null", timeout=10),
                    _run_cmd(conn, "docker network inspect bridge --format '{{(index .Options \"com.docker.network.bridge.enable_icc\")}}' 2>/dev/null", timeout=10),
                    _run_cmd(conn, "docker ps --quiet --filter 'label=com.docker.compose.project' 2>/dev/null | xargs -r docker inspect --format '{{.Name}} {{.HostConfig.Privileged}}' 2>/dev/null | grep true", timeout=15),
                    _run_cmd(conn, "docker ps -q 2>/dev/null | xargs -r docker inspect --format '{{.Name}} {{.HostConfig.PidMode}}' 2>/dev/null | grep host", timeout=15),
                    _run_cmd(conn, "docker ps -q 2>/dev/null | xargs -r docker inspect --format '{{.Name}} {{.HostConfig.NetworkMode}}' 2>/dev/null | grep host", timeout=15),
                    _run_cmd(conn, "docker ps -q 2>/dev/null | xargs -r docker inspect --format '{{.Name}} {{.HostConfig.ReadonlyRootfs}}' 2>/dev/null | grep false", timeout=15),
                    _run_cmd(conn, "docker ps -q 2>/dev/null | xargs -r docker inspect --format '{{.Name}} {{if .Config.Healthcheck}}OK{{else}}MISSING{{end}}' 2>/dev/null | grep MISSING", timeout=15),
                )

            # Parse results
            containers = [l for l in containers_raw.splitlines() if l.strip()] if containers_raw else []
            images = [l for l in images_raw.splitlines() if l.strip()] if images_raw else []

            # Security checks
            sections: dict[str, dict[str, list[str]]] = {
                "host_configuration": {"pass": [], "warn": [], "info": []},
                "docker_daemon_configuration": {"pass": [], "warn": [], "info": []},
                "container_runtime": {"pass": [], "warn": [], "info": []},
                "container_images": {"pass": [], "warn": [], "info": []},
                "docker_security_operations": {"pass": [], "warn": [], "info": []},
            }

            risk_findings: list[dict] = []

            # 1. Host configuration
            sock_parts = docker_sock_perms.split() if docker_sock_perms else []
            if sock_parts:
                perms = sock_parts[0]
                owner = sock_parts[1] if len(sock_parts) > 1 else ""
                if perms != "660" and perms != "600":
                    sections["host_configuration"]["warn"].append(f"1.1 - Docker socket permissions too permissive: {perms}")
                    risk_findings.append({"severity": "high", "finding": f"Docker socket permissions: {perms}", "cis": "1.1"})
                else:
                    sections["host_configuration"]["pass"].append("1.1 - Docker socket permissions are restrictive")

            docker_members = docker_group.split(":")[-1] if docker_group else ""
            if docker_members:
                members = [m.strip() for m in docker_members.split(",") if m.strip()]
                if len(members) > 3:
                    sections["host_configuration"]["warn"].append(f"1.2 - {len(members)} users in docker group: {', '.join(members)}")
                    risk_findings.append({"severity": "medium", "finding": f"{len(members)} users in docker group", "cis": "1.2"})
                else:
                    sections["host_configuration"]["pass"].append(f"1.2 - Docker group has {len(members)} member(s)")

            # 2. Daemon configuration
            daemon_config = {}
            if daemon_json:
                try:
                    daemon_config = json.loads(daemon_json)
                except (json.JSONDecodeError, ValueError):
                    pass

            if "userns-remap" not in daemon_config and "userns" not in (user_ns or "").lower():
                sections["docker_daemon_configuration"]["warn"].append("2.8 - User namespace remapping not enabled")
                risk_findings.append({"severity": "high", "finding": "User namespace not enabled", "cis": "2.8"})
            else:
                sections["docker_daemon_configuration"]["pass"].append("2.8 - User namespace remapping enabled")

            if content_trust != "1":
                sections["docker_daemon_configuration"]["warn"].append("2.11 - DOCKER_CONTENT_TRUST not enabled")
            else:
                sections["docker_daemon_configuration"]["pass"].append("2.11 - Content trust enabled")

            if live_restore != "true":
                sections["docker_daemon_configuration"]["warn"].append("2.14 - Live restore not enabled")
            else:
                sections["docker_daemon_configuration"]["pass"].append("2.14 - Live restore enabled")

            if icc == "true" or not icc:
                sections["docker_daemon_configuration"]["warn"].append("2.1 - Inter-container communication not restricted")
                risk_findings.append({"severity": "medium", "finding": "ICC enabled on bridge network", "cis": "2.1"})
            else:
                sections["docker_daemon_configuration"]["pass"].append("2.1 - ICC restricted on bridge")

            if logging_driver not in ("json-file", "journald", "syslog", "fluentd", "splunk", "gelf"):
                sections["docker_daemon_configuration"]["warn"].append(f"2.12 - Unusual logging driver: {logging_driver}")
            else:
                sections["docker_daemon_configuration"]["pass"].append(f"2.12 - Logging driver: {logging_driver}")

            # 3. Container runtime
            if privileged_containers:
                priv_list = [l.strip() for l in privileged_containers.splitlines() if l.strip()]
                sections["container_runtime"]["warn"].append(f"5.4 - {len(priv_list)} privileged containers running")
                risk_findings.append({"severity": "critical", "finding": f"{len(priv_list)} privileged containers", "cis": "5.4"})
            else:
                sections["container_runtime"]["pass"].append("5.4 - No privileged containers running")

            if pid_host_containers:
                sections["container_runtime"]["warn"].append("5.15 - Containers sharing host PID namespace")
                risk_findings.append({"severity": "high", "finding": "Containers with host PID namespace", "cis": "5.15"})
            else:
                sections["container_runtime"]["pass"].append("5.15 - No containers share host PID namespace")

            if net_host_containers:
                sections["container_runtime"]["warn"].append("5.9 - Containers sharing host network namespace")
                risk_findings.append({"severity": "high", "finding": "Containers with host network mode", "cis": "5.9"})
            else:
                sections["container_runtime"]["pass"].append("5.9 - No containers share host network")

            # Score calculation
            total_checks = sum(len(s["pass"]) + len(s["warn"]) for s in sections.values())
            total_pass = sum(len(s["pass"]) for s in sections.values())
            total_warn = sum(len(s["warn"]) for s in sections.values())
            total_info = sum(len(s["info"]) for s in sections.values())
            score = round((total_pass / max(total_checks, 1)) * 100, 1)

            findings = {
                "docker_available": True,
                "docker_version": docker_version,
                "sections": sections,
                "risk_findings": risk_findings,
                "containers_running": len(containers),
                "images_count": len(images),
                "daemon_config": daemon_config,
            }

            async with factory() as session:
                report = (await session.execute(select(DockerBenchReport).where(DockerBenchReport.id == report_id))).scalar_one()
                report.status = "completed"
                report.docker_version = docker_version
                report.score = score
                report.pass_count = total_pass
                report.warn_count = total_warn
                report.info_count = total_info
                report.findings = findings
                await session.commit()

        except Exception as exc:
            logger.error("Docker bench audit failed", report_id=str(report_id), error=str(exc), exc_info=True)
            async with factory() as session:
                report = (await session.execute(select(DockerBenchReport).where(DockerBenchReport.id == report_id))).scalar_one_or_none()
                if report:
                    report.status = "failed"
                    report.error_msg = str(exc)[:500]
                    await session.commit()
