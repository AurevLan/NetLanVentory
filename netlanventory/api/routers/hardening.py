"""Hardening scan router — Lynis system audit + CIS-style checks via SSH.

Flow for POST (trigger):
  1. Validate asset has SSH credentials
  2. Create HardeningReport (status=pending)
  3. Return 202 immediately
  4. Background task:
     a. SSH into asset
     b. Check if Lynis is available; run 'lynis audit system' if present
     c. Parse Lynis .dat report (hardening index, warnings, suggestions)
     d. Run CIS-style checks (world-writable files, SUID binaries, SSH config,
        password policy, crontab entries)
     e. Persist findings to HardeningReport
"""

from __future__ import annotations

import asyncio
import re
import uuid
from datetime import datetime, timezone
from typing import Annotated

import asyncssh
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import actor_from_user, get_current_active_user, get_db
from netlanventory.core.audit import log_action
from netlanventory.core.database import get_session_factory
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.hardening_report import HardeningReport

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/hardening-scan", tags=["hardening"])
lynis_router = APIRouter(prefix="/assets/{asset_id}/lynis-scan", tags=["lynis"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]

# At most 2 simultaneous SSH hardening scans
_hardening_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    global _hardening_semaphore
    if _hardening_semaphore is None:
        _hardening_semaphore = asyncio.Semaphore(2)
    return _hardening_semaphore


# ── Schemas ───────────────────────────────────────────────────────────────────

class HardeningReportOut(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    asset_id: uuid.UUID
    status: str
    scan_type: str = "full"
    lynis_index: int | None = None
    warnings_count: int = 0
    suggestions_count: int = 0
    findings: dict | None = None
    error_msg: str | None = None
    created_at: datetime
    updated_at: datetime


class HardeningTriggerOut(BaseModel):
    report_id: uuid.UUID
    message: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("", response_model=HardeningTriggerOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
async def trigger_hardening_scan(
    request: Request,
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DbDep,
    current_user: UserDep,
) -> HardeningTriggerOut:
    """Launch a system hardening audit (Lynis + CIS checks) against an asset via SSH."""
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id).options(selectinload(Asset.ssh_profile))
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not asset.ip:
        raise HTTPException(status_code=400, detail="Asset has no IP address")
    if not asset.has_ssh_credentials:
        raise HTTPException(
            status_code=400,
            detail="No SSH credentials configured. Add a password or private key, or link an SSH profile.",
        )

    report = HardeningReport(asset_id=asset_id, status="pending", scan_type="full")
    db.add(report)
    await db.flush()

    actor = actor_from_user(current_user)
    await log_action(
        db,
        user=actor,
        action="hardening_scan.trigger",
        resource_type="asset",
        resource_id=str(asset_id),
    )
    await db.commit()

    background_tasks.add_task(_run_hardening_scan, report_id=report.id, asset_id=asset_id)
    logger.info("Hardening scan queued", report_id=str(report.id), asset_id=str(asset_id))

    return HardeningTriggerOut(
        report_id=report.id,
        message="Hardening scan queued. Poll GET /hardening-scan for results.",
    )


@router.get("", response_model=list[HardeningReportOut])
async def list_hardening_reports(
    asset_id: uuid.UUID,
    db: DbDep,
    _user: UserDep,
) -> list[HardeningReport]:
    """List all hardening scan reports for an asset (newest first)."""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Asset not found")

    reports = await db.execute(
        select(HardeningReport)
        .where(
            HardeningReport.asset_id == asset_id,
            HardeningReport.scan_type == "full",
        )
        .order_by(HardeningReport.created_at.desc())
        .limit(50)
    )
    return list(reports.scalars().all())


@router.get("/{report_id}", response_model=HardeningReportOut)
async def get_hardening_report(
    asset_id: uuid.UUID,
    report_id: uuid.UUID,
    db: DbDep,
    _user: UserDep,
) -> HardeningReport:
    """Get a specific hardening scan report."""
    result = await db.execute(
        select(HardeningReport).where(
            HardeningReport.id == report_id,
            HardeningReport.asset_id == asset_id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Hardening report not found")
    return report


# ── Lynis-only endpoints ──────────────────────────────────────────────────────

@lynis_router.post("", response_model=HardeningTriggerOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
async def trigger_lynis_scan(
    request: Request,
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DbDep,
    current_user: UserDep,
) -> HardeningTriggerOut:
    """Run a Lynis-only system audit via SSH (no CIS checks).

    Lynis is deployed agentlessly if not installed on the target.
    Returns immediately (202) — poll GET /lynis-scan for results.
    """
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id).options(selectinload(Asset.ssh_profile))
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if not asset.ip:
        raise HTTPException(status_code=400, detail="Asset has no IP address")
    if not asset.has_ssh_credentials:
        raise HTTPException(
            status_code=400,
            detail="No SSH credentials configured. Add a password or private key, or link an SSH profile.",
        )

    report = HardeningReport(asset_id=asset_id, status="pending", scan_type="lynis")
    db.add(report)
    await db.flush()

    actor = actor_from_user(current_user)
    await log_action(
        db,
        user=actor,
        action="lynis_scan.trigger",
        resource_type="asset",
        resource_id=str(asset_id),
    )
    await db.commit()

    background_tasks.add_task(_run_lynis_scan, report_id=report.id, asset_id=asset_id)
    logger.info("Lynis scan queued", report_id=str(report.id), asset_id=str(asset_id))

    return HardeningTriggerOut(
        report_id=report.id,
        message="Lynis scan queued. Poll GET /lynis-scan for results.",
    )


@lynis_router.get("", response_model=list[HardeningReportOut])
async def list_lynis_reports(
    asset_id: uuid.UUID,
    db: DbDep,
    _user: UserDep,
) -> list[HardeningReport]:
    """List all Lynis scan reports for an asset (newest first)."""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Asset not found")

    reports = await db.execute(
        select(HardeningReport)
        .where(
            HardeningReport.asset_id == asset_id,
            HardeningReport.scan_type == "lynis",
        )
        .order_by(HardeningReport.created_at.desc())
        .limit(50)
    )
    return list(reports.scalars().all())


@lynis_router.get("/{report_id}", response_model=HardeningReportOut)
async def get_lynis_report(
    asset_id: uuid.UUID,
    report_id: uuid.UUID,
    db: DbDep,
    _user: UserDep,
) -> HardeningReport:
    """Get a specific Lynis scan report."""
    result = await db.execute(
        select(HardeningReport).where(
            HardeningReport.id == report_id,
            HardeningReport.asset_id == asset_id,
            HardeningReport.scan_type == "lynis",
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Lynis report not found")
    return report


# ── Background task — Lynis only ──────────────────────────────────────────────

async def _run_lynis_scan(report_id: uuid.UUID, asset_id: uuid.UUID) -> None:
    """SSH into the asset, run Lynis only, persist results."""
    from netlanventory.api.routers.ssh_scan import _build_ssh_kwargs

    factory = get_session_factory()

    async with _get_semaphore():
        async with factory() as session:
            report = (
                await session.execute(
                    select(HardeningReport).where(HardeningReport.id == report_id)
                )
            ).scalar_one_or_none()
            if not report:
                return

            asset = (
                await session.execute(
                    select(Asset)
                    .where(Asset.id == asset_id)
                    .options(selectinload(Asset.ssh_profile))
                )
            ).scalar_one_or_none()
            if not asset:
                report.status = "failed"
                report.error_msg = "Asset not found"
                await session.commit()
                return

            report.status = "running"
            await session.flush()

            try:
                ssh_kwargs = _build_ssh_kwargs(asset)
                host = asset.ip
                port = (
                    asset.ssh_port
                    or (asset.ssh_profile.ssh_port if asset.ssh_profile else None)
                    or 22
                )
                user = (
                    asset.ssh_user
                    or (asset.ssh_profile.ssh_user if asset.ssh_profile else None)
                    or "root"
                )

                async with asyncssh.connect(
                    host,
                    port=port,
                    username=user,
                    known_hosts=None,
                    **ssh_kwargs,
                ) as conn:
                    # Lynis auto-deploys agentlessly if not installed
                    lynis_data = await _run_lynis(conn, report_id)

                report.lynis_index = lynis_data.get("hardening_index")
                report.warnings_count = len(lynis_data.get("warnings", []))
                report.suggestions_count = len(lynis_data.get("suggestions", []))
                report.findings = lynis_data
                report.status = "completed"

            except (asyncssh.DisconnectError, asyncssh.PermissionDenied, OSError) as exc:
                logger.warning("Lynis scan SSH error", asset_id=str(asset_id), error=str(exc))
                report.status = "failed"
                report.error_msg = str(exc)
            except Exception as exc:
                logger.error(
                    "Lynis scan unexpected error",
                    asset_id=str(asset_id),
                    error=str(exc),
                    exc_info=True,
                )
                report.status = "failed"
                report.error_msg = f"Unexpected error: {exc}"

            await session.commit()
    logger.info("Lynis scan finished", report_id=str(report_id))


# ── Background task ───────────────────────────────────────────────────────────

async def _run_hardening_scan(report_id: uuid.UUID, asset_id: uuid.UUID) -> None:
    """SSH into the asset, run Lynis and CIS checks, persist results."""
    from netlanventory.api.routers.ssh_scan import _build_ssh_kwargs

    factory = get_session_factory()

    async with _get_semaphore():
        async with factory() as session:
            report = (
                await session.execute(select(HardeningReport).where(HardeningReport.id == report_id))
            ).scalar_one_or_none()
            if not report:
                return

            asset = (
                await session.execute(
                    select(Asset).where(Asset.id == asset_id).options(selectinload(Asset.ssh_profile))
                )
            ).scalar_one_or_none()
            if not asset:
                report.status = "failed"
                report.error_msg = "Asset not found"
                await session.commit()
                return

            report.status = "running"
            await session.flush()

            try:
                ssh_kwargs = _build_ssh_kwargs(asset)
                host = asset.ip
                port = asset.ssh_port or (asset.ssh_profile.ssh_port if asset.ssh_profile else None) or 22
                user = asset.ssh_user or (asset.ssh_profile.ssh_user if asset.ssh_profile else None) or "root"

                async with asyncssh.connect(
                    host,
                    port=port,
                    username=user,
                    known_hosts=None,
                    **ssh_kwargs,
                ) as conn:
                    findings = await _collect_findings(conn, report_id)

                report.lynis_index = findings.get("lynis_index")
                report.warnings_count = len(findings.get("warnings", []))
                report.suggestions_count = len(findings.get("suggestions", []))
                report.findings = findings
                report.status = "completed"

                # CIS Benchmark mapping
                try:
                    from netlanventory.core.cis_mapper import map_hardening_to_cis
                    cis_result = map_hardening_to_cis(
                        findings.get("cis_checks", {}),
                        findings.get("lynis_index"),
                    )
                    report.cis_score = cis_result.get("score")
                    report.cis_level = cis_result.get("level")
                    report.cis_findings = cis_result.get("findings", [])
                except Exception as cis_exc:
                    logger.debug("CIS mapping failed", error=str(cis_exc))

            except (asyncssh.DisconnectError, asyncssh.PermissionDenied, OSError) as exc:
                logger.warning("Hardening scan SSH error", asset_id=str(asset_id), error=str(exc))
                report.status = "failed"
                report.error_msg = str(exc)
            except Exception as exc:
                logger.error("Hardening scan unexpected error", asset_id=str(asset_id), error=str(exc), exc_info=True)
                report.status = "failed"
                report.error_msg = f"Unexpected error: {exc}"

            await session.commit()


async def _run_cmd(conn: asyncssh.SSHClientConnection, cmd: str, timeout: int = 60) -> str:
    """Run a command and return stdout (empty string on error)."""
    try:
        result = await asyncio.wait_for(conn.run(cmd, check=False), timeout=timeout)
        return (result.stdout or "").strip()
    except Exception as exc:
        logger.debug("ssh_cmd_failed", cmd=cmd[:80], error=str(exc))
        return ""


async def _collect_findings(
    conn: asyncssh.SSHClientConnection, report_id: uuid.UUID
) -> dict:
    """Run all checks and return the findings dict."""
    findings: dict = {}

    # ── Lynis (agentless — auto-deploys if not installed) ──────────────────
    findings["lynis"] = await _run_lynis(conn, report_id)
    findings["lynis_available"] = findings["lynis"].get("available", True)
    findings["lynis_index"] = findings["lynis"].get("hardening_index")
        findings["warnings"] = findings["lynis"].get("warnings", [])
        findings["suggestions"] = findings["lynis"].get("suggestions", [])
    else:
        findings["lynis_index"] = None
        findings["warnings"] = []
        findings["suggestions"] = []
        findings["lynis"] = {"available": False}
        logger.info("Lynis not found on asset — skipping Lynis checks")

    # ── CIS-style checks — run all in parallel ───────────────────────────────
    cis: dict = {}

    (
        ww_out,
        suid_out,
        ssh_cfg_out,
        login_defs_out,
        cron_out,
        auto_updates_out,
        firewall_out,
    ) = await asyncio.gather(
        _run_cmd(
            conn,
            "find / -xdev -perm -0002 -type f ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null | head -50",
            timeout=120,
        ),
        _run_cmd(conn, "find / -xdev -perm -4000 -type f 2>/dev/null | head -50", timeout=120),
        _run_cmd(
            conn,
            r"grep -E '^(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|X11Forwarding|Protocol)' "
            r"/etc/ssh/sshd_config 2>/dev/null",
        ),
        _run_cmd(
            conn,
            r"grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|PASS_MIN_LEN)' "
            r"/etc/login.defs 2>/dev/null",
        ),
        _run_cmd(
            conn,
            "{ crontab -l 2>/dev/null; echo '---/etc/crontab---'; cat /etc/crontab 2>/dev/null; "
            "echo '---/etc/cron.d/---'; ls /etc/cron.d/ 2>/dev/null; }",
        ),
        _run_cmd(
            conn,
            "dpkg -l unattended-upgrades 2>/dev/null | grep '^ii' | head -1 || "
            "rpm -q dnf-automatic 2>/dev/null || echo 'not_found'",
        ),
        _run_cmd(
            conn,
            "ufw status 2>/dev/null || firewall-cmd --state 2>/dev/null || iptables -L -n --line-numbers 2>/dev/null | head -20",
        ),
    )

    cis["world_writable_files"] = [f for f in ww_out.splitlines() if f]
    cis["suid_binaries"] = [f for f in suid_out.splitlines() if f]

    ssh_cfg: dict[str, str] = {}
    for line in ssh_cfg_out.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            ssh_cfg[parts[0]] = parts[1]
    cis["ssh_config"] = ssh_cfg

    login_defs: dict[str, str] = {}
    for line in login_defs_out.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            login_defs[parts[0]] = parts[1].strip()
    cis["password_policy"] = login_defs

    cis["cron_entries"] = cron_out
    cis["auto_updates"] = auto_updates_out.strip()
    cis["firewall_status"] = firewall_out

    findings["cis_checks"] = cis

    # ── Risk summary ─────────────────────────────────────────────────────────
    findings["risk_indicators"] = _compute_risk_indicators(cis, ssh_cfg, login_defs)

    return findings


_LYNIS_GIT_TARBALL = "https://github.com/CISOfy/lynis/archive/refs/heads/master.tar.gz"


async def _run_lynis(conn: asyncssh.SSHClientConnection, report_id: uuid.UUID) -> dict:
    """Run Lynis on the remote asset agentlessly — no installation required.

    Strategy (in order):
      1. Use system Lynis if already installed
      2. Download Lynis tarball to /tmp, extract, run, clean up

    This ensures Lynis runs even on servers where nothing is pre-installed.
    """
    report_file = f"/tmp/netlanventory-lynis-{report_id}.dat"
    tmp_dir = f"/tmp/netlanventory-lynis-{report_id}"

    # Detect whether we can run Lynis as root or need sudo
    whoami = await _run_cmd(conn, "whoami")
    sudo_prefix = "" if whoami == "root" else "sudo "

    # 1. Check if Lynis is already installed
    lynis_path = await _run_cmd(conn, "which lynis 2>/dev/null || command -v lynis 2>/dev/null")

    if not lynis_path:
        # 2. Agentless deploy: download + extract to /tmp
        logger.info("Lynis not found — deploying agentless copy to /tmp", report_id=str(report_id))
        deploy_cmd = (
            f"mkdir -p {tmp_dir} && "
            f"curl -sL '{_LYNIS_GIT_TARBALL}' 2>/dev/null | tar xz -C {tmp_dir} --strip-components=1 2>/dev/null"
        )
        deploy_out = await _run_cmd(conn, deploy_cmd, timeout=60)
        # Verify deployment
        check = await _run_cmd(conn, f"test -f {tmp_dir}/lynis && echo OK")
        if check != "OK":
            # Fallback: try wget
            deploy_cmd2 = (
                f"rm -rf {tmp_dir} && mkdir -p {tmp_dir} && "
                f"wget -qO- '{_LYNIS_GIT_TARBALL}' 2>/dev/null | tar xz -C {tmp_dir} --strip-components=1 2>/dev/null"
            )
            await _run_cmd(conn, deploy_cmd2, timeout=60)
            check2 = await _run_cmd(conn, f"test -f {tmp_dir}/lynis && echo OK")
            if check2 != "OK":
                return {
                    "available": False,
                    "error": "Could not deploy Lynis agentlessly (neither curl nor wget available on target)",
                }

        lynis_path = f"{tmp_dir}/lynis"

    lynis_cmd = (
        f"{sudo_prefix}{lynis_path} audit system --quiet --no-colors "
        f"--report-file {report_file} 2>/dev/null"
    )

    exit_code_raw = await _run_cmd(
        conn,
        f"{lynis_cmd}; echo \"LYNIS_EXIT:$?\"",
        timeout=300,
    )
    exit_code = 0
    for line in exit_code_raw.splitlines():
        if line.startswith("LYNIS_EXIT:"):
            try:
                exit_code = int(line.split(":")[1])
            except ValueError:
                pass

    # Retrieve and clean up
    dat_content = await _run_cmd(conn, f"cat {report_file} 2>/dev/null")
    await _run_cmd(conn, f"rm -f {report_file}")
    await _run_cmd(conn, f"rm -rf {tmp_dir}")

    if not dat_content:
        return {
            "available": True,
            "error": "Lynis ran but produced no report (permission issue or crash)",
            "exit_code": exit_code,
        }

    return _parse_lynis_dat(dat_content)


def _parse_lynis_dat(content: str) -> dict:
    """Parse a Lynis .dat report file into a rich structured dict.

    Lynis .dat format — each line is one of:
      key=value          →  scalar field
      key[]=value        →  array field (multiple lines with same key)

    Warning / suggestion format (pipe-separated):
      TEST_ID | description | solution | url
    """
    scalars: dict[str, str] = {}
    arrays: dict[str, list[str]] = {}

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Array field:  key[]=value
        m = re.match(r"^([a-zA-Z0-9_]+)\[\]=(.*)", line)
        if m:
            key, val = m.group(1), m.group(2)
            arrays.setdefault(key, []).append(val)
            continue

        # Scalar field:  key=value
        m = re.match(r"^([a-zA-Z0-9_]+)=(.*)", line)
        if m:
            scalars[m.group(1)] = m.group(2)

    # ── Scalar fields ─────────────────────────────────────────────────────────
    result: dict = {"available": True}

    hardening_index = scalars.get("hardening_index")
    result["hardening_index"] = int(hardening_index) if hardening_index and hardening_index.isdigit() else None

    result["lynis_version"] = scalars.get("lynis_version", "unknown")

    result["os"] = {
        "name":    scalars.get("os", ""),
        "version": scalars.get("os_version", ""),
        "full":    scalars.get("os_full_name", ""),
        "arch":    scalars.get("hardware_platform", ""),
        "kernel":  scalars.get("linux_kernel_version", ""),
    }

    result["compiler_installed"]   = scalars.get("compiler_installed", "")
    result["memory_size"]          = scalars.get("memory_size", "")
    result["uptime_hours"]         = scalars.get("uptime_hours", "")
    result["boot_loader"]          = scalars.get("boot_loader", "")
    result["firewall_active"]      = scalars.get("firewall_active", "")
    result["malware_scanner"]      = scalars.get("malware_scanner", "")

    # ── Structured warnings ───────────────────────────────────────────────────
    result["warnings"] = [
        _parse_lynis_finding(w) for w in arrays.get("warning", [])
    ]

    # ── Structured suggestions ────────────────────────────────────────────────
    result["suggestions"] = [
        _parse_lynis_finding(s) for s in arrays.get("suggestion", [])
    ]

    # ── Tests performed / skipped ─────────────────────────────────────────────
    result["tests_performed"]     = arrays.get("test_performed", [])
    result["tests_skipped"]       = arrays.get("test_skipped", [])
    result["tests_not_performed"] = arrays.get("test_not_performed", [])

    # ── Categories covered ────────────────────────────────────────────────────
    result["categories"] = sorted(set(arrays.get("test_category", [])))

    # ── Installed security tools detected by Lynis ────────────────────────────
    result["security_tools"] = {
        "malware_scanner":    arrays.get("malware_scanner", []),
        "file_integrity":     arrays.get("file_integrity_tool", []),
        "intrusion_detection":arrays.get("ids_tool", []),
    }

    # ── Plugin results ────────────────────────────────────────────────────────
    result["plugins_enabled"] = arrays.get("plugin_enabled_phase", [])

    # ── Compliance results (if Lynis ran compliance tests) ────────────────────
    compliance_raw = arrays.get("compliance", [])
    result["compliance"] = _parse_lynis_compliance(compliance_raw)

    # ── Users detected ────────────────────────────────────────────────────────
    result["users_with_uid0"] = [
        u for u in arrays.get("uid_0_accounts", []) if u not in ("root",)
    ]

    # ── Network details ───────────────────────────────────────────────────────
    result["network"] = {
        "interfaces": arrays.get("network_interface", []),
        "listening_services": len(arrays.get("network_listen_port", [])),
    }

    # ── Summary counters ──────────────────────────────────────────────────────
    result["summary"] = {
        "warnings_count":    len(result["warnings"]),
        "suggestions_count": len(result["suggestions"]),
        "tests_performed":   len(result["tests_performed"]),
        "tests_skipped":     len(result["tests_skipped"]),
    }

    return result


def _parse_lynis_finding(raw: str) -> dict:
    """Parse a Lynis warning or suggestion pipe-separated string.

    Format: TEST_ID|description|solution|url
    Some fields may be empty.
    """
    parts = raw.split("|")
    return {
        "test_id":     parts[0].strip() if len(parts) > 0 else "",
        "description": parts[1].strip() if len(parts) > 1 else raw,
        "solution":    parts[2].strip() if len(parts) > 2 else "",
        "url":         parts[3].strip() if len(parts) > 3 else "",
    }


def _parse_lynis_compliance(raw: list[str]) -> dict:
    """Parse Lynis compliance[] lines into a per-framework dict.

    Format: framework|status   e.g.  iso27001|partial
    """
    compliance: dict[str, str] = {}
    for entry in raw:
        parts = entry.split("|")
        if len(parts) >= 2:
            compliance[parts[0].strip()] = parts[1].strip()
    return compliance


def _compute_risk_indicators(
    cis: dict, ssh_cfg: dict, login_defs: dict
) -> list[dict]:
    """Flag specific high-risk conditions as structured indicators."""
    indicators: list[dict] = []

    # Root login via SSH allowed
    if ssh_cfg.get("PermitRootLogin", "").lower() not in ("no", "prohibit-password", "forced-commands-only"):
        indicators.append({
            "id": "SSH-001",
            "severity": "high",
            "title": "SSH PermitRootLogin not disabled",
            "detail": f"PermitRootLogin = {ssh_cfg.get('PermitRootLogin', 'not set')}",
            "remediation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd.",
        })

    # Password authentication enabled
    if ssh_cfg.get("PasswordAuthentication", "yes").lower() == "yes":
        indicators.append({
            "id": "SSH-002",
            "severity": "medium",
            "title": "SSH PasswordAuthentication enabled",
            "detail": "Password-based SSH authentication allows brute-force attacks.",
            "remediation": "Set 'PasswordAuthentication no' and enforce key-based auth.",
        })

    # Empty passwords allowed
    if ssh_cfg.get("PermitEmptyPasswords", "no").lower() == "yes":
        indicators.append({
            "id": "SSH-003",
            "severity": "critical",
            "title": "SSH PermitEmptyPasswords enabled",
            "detail": "Accounts with empty passwords can SSH in without authentication.",
            "remediation": "Set 'PermitEmptyPasswords no' immediately.",
        })

    # Password max age too long (>90 days) or not set
    pass_max = login_defs.get("PASS_MAX_DAYS", "")
    try:
        if pass_max and int(pass_max) > 90:
            indicators.append({
                "id": "PWD-001",
                "severity": "low",
                "title": "Password maximum age too long",
                "detail": f"PASS_MAX_DAYS = {pass_max} (recommended: ≤ 90)",
                "remediation": "Set PASS_MAX_DAYS to 90 or less in /etc/login.defs.",
            })
    except ValueError:
        pass

    # World-writable files
    ww_count = len(cis.get("world_writable_files", []))
    if ww_count > 0:
        indicators.append({
            "id": "FS-001",
            "severity": "medium",
            "title": f"{ww_count} world-writable file(s) found",
            "detail": f"World-writable files can be modified by any local user: {cis['world_writable_files'][:5]}",
            "remediation": "Review and restrict permissions with 'chmod o-w <file>'.",
        })

    # Unusual SUID binaries (> 20 is suspicious on a minimal server)
    suid_count = len(cis.get("suid_binaries", []))
    if suid_count > 20:
        indicators.append({
            "id": "FS-002",
            "severity": "low",
            "title": f"{suid_count} SUID binaries found",
            "detail": "High number of SUID binaries increases local privilege escalation attack surface.",
            "remediation": "Audit SUID binaries and remove the bit where not needed: 'chmod u-s <file>'.",
        })

    return indicators
