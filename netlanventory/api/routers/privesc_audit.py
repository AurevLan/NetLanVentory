"""Privileged access & escalation audit router.

Connects via SSH and audits:
  - System users (passwd, login shells, UID 0 accounts)
  - Sudoers configuration (NOPASSWD, wildcards)
  - SUID / SGID binaries (with GTFOBins risk flagging)
  - Linux capabilities on binaries
  - SSH authorized_keys per user
  - World-writable files in sensitive paths
  - Empty password accounts
"""

from __future__ import annotations

import asyncio
import re
import uuid
from datetime import datetime, timezone
from typing import Annotated

import asyncssh

from netlanventory.core.ssh import ssh_connect
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
from netlanventory.models.privesc_report import PrivescReport

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/privesc-audit", tags=["privesc-audit"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]

_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(3)
    return _semaphore


# Known SUID binaries that can be abused for privilege escalation (GTFOBins)
_GTFOBINS_SUID: set[str] = {
    "python", "python2", "python3", "perl", "ruby", "lua", "php",
    "bash", "dash", "zsh", "ksh", "csh",
    "nmap", "vim", "vi", "nano", "less", "more", "man",
    "find", "awk", "gawk", "nawk", "sed",
    "env", "strace", "ltrace", "gdb", "node",
    "tar", "zip", "unzip", "rsync", "cp", "mv",
    "docker", "kubectl", "mount", "umount",
    "systemctl", "journalctl", "apt", "apt-get", "yum", "dnf", "rpm",
    "git", "curl", "wget", "nc", "ncat", "socat",
    "tee", "dd", "base64", "openssl",
    "capsh", "dmesg", "ip",
}

# Capabilities that allow privilege escalation
_DANGEROUS_CAPS: set[str] = {
    "cap_setuid", "cap_setgid", "cap_dac_override", "cap_dac_read_search",
    "cap_sys_admin", "cap_sys_ptrace", "cap_sys_module", "cap_sys_rawio",
    "cap_net_admin", "cap_net_raw", "cap_chown", "cap_fowner",
}


# ── Schemas ───────────────────────────────────────────────────────────────────


class PrivescReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    asset_id: uuid.UUID
    status: str
    users_count: int
    sudoers_count: int
    suid_count: int
    sgid_count: int
    capabilities_count: int
    authorized_keys_count: int
    writable_paths_count: int
    risk_findings_count: int
    findings: dict | None = None
    error_msg: str | None = None
    created_at: datetime
    updated_at: datetime


class PrivescTriggerOut(BaseModel):
    report_id: uuid.UUID
    message: str


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", response_model=PrivescTriggerOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
async def trigger_privesc_audit(
    request: Request,
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DbDep,
    current_user: UserDep,
) -> PrivescTriggerOut:
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

    report = PrivescReport(asset_id=asset_id, status="pending")
    db.add(report)
    await db.flush()

    actor = actor_from_user(current_user)
    await log_action(db, user=actor, action="privesc_audit.trigger", resource_type="asset", resource_id=str(asset_id))
    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(_run_privesc_audit, report_id=report.id, asset_id=asset_id)
    return PrivescTriggerOut(report_id=report.id, message="Privileged access audit started")


@router.get("", response_model=list[PrivescReportOut])
async def list_privesc_reports(asset_id: uuid.UUID, db: DbDep, _user: UserDep) -> list[PrivescReport]:
    result = await db.execute(
        select(PrivescReport)
        .where(PrivescReport.asset_id == asset_id)
        .order_by(PrivescReport.created_at.desc())
        .limit(50)
    )
    return list(result.scalars().all())


@router.get("/{report_id}", response_model=PrivescReportOut)
async def get_privesc_report(asset_id: uuid.UUID, report_id: uuid.UUID, db: DbDep, _user: UserDep) -> PrivescReport:
    result = await db.execute(
        select(PrivescReport).where(PrivescReport.id == report_id, PrivescReport.asset_id == asset_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Privesc report not found")
    return report


# ── Background task ───────────────────────────────────────────────────────────


async def _run_cmd(conn: asyncssh.SSHClientConnection, cmd: str, timeout: int = 60) -> str:
    try:
        result = await asyncio.wait_for(conn.run(cmd, check=False), timeout=timeout)
        return (result.stdout or "").strip()
    except Exception as exc:
        logger.debug("ssh_cmd_failed", cmd=cmd[:80], error=str(exc))
        return ""


async def _run_privesc_audit(report_id: uuid.UUID, asset_id: uuid.UUID) -> None:
    from netlanventory.api.routers.ssh_scan import _build_ssh_kwargs

    factory = get_session_factory()

    async with _get_semaphore():
        async with factory() as session:
            report = (await session.execute(select(PrivescReport).where(PrivescReport.id == report_id))).scalar_one_or_none()
            asset = (await session.execute(
                select(Asset).options(selectinload(Asset.ssh_profile)).where(Asset.id == asset_id)
            )).scalar_one_or_none()

            if not report or not asset:
                return

            report.status = "running"

            # Extract SSH params while session is open (avoids greenlet_spawn)
            ssh_kwargs = _build_ssh_kwargs(asset)
            host = str(asset.ip)
            port = asset.ssh_port or (asset.ssh_profile.ssh_port if asset.ssh_profile else None) or 22
            user = asset.ssh_user or (asset.ssh_profile.ssh_user if asset.ssh_profile else None) or "root"
            await session.commit()

        try:

            async with ssh_connect(host, port=port, username=user, **ssh_kwargs) as conn:
                # Run all data collection in parallel
                (
                    passwd_out,
                    shadow_readable,
                    sudoers_out,
                    sudoers_d_out,
                    suid_out,
                    sgid_out,
                    caps_out,
                    writable_out,
                    lastlog_out,
                ) = await asyncio.gather(
                    _run_cmd(conn, "getent passwd", timeout=30),
                    _run_cmd(conn, "test -r /etc/shadow && echo readable || echo denied", timeout=10),
                    _run_cmd(conn, "cat /etc/sudoers 2>/dev/null || echo 'DENIED'", timeout=30),
                    _run_cmd(conn, "cat /etc/sudoers.d/* 2>/dev/null", timeout=30),
                    _run_cmd(conn, "find / -xdev -perm -4000 -type f 2>/dev/null | head -200", timeout=120),
                    _run_cmd(conn, "find / -xdev -perm -2000 -type f 2>/dev/null | head -200", timeout=120),
                    _run_cmd(conn, "getcap -r / 2>/dev/null | head -200", timeout=120),
                    _run_cmd(conn, "find /etc /var /opt /srv /home -xdev -writable -type f 2>/dev/null | head -100", timeout=120),
                    _run_cmd(conn, "lastlog 2>/dev/null | grep -v 'Never logged in' | head -50", timeout=30),
                )

                # Collect authorized_keys per user with login shell
                users_parsed = _parse_passwd(passwd_out)
                login_users = [u for u in users_parsed if u["shell"] not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin")]

                auth_keys_tasks = []
                for u in login_users:
                    home = u["home"]
                    auth_keys_tasks.append(_run_cmd(conn, f"cat {home}/.ssh/authorized_keys 2>/dev/null", timeout=15))

                auth_keys_results = await asyncio.gather(*auth_keys_tasks) if auth_keys_tasks else []

                authorized_keys = []
                total_keys = 0
                for u, keys_out in zip(login_users, auth_keys_results):
                    if keys_out:
                        keys = [l.strip() for l in keys_out.splitlines() if l.strip() and not l.startswith("#")]
                        if keys:
                            authorized_keys.append({
                                "user": u["name"],
                                "keys_count": len(keys),
                                "keys": [k[:120] + "..." if len(k) > 120 else k for k in keys],
                            })
                            total_keys += len(keys)

            # Parse findings
            sudoers_rules = _parse_sudoers(sudoers_out, sudoers_d_out)
            suid_binaries = [l for l in suid_out.splitlines() if l.strip()] if suid_out else []
            sgid_binaries = [l for l in sgid_out.splitlines() if l.strip()] if sgid_out else []
            capabilities = _parse_capabilities(caps_out)
            writable_paths = [l for l in writable_out.splitlines() if l.strip()] if writable_out else []
            empty_pw_users = [u["name"] for u in users_parsed if u.get("password") == ""]
            nologin_count = sum(1 for u in users_parsed if u["shell"] in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin"))
            uid0_users = [u["name"] for u in users_parsed if u["uid"] == 0]

            # Risk analysis
            risk_findings = _analyze_risks(
                users_parsed, sudoers_rules, suid_binaries, sgid_binaries,
                capabilities, authorized_keys, writable_paths,
                shadow_readable, empty_pw_users, uid0_users,
            )

            findings = {
                "users": users_parsed,
                "sudoers": sudoers_rules,
                "suid_binaries": suid_binaries,
                "sgid_binaries": sgid_binaries,
                "capabilities": capabilities,
                "authorized_keys": authorized_keys,
                "writable_paths": writable_paths,
                "risk_findings": risk_findings,
                "passwd_hash_exposure": shadow_readable == "readable",
                "empty_password_users": empty_pw_users,
                "nologin_shell_users": nologin_count,
                "uid0_accounts": uid0_users,
                "root_login_allowed": any(u["name"] == "root" and u["shell"] not in ("/usr/sbin/nologin", "/bin/false") for u in users_parsed),
            }

            async with factory() as session:
                report = (await session.execute(select(PrivescReport).where(PrivescReport.id == report_id))).scalar_one()
                report.status = "completed"
                report.users_count = len(users_parsed)
                report.sudoers_count = len(sudoers_rules)
                report.suid_count = len(suid_binaries)
                report.sgid_count = len(sgid_binaries)
                report.capabilities_count = len(capabilities)
                report.authorized_keys_count = total_keys
                report.writable_paths_count = len(writable_paths)
                report.risk_findings_count = len(risk_findings)
                report.findings = findings
                await session.commit()

        except Exception as exc:
            logger.error("Privesc audit failed", report_id=str(report_id), error=str(exc), exc_info=True)
            async with factory() as session:
                report = (await session.execute(select(PrivescReport).where(PrivescReport.id == report_id))).scalar_one_or_none()
                if report:
                    report.status = "failed"
                    report.error_msg = str(exc)[:500]
                    await session.commit()


# ── Parsing helpers ───────────────────────────────────────────────────────────


def _parse_passwd(raw: str) -> list[dict]:
    users = []
    for line in raw.splitlines():
        parts = line.split(":")
        if len(parts) >= 7:
            users.append({
                "name": parts[0],
                "uid": int(parts[2]) if parts[2].isdigit() else -1,
                "gid": int(parts[3]) if parts[3].isdigit() else -1,
                "gecos": parts[4],
                "home": parts[5],
                "shell": parts[6],
            })
    return users


def _parse_sudoers(main: str, drop_in: str) -> list[dict]:
    rules = []
    if main == "DENIED":
        main = ""
    combined = (main or "") + "\n" + (drop_in or "")
    for line in combined.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("Defaults"):
            continue
        risky = "NOPASSWD" in line or "ALL=(ALL)" in line
        rules.append({"rule": line, "risky": risky})
    return rules


def _parse_capabilities(raw: str) -> list[dict]:
    caps = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        # Format: /path/to/binary cap_xxx=ep
        parts = line.split(None, 1)
        if len(parts) == 2:
            caps.append({"path": parts[0], "caps": parts[1]})
        elif parts:
            caps.append({"path": parts[0], "caps": ""})
    return caps


def _analyze_risks(
    users, sudoers, suid, sgid, caps, auth_keys, writable,
    shadow_readable, empty_pw_users, uid0_users,
) -> list[dict]:
    findings: list[dict] = []

    # UID 0 accounts other than root
    for u in uid0_users:
        if u != "root":
            findings.append({"severity": "critical", "finding": f"Non-root UID 0 account: {u}", "detail": "Multiple UID 0 accounts may indicate compromise or misconfiguration"})

    # Empty passwords
    for u in empty_pw_users:
        findings.append({"severity": "critical", "finding": f"Empty password for user: {u}", "detail": "Account can be accessed without authentication"})

    # Shadow readable by non-root
    if shadow_readable == "readable":
        findings.append({"severity": "high", "finding": "/etc/shadow is world-readable", "detail": "Password hashes exposed — offline cracking possible"})

    # NOPASSWD sudoers
    for rule in sudoers:
        if rule.get("risky") and "NOPASSWD" in rule.get("rule", ""):
            findings.append({"severity": "critical", "finding": f"NOPASSWD sudo rule: {rule['rule'][:120]}", "detail": "Allows privilege escalation without password"})

    # Dangerous SUID binaries (GTFOBins)
    for path in suid:
        binary_name = path.rsplit("/", 1)[-1] if "/" in path else path
        # Strip version suffixes like python3.11
        base_name = re.sub(r"[\d.]+$", "", binary_name)
        if base_name in _GTFOBINS_SUID or binary_name in _GTFOBINS_SUID:
            findings.append({"severity": "high", "finding": f"SUID on GTFOBins binary: {path}", "detail": f"{binary_name} with SUID can be used for privilege escalation"})

    # Dangerous capabilities
    for cap in caps:
        cap_names = cap.get("caps", "").lower()
        dangerous = [c for c in _DANGEROUS_CAPS if c in cap_names]
        if dangerous:
            findings.append({"severity": "high", "finding": f"Dangerous capability on {cap['path']}: {', '.join(dangerous)}", "detail": "Can be used for privilege escalation"})

    # Root authorized_keys
    for ak in auth_keys:
        if ak["user"] == "root" and ak["keys_count"] > 0:
            findings.append({"severity": "medium", "finding": f"Root has {ak['keys_count']} SSH authorized keys", "detail": "Direct root SSH access — verify all keys are legitimate"})

    # Writable files in sensitive paths
    sensitive_writable = [p for p in writable if any(p.startswith(d) for d in ("/etc/", "/var/spool/cron", "/usr/"))]
    if sensitive_writable:
        findings.append({
            "severity": "high",
            "finding": f"{len(sensitive_writable)} writable files in sensitive paths",
            "detail": "; ".join(sensitive_writable[:10]),
        })

    return findings
