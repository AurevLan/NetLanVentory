"""Authentication log analysis audit router.

Connects via SSH and analyses:
  - Failed login attempts (brute-force detection)
  - Successful logins (unusual sources)
  - Last logins per user
  - Auth log sources (journalctl, /var/log/auth.log, /var/log/secure)
"""

from __future__ import annotations

import asyncio
import re
import uuid
from collections import Counter
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
from netlanventory.models.auth_log_report import AuthLogReport

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/auth-log-audit", tags=["auth-log-audit"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]

_semaphore: asyncio.Semaphore | None = None

# Threshold: more than N failed attempts from a single IP = brute-force
_BRUTE_FORCE_THRESHOLD = 20


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(3)
    return _semaphore


# ── Schemas ───────────────────────────────────────────────────────────────────


class AuthLogReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    asset_id: uuid.UUID
    status: str
    failed_logins_count: int
    successful_logins_count: int
    unique_source_ips: int
    brute_force_sources: int
    risk_findings_count: int
    findings: dict | None = None
    error_msg: str | None = None
    created_at: datetime
    updated_at: datetime


class AuthLogTriggerOut(BaseModel):
    report_id: uuid.UUID
    message: str


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", response_model=AuthLogTriggerOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
async def trigger_auth_log_audit(
    request: Request,
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DbDep,
    current_user: UserDep,
) -> AuthLogTriggerOut:
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

    report = AuthLogReport(asset_id=asset_id, status="pending")
    db.add(report)
    await db.flush()

    actor = actor_from_user(current_user)
    await log_action(db, user=actor, action="auth_log_audit.trigger", resource_type="asset", resource_id=str(asset_id))
    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(_run_auth_log_audit, report_id=report.id, asset_id=asset_id)
    return AuthLogTriggerOut(report_id=report.id, message="Auth log analysis started")


@router.get("", response_model=list[AuthLogReportOut])
async def list_auth_log_reports(asset_id: uuid.UUID, db: DbDep, _user: UserDep) -> list[AuthLogReport]:
    result = await db.execute(
        select(AuthLogReport)
        .where(AuthLogReport.asset_id == asset_id)
        .order_by(AuthLogReport.created_at.desc())
        .limit(50)
    )
    return list(result.scalars().all())


@router.get("/{report_id}", response_model=AuthLogReportOut)
async def get_auth_log_report(asset_id: uuid.UUID, report_id: uuid.UUID, db: DbDep, _user: UserDep) -> AuthLogReport:
    result = await db.execute(
        select(AuthLogReport).where(AuthLogReport.id == report_id, AuthLogReport.asset_id == asset_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Auth log report not found")
    return report


# ── Background task ───────────────────────────────────────────────────────────


async def _run_cmd(conn: asyncssh.SSHClientConnection, cmd: str, timeout: int = 60) -> str:
    try:
        result = await asyncio.wait_for(conn.run(cmd, check=False), timeout=timeout)
        return (result.stdout or "").strip()
    except Exception:
        return ""


async def _run_auth_log_audit(report_id: uuid.UUID, asset_id: uuid.UUID) -> None:
    from netlanventory.api.routers.ssh_scan import _build_ssh_kwargs

    factory = get_session_factory()

    async with _get_semaphore():
        async with factory() as session:
            report = (await session.execute(select(AuthLogReport).where(AuthLogReport.id == report_id))).scalar_one_or_none()
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
                # Detect log source and gather data
                (
                    has_journalctl,
                    has_auth_log,
                    has_secure,
                    lastlog_out,
                    lastb_out,
                    wtmp_out,
                ) = await asyncio.gather(
                    _run_cmd(conn, "which journalctl 2>/dev/null", timeout=10),
                    _run_cmd(conn, "test -f /var/log/auth.log && echo yes || echo no", timeout=10),
                    _run_cmd(conn, "test -f /var/log/secure && echo yes || echo no", timeout=10),
                    _run_cmd(conn, "lastlog 2>/dev/null | grep -v 'Never logged in' | tail -n +2 | head -50", timeout=30),
                    _run_cmd(conn, "lastb -n 200 2>/dev/null", timeout=30),
                    _run_cmd(conn, "last -n 100 2>/dev/null", timeout=30),
                )

                # Determine best log source and extract failed/successful auths
                log_source = "unknown"
                failed_raw = ""
                success_raw = ""

                if has_journalctl:
                    log_source = "journalctl"
                    failed_raw, success_raw = await asyncio.gather(
                        _run_cmd(conn, "journalctl -u sshd -u ssh --no-pager --since '7 days ago' 2>/dev/null | grep -i 'failed\\|invalid user\\|authentication failure' | tail -5000", timeout=60),
                        _run_cmd(conn, "journalctl -u sshd -u ssh --no-pager --since '7 days ago' 2>/dev/null | grep -i 'accepted' | tail -1000", timeout=60),
                    )
                elif has_auth_log == "yes":
                    log_source = "auth.log"
                    failed_raw, success_raw = await asyncio.gather(
                        _run_cmd(conn, "grep -i 'failed\\|invalid user\\|authentication failure' /var/log/auth.log 2>/dev/null | tail -5000", timeout=60),
                        _run_cmd(conn, "grep -i 'accepted' /var/log/auth.log 2>/dev/null | tail -1000", timeout=60),
                    )
                elif has_secure == "yes":
                    log_source = "secure"
                    failed_raw, success_raw = await asyncio.gather(
                        _run_cmd(conn, "grep -i 'failed\\|invalid user\\|authentication failure' /var/log/secure 2>/dev/null | tail -5000", timeout=60),
                        _run_cmd(conn, "grep -i 'accepted' /var/log/secure 2>/dev/null | tail -1000", timeout=60),
                    )

            # Parse failed logins
            failed_by_user: Counter[str] = Counter()
            failed_by_ip: Counter[str] = Counter()
            failed_by_service: Counter[str] = Counter()
            total_failed = 0

            for line in failed_raw.splitlines():
                total_failed += 1
                # Extract user
                user_match = re.search(r"(?:user|for)\s+(\S+)", line, re.IGNORECASE)
                if user_match:
                    failed_by_user[user_match.group(1)] += 1
                # Extract source IP
                ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    failed_by_ip[ip_match.group(1)] += 1
                # Extract service
                if "sshd" in line.lower():
                    failed_by_service["sshd"] += 1
                elif "su" in line.lower():
                    failed_by_service["su"] += 1
                elif "sudo" in line.lower():
                    failed_by_service["sudo"] += 1

            # Parse successful logins
            success_entries = []
            total_success = 0
            success_by_user: Counter[str] = Counter()

            for line in success_raw.splitlines():
                total_success += 1
                user_match = re.search(r"for\s+(\S+)", line)
                ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
                if user_match:
                    success_by_user[user_match.group(1)] += 1
                if user_match and ip_match and len(success_entries) < 50:
                    success_entries.append({
                        "user": user_match.group(1),
                        "source": ip_match.group(1),
                        "service": "sshd",
                    })

            # Brute-force detection
            brute_force_suspects = []
            for ip, count in failed_by_ip.most_common(50):
                if count >= _BRUTE_FORCE_THRESHOLD:
                    brute_force_suspects.append({
                        "ip": ip,
                        "attempts": count,
                    })

            # Parse last logins
            last_logins = _parse_last(wtmp_out)

            # Unique source IPs
            all_ips = set(failed_by_ip.keys())

            # Risk findings
            risk_findings: list[dict] = []

            for suspect in brute_force_suspects:
                severity = "critical" if suspect["attempts"] >= 100 else "high"
                risk_findings.append({
                    "severity": severity,
                    "finding": f"Brute-force from {suspect['ip']} ({suspect['attempts']} attempts)",
                    "detail": f"{suspect['attempts']} failed login attempts detected",
                })

            # Root login from external
            for entry in success_entries:
                if entry["user"] == "root" and not _is_private_ip(entry["source"]):
                    risk_findings.append({
                        "severity": "critical",
                        "finding": f"Root login from external IP {entry['source']}",
                        "detail": "Direct root SSH access from a public IP address",
                    })
                    break

            # Too many failed logins overall
            if total_failed > 1000:
                risk_findings.append({
                    "severity": "high",
                    "finding": f"{total_failed} failed login attempts in the last 7 days",
                    "detail": "High volume of authentication failures — consider fail2ban or IP blocking",
                })

            # No fail2ban or denyhosts
            if brute_force_suspects and total_failed > 500:
                risk_findings.append({
                    "severity": "medium",
                    "finding": "No brute-force protection detected",
                    "detail": "Consider installing fail2ban or denyhosts",
                })

            findings = {
                "log_source": log_source,
                "failed_logins": {
                    "total": total_failed,
                    "by_user": dict(failed_by_user.most_common(30)),
                    "by_source_ip": dict(failed_by_ip.most_common(30)),
                    "by_service": dict(failed_by_service.most_common(10)),
                },
                "successful_logins": {
                    "total": total_success,
                    "by_user": dict(success_by_user.most_common(20)),
                    "recent": success_entries[:30],
                },
                "brute_force_suspects": brute_force_suspects,
                "last_logins": last_logins,
                "risk_findings": risk_findings,
            }

            async with factory() as session:
                report = (await session.execute(select(AuthLogReport).where(AuthLogReport.id == report_id))).scalar_one()
                report.status = "completed"
                report.failed_logins_count = total_failed
                report.successful_logins_count = total_success
                report.unique_source_ips = len(all_ips)
                report.brute_force_sources = len(brute_force_suspects)
                report.risk_findings_count = len(risk_findings)
                report.findings = findings
                await session.commit()

        except Exception as exc:
            logger.error("Auth log audit failed", report_id=str(report_id), error=str(exc), exc_info=True)
            async with factory() as session:
                report = (await session.execute(select(AuthLogReport).where(AuthLogReport.id == report_id))).scalar_one_or_none()
                if report:
                    report.status = "failed"
                    report.error_msg = str(exc)[:500]
                    await session.commit()


# ── Parsing helpers ───────────────────────────────────────────────────────────


def _parse_last(raw: str) -> list[dict]:
    entries = []
    for line in raw.splitlines():
        if not line.strip() or line.startswith("wtmp") or line.startswith("reboot"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            entries.append({
                "user": parts[0],
                "tty": parts[1],
                "source": parts[2] if len(parts) > 2 and "." in parts[2] else "",
            })
        if len(entries) >= 50:
            break
    return entries


def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return (
        a == 10
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or a == 127
    )
