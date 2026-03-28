"""Firewall rules audit router.

Connects via SSH and audits:
  - Firewall backend detection (iptables / nftables / ufw / firewalld)
  - Default chain policies
  - Active rules enumeration
  - Risk analysis (permissive policies, exposed services)
"""

from __future__ import annotations

import asyncio
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
from netlanventory.models.firewall_report import FirewallReport

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/firewall-audit", tags=["firewall-audit"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]

_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(3)
    return _semaphore


# Ports commonly dangerous when exposed to 0.0.0.0/0
_RISKY_PORTS: dict[str, str] = {
    "3306": "MySQL", "5432": "PostgreSQL", "6379": "Redis",
    "27017": "MongoDB", "11211": "Memcached", "9200": "Elasticsearch",
    "5900": "VNC", "3389": "RDP", "445": "SMB",
    "23": "Telnet", "21": "FTP", "1433": "MSSQL",
    "2375": "Docker API", "2376": "Docker API TLS",
    "8080": "HTTP-Alt", "9090": "Admin",
}


# ── Schemas ───────────────────────────────────────────────────────────────────


class FirewallReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    asset_id: uuid.UUID
    status: str
    backend: str | None = None
    firewall_active: bool | None = None
    rules_count: int
    open_input_count: int
    risk_findings_count: int
    findings: dict | None = None
    error_msg: str | None = None
    created_at: datetime
    updated_at: datetime


class FirewallTriggerOut(BaseModel):
    report_id: uuid.UUID
    message: str


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", response_model=FirewallTriggerOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
async def trigger_firewall_audit(
    request: Request,
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DbDep,
    current_user: UserDep,
) -> FirewallTriggerOut:
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

    report = FirewallReport(asset_id=asset_id, status="pending")
    db.add(report)
    await db.flush()

    actor = actor_from_user(current_user)
    await log_action(db, user=actor, action="firewall_audit.trigger", resource_type="asset", resource_id=str(asset_id))
    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(_run_firewall_audit, report_id=report.id, asset_id=asset_id)
    return FirewallTriggerOut(report_id=report.id, message="Firewall audit started")


@router.get("", response_model=list[FirewallReportOut])
async def list_firewall_reports(asset_id: uuid.UUID, db: DbDep, _user: UserDep) -> list[FirewallReport]:
    result = await db.execute(
        select(FirewallReport)
        .where(FirewallReport.asset_id == asset_id)
        .order_by(FirewallReport.created_at.desc())
        .limit(50)
    )
    return list(result.scalars().all())


@router.get("/{report_id}", response_model=FirewallReportOut)
async def get_firewall_report(asset_id: uuid.UUID, report_id: uuid.UUID, db: DbDep, _user: UserDep) -> FirewallReport:
    result = await db.execute(
        select(FirewallReport).where(FirewallReport.id == report_id, FirewallReport.asset_id == asset_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Firewall report not found")
    return report


# ── Background task ───────────────────────────────────────────────────────────


async def _run_cmd(conn: asyncssh.SSHClientConnection, cmd: str, timeout: int = 60) -> str:
    try:
        result = await asyncio.wait_for(conn.run(cmd, check=False), timeout=timeout)
        return (result.stdout or "").strip()
    except Exception:
        return ""


async def _run_firewall_audit(report_id: uuid.UUID, asset_id: uuid.UUID) -> None:
    from netlanventory.api.routers.ssh_scan import _build_ssh_kwargs

    factory = get_session_factory()

    async with _get_semaphore():
        async with factory() as session:
            report = (await session.execute(select(FirewallReport).where(FirewallReport.id == report_id))).scalar_one_or_none()
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
                # Detect firewall backend and collect rules
                (
                    iptables_out,
                    iptables_policy_out,
                    nft_out,
                    ufw_out,
                    firewalld_out,
                    firewalld_zones,
                    ss_out,
                ) = await asyncio.gather(
                    _run_cmd(conn, "iptables -L -n -v --line-numbers 2>/dev/null", timeout=30),
                    _run_cmd(conn, "iptables -L -n 2>/dev/null | grep 'Chain.*policy'", timeout=15),
                    _run_cmd(conn, "nft list ruleset 2>/dev/null", timeout=30),
                    _run_cmd(conn, "ufw status verbose 2>/dev/null", timeout=15),
                    _run_cmd(conn, "firewall-cmd --state 2>/dev/null", timeout=15),
                    _run_cmd(conn, "firewall-cmd --list-all-zones 2>/dev/null", timeout=30),
                    _run_cmd(conn, "ss -tlnp 2>/dev/null | tail -n +2", timeout=15),
                )

            # Detect backend
            backend = "none"
            firewall_active = False

            if "Status: active" in ufw_out:
                backend = "ufw"
                firewall_active = True
            elif firewalld_out == "running":
                backend = "firewalld"
                firewall_active = True
            elif nft_out and "table" in nft_out:
                backend = "nftables"
                firewall_active = True
            elif iptables_out and "Chain" in iptables_out:
                # Check if there are actual rules beyond default policies
                has_rules = any(
                    line.strip() and not line.startswith("Chain") and not line.startswith("num")
                    for line in iptables_out.splitlines()
                    if line.strip() and "pkts" not in line
                )
                if has_rules:
                    backend = "iptables"
                    firewall_active = True

            # Parse default policies
            default_policies = _parse_iptables_policies(iptables_policy_out)

            # Parse rules
            rules = _parse_iptables_rules(iptables_out)
            ufw_rules = _parse_ufw_rules(ufw_out) if backend == "ufw" else []

            # Parse listening services
            listening_services = _parse_ss(ss_out)

            # Risk analysis
            risk_findings = _analyze_firewall_risks(
                backend, firewall_active, default_policies, rules, ufw_rules,
                listening_services, firewalld_zones if backend == "firewalld" else "",
            )

            # Count open INPUT rules accepting from anywhere
            open_input = sum(
                1 for r in rules
                if r.get("chain") == "INPUT" and r.get("target") == "ACCEPT"
                and r.get("source") in ("0.0.0.0/0", "anywhere", "::/0", "")
            )

            findings = {
                "backend": backend,
                "firewall_active": firewall_active,
                "default_policies": default_policies,
                "rules": rules[:200],
                "ufw_rules": ufw_rules,
                "nft_ruleset_preview": nft_out[:3000] if nft_out else None,
                "firewalld_zones": firewalld_zones[:2000] if firewalld_zones else None,
                "listening_services": listening_services,
                "risk_findings": risk_findings,
            }

            async with factory() as session:
                report = (await session.execute(select(FirewallReport).where(FirewallReport.id == report_id))).scalar_one()
                report.status = "completed"
                report.backend = backend
                report.firewall_active = firewall_active
                report.rules_count = len(rules) + len(ufw_rules)
                report.open_input_count = open_input
                report.risk_findings_count = len(risk_findings)
                report.findings = findings
                await session.commit()

        except Exception as exc:
            logger.error("Firewall audit failed", report_id=str(report_id), error=str(exc), exc_info=True)
            async with factory() as session:
                report = (await session.execute(select(FirewallReport).where(FirewallReport.id == report_id))).scalar_one_or_none()
                if report:
                    report.status = "failed"
                    report.error_msg = str(exc)[:500]
                    await session.commit()


# ── Parsing helpers ───────────────────────────────────────────────────────────


def _parse_iptables_policies(raw: str) -> dict[str, str]:
    policies = {}
    for line in raw.splitlines():
        m = re.match(r"Chain\s+(\S+)\s+\(policy\s+(\S+)\)", line)
        if m:
            policies[m.group(1)] = m.group(2)
    return policies


def _parse_iptables_rules(raw: str) -> list[dict]:
    rules = []
    current_chain = ""
    for line in raw.splitlines():
        line = line.strip()
        m = re.match(r"Chain\s+(\S+)", line)
        if m:
            current_chain = m.group(1)
            continue
        if not line or line.startswith("num") or line.startswith("pkts"):
            continue
        parts = line.split()
        if len(parts) >= 8:
            rule = {
                "chain": current_chain,
                "target": parts[1] if len(parts) > 1 else "",
                "proto": parts[2] if len(parts) > 2 else "",
                "source": parts[4] if len(parts) > 4 else "",
                "destination": parts[5] if len(parts) > 5 else "",
                "extra": " ".join(parts[6:]) if len(parts) > 6 else "",
            }
            # Extract dport
            dport_match = re.search(r"dpt:(\d+)", rule["extra"])
            if dport_match:
                rule["dport"] = dport_match.group(1)
            rules.append(rule)
    return rules


def _parse_ufw_rules(raw: str) -> list[str]:
    rules = []
    in_rules = False
    for line in raw.splitlines():
        if line.startswith("--"):
            in_rules = True
            continue
        if in_rules and line.strip():
            rules.append(line.strip())
    return rules


def _parse_ss(raw: str) -> list[dict]:
    services = []
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            local = parts[3]
            # Extract port and bind address
            if ":" in local:
                addr, port = local.rsplit(":", 1)
                services.append({
                    "bind": addr.strip("[]"),
                    "port": port,
                    "proto": parts[0],
                    "process": parts[5] if len(parts) > 5 else "",
                })
    return services


def _analyze_firewall_risks(
    backend, active, policies, rules, ufw_rules, listening, firewalld_zones,
) -> list[dict]:
    findings: list[dict] = []

    # No firewall at all
    if not active or backend == "none":
        findings.append({
            "severity": "critical",
            "finding": "No active firewall detected",
            "detail": "Host has no firewall — all listening services are directly exposed",
        })
        return findings

    # Default INPUT ACCEPT
    if policies.get("INPUT") == "ACCEPT":
        findings.append({
            "severity": "critical",
            "finding": "Default INPUT policy is ACCEPT",
            "detail": "All inbound traffic is allowed by default — should be DROP or REJECT",
        })

    # Default FORWARD ACCEPT
    if policies.get("FORWARD") == "ACCEPT":
        findings.append({
            "severity": "high",
            "finding": "Default FORWARD policy is ACCEPT",
            "detail": "Packet forwarding allowed — potential pivot point for lateral movement",
        })

    # Risky ports open to 0.0.0.0/0
    for r in rules:
        dport = r.get("dport", "")
        if (
            r.get("chain") == "INPUT"
            and r.get("target") == "ACCEPT"
            and r.get("source") in ("0.0.0.0/0", "anywhere", "::/0")
            and dport in _RISKY_PORTS
        ):
            findings.append({
                "severity": "high",
                "finding": f"Port {dport} ({_RISKY_PORTS[dport]}) open to all sources",
                "detail": f"Service {_RISKY_PORTS[dport]} accessible from any IP — restrict to trusted networks",
            })

    # Listening services not covered by firewall (when INPUT default is DROP)
    if policies.get("INPUT") == "DROP" and listening:
        allowed_ports = {r.get("dport") for r in rules if r.get("target") == "ACCEPT" and r.get("dport")}
        for svc in listening:
            if svc["bind"] in ("0.0.0.0", "::", "*") and svc["port"] not in allowed_ports:
                if svc["port"] in _RISKY_PORTS:
                    findings.append({
                        "severity": "medium",
                        "finding": f"{_RISKY_PORTS[svc['port']]} listening on port {svc['port']} but blocked by firewall",
                        "detail": "Service is running but firewall blocks access — consider stopping the service",
                    })

    return findings
