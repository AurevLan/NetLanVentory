"""Security posture radar — aggregated security scores per domain for an asset."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_current_active_user, get_db
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/security-posture", tags=["security-posture"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]


class DomainScore(BaseModel):
    domain: str
    score: int  # 0-100, higher = more secure
    label: str
    detail: str


class SecurityPosture(BaseModel):
    asset_id: str
    overall_score: int
    domains: list[DomainScore]


@router.get("", response_model=SecurityPosture)
async def get_security_posture(
    asset_id: uuid.UUID,
    db: DbDep,
    _user: UserDep,
) -> SecurityPosture:
    """Compute per-domain security scores for radar chart visualization."""
    from netlanventory.models.asset_cve import AssetCve
    from netlanventory.models.cve import Cve
    from netlanventory.models.firewall_report import FirewallReport
    from netlanventory.models.hardening_report import HardeningReport
    from netlanventory.models.privesc_report import PrivescReport
    from netlanventory.models.rootkit_report import RootkitReport
    from netlanventory.models.ssh_audit_report import SshAuditReport
    from netlanventory.models.testssl_report import TestsslReport
    from netlanventory.models.auth_log_report import AuthLogReport
    from netlanventory.models.docker_bench_report import DockerBenchReport
    from netlanventory.models.threat_ioc import ThreatIoc
    from sqlalchemy import func
    from sqlalchemy.orm import selectinload

    asset = (await db.execute(
        select(Asset).options(selectinload(Asset.ports)).where(Asset.id == asset_id)
    )).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    domains: list[DomainScore] = []

    # 1. Network — based on open ports, firewall status
    open_ports = sum(1 for p in (asset.ports or []) if p.state == "open")
    fw_row = (await db.execute(
        select(FirewallReport.firewall_active)
        .where(FirewallReport.asset_id == asset_id, FirewallReport.status == "completed")
        .order_by(FirewallReport.created_at.desc()).limit(1)
    )).scalar_one_or_none()

    net_score = 100
    if open_ports > 20:
        net_score -= 30
    elif open_ports > 10:
        net_score -= 15
    elif open_ports > 5:
        net_score -= 5
    if fw_row is False:
        net_score -= 40
    elif fw_row is None:
        net_score -= 10  # not scanned

    domains.append(DomainScore(
        domain="network", score=max(0, net_score), label="Réseau",
        detail=f"{open_ports} ports ouverts, firewall {'actif' if fw_row else 'inactif' if fw_row is False else 'non scanné'}",
    ))

    # 2. Vulnerabilities — based on CVE severity
    cve_counts = dict((await db.execute(
        select(Cve.severity, func.count(AssetCve.id))
        .join(Cve, AssetCve.cve_id == Cve.id)
        .where(AssetCve.asset_id == asset_id, AssetCve.ack_status == "none")
        .group_by(Cve.severity)
    )).all())

    vuln_score = 100
    vuln_score -= cve_counts.get("Critical", 0) * 15
    vuln_score -= cve_counts.get("High", 0) * 8
    vuln_score -= cve_counts.get("Medium", 0) * 3
    vuln_score -= cve_counts.get("Low", 0) * 1
    total_cves = sum(cve_counts.values())

    domains.append(DomainScore(
        domain="vulnerabilities", score=max(0, min(100, vuln_score)), label="Vulnérabilités",
        detail=f"{total_cves} CVEs actives ({cve_counts.get('Critical', 0)} critiques)",
    ))

    # 3. Crypto/TLS — based on testssl grade
    tls_grade = (await db.execute(
        select(TestsslReport.grade)
        .where(TestsslReport.asset_id == asset_id, TestsslReport.status == "completed")
        .order_by(TestsslReport.created_at.desc()).limit(1)
    )).scalar_one_or_none()

    grade_scores = {"A+": 100, "A": 95, "A-": 90, "B": 70, "C": 50, "D": 30, "F": 10, "T": 10}
    tls_score = grade_scores.get((tls_grade or "").strip().upper(), 50 if tls_grade is None else 10)
    if tls_grade is None:
        tls_detail = "Non audité"
    else:
        tls_detail = f"Grade {tls_grade}"

    domains.append(DomainScore(
        domain="crypto", score=tls_score, label="Chiffrement",
        detail=tls_detail,
    ))

    # 4. System — hardening + SSH audit
    # SSH audit: compute score from critical/high counts (no score field on model)
    ssh_row = (await db.execute(
        select(SshAuditReport.critical_count, SshAuditReport.high_count)
        .where(SshAuditReport.asset_id == asset_id, SshAuditReport.status == "completed")
        .order_by(SshAuditReport.created_at.desc()).limit(1)
    )).first()
    ssh_score_val = None
    if ssh_row:
        ssh_score_val = max(0, 100 - ssh_row[0] * 20 - ssh_row[1] * 10)

    # Hardening: lynis_index is the score (0-100)
    hardening_idx = (await db.execute(
        select(HardeningReport.lynis_index)
        .where(HardeningReport.asset_id == asset_id, HardeningReport.status == "completed")
        .order_by(HardeningReport.created_at.desc()).limit(1)
    )).scalar_one_or_none()

    sys_scores = [s for s in [ssh_score_val, hardening_idx] if s is not None]
    sys_score = int(sum(sys_scores) / len(sys_scores)) if sys_scores else 50

    domains.append(DomainScore(
        domain="system", score=max(0, min(100, sys_score)), label="Système",
        detail=f"SSH: {ssh_score_val if ssh_score_val is not None else '—'}/100, Hardening: {hardening_idx or '—'}/100",
    ))

    # 5. Access control — privesc risks, auth logs, rootkit
    privesc_count = (await db.execute(
        select(PrivescReport.risk_findings_count)
        .where(PrivescReport.asset_id == asset_id, PrivescReport.status == "completed")
        .order_by(PrivescReport.created_at.desc()).limit(1)
    )).scalar_one_or_none()

    rootkit_count = (await db.execute(
        select(RootkitReport.infected_count)
        .where(RootkitReport.asset_id == asset_id, RootkitReport.status == "completed")
        .order_by(RootkitReport.created_at.desc()).limit(1)
    )).scalar_one_or_none()

    brute_count = (await db.execute(
        select(AuthLogReport.brute_force_sources)
        .where(AuthLogReport.asset_id == asset_id, AuthLogReport.status == "completed")
        .order_by(AuthLogReport.created_at.desc()).limit(1)
    )).scalar_one_or_none()

    access_score = 100
    if privesc_count:
        access_score -= min(privesc_count * 10, 40)
    if rootkit_count and rootkit_count > 0:
        access_score -= 50
    if brute_count and brute_count > 0:
        access_score -= min(brute_count * 5, 30)

    domains.append(DomainScore(
        domain="access", score=max(0, access_score), label="Contrôle d'accès",
        detail=f"Privesc: {privesc_count or 0} risques, Rootkit: {rootkit_count or 0}, Brute-force: {brute_count or 0} sources",
    ))

    # 6. Threat Intel — IOC matches
    ioc_count = (await db.execute(
        select(func.count(ThreatIoc.id))
        .where(ThreatIoc.indicator == str(asset.ip), ThreatIoc.ioc_type == "ip")
    )).scalar_one() if asset.ip else 0

    intel_score = 100 - min(ioc_count * 20, 80)

    domains.append(DomainScore(
        domain="threat_intel", score=max(0, intel_score), label="Threat Intel",
        detail=f"{ioc_count} IOCs correspondants",
    ))

    overall = int(sum(d.score for d in domains) / len(domains)) if domains else 50

    return SecurityPosture(
        asset_id=str(asset_id),
        overall_score=overall,
        domains=domains,
    )
