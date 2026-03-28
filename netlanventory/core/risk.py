"""Risk score computation for assets.

Unified formula combining:
  - CVE severity (CVSS base score)
  - Asset criticality factor
  - Exposure (open port count)
  - Confirmed exploitation (Nuclei validated)
  - Default credentials found (direct access = highest penalty)
  - TLS grade (testssl.sh)
  - SSH configuration weaknesses (ssh-audit)

Score is normalised to [0, 100].
"""

from __future__ import annotations

import uuid

from netlanventory.core.logging import get_logger

logger = get_logger(__name__)

_CRITICALITY_FACTORS: dict[str, float] = {
    "critical": 2.0,
    "high": 1.5,
    "medium": 1.0,
    "low": 0.5,
}

_TESTSSL_GRADE_PENALTY: dict[str, float] = {
    "F": 18.0,
    "T": 15.0,   # certificate untrusted — treated like F
    "D": 10.0,
    "C": 6.0,
    "B": 2.0,
    "A": 0.0,
    "A-": 0.0,
    "A+": 0.0,
}


def compute_risk_score(
    asset_criticality: str,
    active_cvss_scores: list[float],
    open_port_count: int,
    *,
    testssl_grade: str | None = None,
    default_creds_vulnerable_count: int = 0,
    ssh_audit_critical_count: int = 0,
    exploit_verified_count: int = 0,
    privesc_risk_count: int = 0,
    firewall_active: bool | None = None,
    rootkit_infected_count: int = 0,
    brute_force_sources: int = 0,
) -> float:
    """Return a unified risk score in [0, 100].

    Parameters
    ----------
    asset_criticality:
        One of 'critical', 'high', 'medium', 'low'.
    active_cvss_scores:
        CVSS base scores (0–10) for active CVEs. May be empty.
    open_port_count:
        Open TCP/UDP ports (exposure factor).
    testssl_grade:
        Overall grade from testssl.sh (A+/A/B/C/D/F/T). None = not scanned.
    default_creds_vulnerable_count:
        Number of services where default credentials were confirmed.
        Any value > 0 is critical: unauthenticated access is an immediate compromise.
    ssh_audit_critical_count:
        Number of critical CVEs detected by ssh-audit (e.g. Terrapin).
    exploit_verified_count:
        Number of CVEs confirmed exploitable via Nuclei exploit validation.
    privesc_risk_count:
        Number of privilege escalation risk findings (NOPASSWD sudo, GTFOBins SUID, etc.).
    firewall_active:
        Whether a host firewall is active. None = not scanned. False = no firewall.
    rootkit_infected_count:
        Number of rootkit infections detected.
    brute_force_sources:
        Number of unique IPs performing brute-force attacks on the asset.
    """
    criticality_factor = _CRITICALITY_FACTORS.get(asset_criticality.lower(), 1.0)
    exposure_factor = 1.0 + 0.1 * open_port_count

    # ── Base score from CVEs ──────────────────────────────────────────────────
    if active_cvss_scores:
        max_cvss = max(active_cvss_scores)
        raw_cve = max_cvss * criticality_factor * exposure_factor
        # Normalise: CVSS 10 × criticality 2.0 × exposure ≈ raw up to ~60
        # Map that to 0–70 range so penalties have room to push to 100.
        base = min((raw_cve / 10.0) * 35.0, 70.0)
    else:
        base = 0.0

    # ── Penalty modifiers (additive, weighted by criticality) ─────────────────
    penalties = 0.0

    # Default credentials found — direct unauthenticated access
    # This is the worst finding: a CVE-less Redis/Mongo open to all is instant compromise.
    if default_creds_vulnerable_count > 0:
        penalties += 35.0 + min(default_creds_vulnerable_count - 1, 3) * 5.0

    # Confirmed exploit (Nuclei validated PoC on a CVE)
    if exploit_verified_count > 0:
        penalties += 20.0 + min(exploit_verified_count - 1, 2) * 3.0

    # SSH critical CVE (Terrapin etc.) — confirmed network-level attack
    if ssh_audit_critical_count > 0:
        penalties += 12.0 + min(ssh_audit_critical_count - 1, 2) * 3.0

    # TLS grade penalty (misconfigured TLS = MITM, downgrade, BEAST, Heartbleed)
    grade_upper = (testssl_grade or "").strip().upper()
    penalties += _TESTSSL_GRADE_PENALTY.get(grade_upper, 0.0)

    # Privilege escalation paths — NOPASSWD sudo, GTFOBins SUID, dangerous caps
    if privesc_risk_count > 0:
        penalties += 10.0 + min(privesc_risk_count - 1, 4) * 3.0

    # No firewall — all services directly exposed
    if firewall_active is False:
        penalties += 15.0

    # Rootkit detected — asset likely compromised
    if rootkit_infected_count > 0:
        penalties += 30.0 + min(rootkit_infected_count - 1, 2) * 5.0

    # Active brute-force — asset under attack
    if brute_force_sources > 0:
        penalties += 5.0 + min(brute_force_sources - 1, 4) * 2.0

    # Penalties are also weighted by criticality (a critical asset with open Redis is worse)
    # but cap the factor at 1.5 to avoid double-counting with CVE criticality
    penalty_factor = min(criticality_factor, 1.5)
    total = base + penalties * penalty_factor

    return round(min(total, 100.0), 2)


# ── DB helper — refresh asset.risk_score from all sources ────────────────────


async def refresh_asset_risk_score(session, asset_id: uuid.UUID) -> float | None:
    """Recompute and persist asset.risk_score using all available scan data.

    Reads:
      - Asset.criticality, open ports
      - CVE CVSS scores (active, unacknowledged)
      - Latest testssl grade
      - Latest ssh_audit critical count
      - Latest default_creds vulnerable count
      - Exploit-verified CVE count

    Returns the new score (also written to asset.risk_score), or None if not found.
    """
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    from netlanventory.models.asset import Asset
    from netlanventory.models.asset_cve import AssetCve
    from netlanventory.models.cve import Cve
    from netlanventory.models.testssl_report import TestsslReport
    from netlanventory.models.ssh_audit_report import SshAuditReport
    from netlanventory.models.default_creds_report import DefaultCredsReport

    # Load asset with ports and CVEs
    result = await session.execute(
        select(Asset)
        .options(selectinload(Asset.ports), selectinload(Asset.cves).selectinload(AssetCve.cve))
        .where(Asset.id == asset_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        return None

    open_port_count = sum(1 for p in (asset.ports or []) if p.state == "open")

    # Active CVE CVSS scores — exclude acknowledged as false_positive / accepted
    cvss_scores: list[float] = []
    exploit_verified_count = 0
    for link in (asset.cves or []):
        if link.ack_status in ("false_positive", "accepted"):
            continue
        cve = link.cve
        if cve and cve.cvss_score is not None:
            cvss_scores.append(cve.cvss_score)
        if link.exploit_verified:
            exploit_verified_count += 1

    # Latest testssl grade
    testssl_grade: str | None = None
    ts_result = await session.execute(
        select(TestsslReport)
        .where(
            TestsslReport.asset_id == asset_id,
            TestsslReport.status == "completed",
        )
        .order_by(TestsslReport.created_at.desc())
        .limit(1)
    )
    ts_report = ts_result.scalar_one_or_none()
    if ts_report:
        testssl_grade = ts_report.grade

    # Latest ssh-audit critical count
    ssh_audit_critical = 0
    sa_result = await session.execute(
        select(SshAuditReport)
        .where(
            SshAuditReport.asset_id == asset_id,
            SshAuditReport.status == "completed",
        )
        .order_by(SshAuditReport.created_at.desc())
        .limit(1)
    )
    sa_report = sa_result.scalar_one_or_none()
    if sa_report:
        ssh_audit_critical = sa_report.critical_count

    # Latest default_creds vulnerable count
    dc_vulnerable = 0
    dc_result = await session.execute(
        select(DefaultCredsReport)
        .where(
            DefaultCredsReport.asset_id == asset_id,
            DefaultCredsReport.status == "completed",
        )
        .order_by(DefaultCredsReport.created_at.desc())
        .limit(1)
    )
    dc_report = dc_result.scalar_one_or_none()
    if dc_report:
        dc_vulnerable = dc_report.vulnerable_count

    # Latest privesc risk count
    privesc_risks = 0
    from netlanventory.models.privesc_report import PrivescReport
    pe_result = await session.execute(
        select(PrivescReport)
        .where(PrivescReport.asset_id == asset_id, PrivescReport.status == "completed")
        .order_by(PrivescReport.created_at.desc())
        .limit(1)
    )
    pe_report = pe_result.scalar_one_or_none()
    if pe_report:
        privesc_risks = pe_report.risk_findings_count

    # Latest firewall status
    firewall_active: bool | None = None
    from netlanventory.models.firewall_report import FirewallReport as FwReport
    fw_result = await session.execute(
        select(FwReport)
        .where(FwReport.asset_id == asset_id, FwReport.status == "completed")
        .order_by(FwReport.created_at.desc())
        .limit(1)
    )
    fw_report = fw_result.scalar_one_or_none()
    if fw_report:
        firewall_active = fw_report.firewall_active

    # Latest rootkit infected count
    rootkit_infected = 0
    from netlanventory.models.rootkit_report import RootkitReport as RkReport
    rk_result = await session.execute(
        select(RkReport)
        .where(RkReport.asset_id == asset_id, RkReport.status == "completed")
        .order_by(RkReport.created_at.desc())
        .limit(1)
    )
    rk_report = rk_result.scalar_one_or_none()
    if rk_report:
        rootkit_infected = rk_report.infected_count

    # Latest brute-force source count
    brute_force = 0
    from netlanventory.models.auth_log_report import AuthLogReport as AlReport
    al_result = await session.execute(
        select(AlReport)
        .where(AlReport.asset_id == asset_id, AlReport.status == "completed")
        .order_by(AlReport.created_at.desc())
        .limit(1)
    )
    al_report = al_result.scalar_one_or_none()
    if al_report:
        brute_force = al_report.brute_force_sources

    score = compute_risk_score(
        asset_criticality=asset.criticality or "medium",
        active_cvss_scores=cvss_scores,
        open_port_count=open_port_count,
        testssl_grade=testssl_grade,
        default_creds_vulnerable_count=dc_vulnerable,
        ssh_audit_critical_count=ssh_audit_critical,
        exploit_verified_count=exploit_verified_count,
        privesc_risk_count=privesc_risks,
        firewall_active=firewall_active,
        rootkit_infected_count=rootkit_infected,
        brute_force_sources=brute_force,
    )

    asset.risk_score = score
    logger.info(
        "Risk score refreshed",
        asset_id=str(asset_id),
        score=score,
        cvss_count=len(cvss_scores),
        default_creds=dc_vulnerable,
        testssl_grade=testssl_grade,
        ssh_critical=ssh_audit_critical,
        exploit_verified=exploit_verified_count,
        privesc_risks=privesc_risks,
        firewall_active=firewall_active,
        rootkit_infected=rootkit_infected,
        brute_force=brute_force,
    )
    return score
