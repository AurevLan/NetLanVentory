"""Risk score computation for assets.

Unified formula combining:
  - CVE severity (CVSS base score)
  - Asset criticality factor
  - Exposure (open port count)
  - Confirmed exploitation (Nuclei validated)
  - Default credentials found (direct access = highest penalty)
  - TLS grade (testssl.sh)
  - SSH configuration weaknesses (ssh-audit)
  - IOC correlation (threat intelligence feed matches on IP/domain)

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
    ioc_match_count: int = 0,
    ioc_max_severity: str | None = None,
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
    ioc_match_count:
        Number of IOC matches (IP or domain) found in threat intelligence feeds.
    ioc_max_severity:
        Highest severity among matched IOCs ('critical', 'high', 'medium', 'low').
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

    # IOC correlation — asset IP/domain found in threat intelligence feeds
    if ioc_match_count > 0:
        severity_weight = {"critical": 25.0, "high": 15.0, "medium": 8.0, "low": 3.0}
        base_penalty = severity_weight.get((ioc_max_severity or "").lower(), 8.0)
        penalties += base_penalty + min(ioc_match_count - 1, 4) * 3.0

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
    from sqlalchemy.orm import load_only, selectinload

    from netlanventory.models.asset import Asset
    from netlanventory.models.asset_cve import AssetCve
    from netlanventory.models.auth_log_report import AuthLogReport
    from netlanventory.models.cve import Cve
    from netlanventory.models.default_creds_report import DefaultCredsReport
    from netlanventory.models.firewall_report import FirewallReport
    from netlanventory.models.privesc_report import PrivescReport
    from netlanventory.models.rootkit_report import RootkitReport
    from netlanventory.models.ssh_audit_report import SshAuditReport
    from netlanventory.models.testssl_report import TestsslReport

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
    # When compensating controls are enabled, replace each raw CVSS by the
    # post-controls effective severity computed from the asset's hardening
    # signals (firewall, privesc, headers/WAF, tags, KEV clamp).
    from netlanventory.core.config import get_settings
    settings = get_settings()
    use_cc = settings.use_compensating_controls
    shadow_cc = settings.shadow_mode_compensating_controls

    ctx = None
    if use_cc or shadow_cc:
        from netlanventory.core.compensating_controls import build_context, compute_effective_severity
        ctx = await build_context(session, asset)

    cvss_scores: list[float] = []
    exploit_verified_count = 0
    # Shadow-mode telemetry: count downgrades that *would* have applied
    shadow_downgrades = 0
    shadow_total_delta = 0.0

    for link in (asset.cves or []):
        if link.ack_status in ("false_positive", "accepted"):
            continue
        cve = link.cve
        if cve and cve.cvss_score is not None:
            if ctx is not None and (use_cc or shadow_cc):
                eff = compute_effective_severity(cve, ctx)
                if shadow_cc and not use_cc:
                    # Telemetry only — do NOT apply
                    if eff.effective < cve.cvss_score:
                        shadow_downgrades += 1
                        shadow_total_delta += (cve.cvss_score - eff.effective)
                    cvss_scores.append(cve.cvss_score)
                else:
                    cvss_scores.append(eff.effective)
            else:
                cvss_scores.append(cve.cvss_score)
        if link.exploit_verified:
            exploit_verified_count += 1

    if shadow_cc and not use_cc and shadow_downgrades > 0:
        logger.info(
            "compensating_controls_shadow",
            asset_id=str(asset_id),
            cves_evaluated=len(cvss_scores),
            would_downgrade=shadow_downgrades,
            total_delta=round(shadow_total_delta, 2),
        )

    # ── Scalar queries for latest report data ─────────────────────────────
    # Use load_only() to avoid loading relationship-heavy ORM objects that
    # could trigger lazy back_populates access via the identity map.

    # Latest testssl grade
    testssl_grade: str | None = None
    ts_row = (await session.execute(
        select(TestsslReport.grade)
        .where(TestsslReport.asset_id == asset_id, TestsslReport.status == "completed")
        .order_by(TestsslReport.created_at.desc())
        .limit(1)
    )).first()
    if ts_row:
        testssl_grade = ts_row[0]

    # Latest ssh-audit critical count
    ssh_audit_critical = 0
    sa_row = (await session.execute(
        select(SshAuditReport.critical_count)
        .where(SshAuditReport.asset_id == asset_id, SshAuditReport.status == "completed")
        .order_by(SshAuditReport.created_at.desc())
        .limit(1)
    )).first()
    if sa_row:
        ssh_audit_critical = sa_row[0]

    # Latest default_creds vulnerable count
    dc_vulnerable = 0
    dc_row = (await session.execute(
        select(DefaultCredsReport.vulnerable_count)
        .where(DefaultCredsReport.asset_id == asset_id, DefaultCredsReport.status == "completed")
        .order_by(DefaultCredsReport.created_at.desc())
        .limit(1)
    )).first()
    if dc_row:
        dc_vulnerable = dc_row[0]

    # Latest privesc risk count
    privesc_risks = 0
    pe_row = (await session.execute(
        select(PrivescReport.risk_findings_count)
        .where(PrivescReport.asset_id == asset_id, PrivescReport.status == "completed")
        .order_by(PrivescReport.created_at.desc())
        .limit(1)
    )).first()
    if pe_row:
        privesc_risks = pe_row[0]

    # Latest firewall status
    firewall_active: bool | None = None
    fw_row = (await session.execute(
        select(FirewallReport.firewall_active)
        .where(FirewallReport.asset_id == asset_id, FirewallReport.status == "completed")
        .order_by(FirewallReport.created_at.desc())
        .limit(1)
    )).first()
    if fw_row:
        firewall_active = fw_row[0]

    # Latest rootkit infected count
    rootkit_infected = 0
    rk_row = (await session.execute(
        select(RootkitReport.infected_count)
        .where(RootkitReport.asset_id == asset_id, RootkitReport.status == "completed")
        .order_by(RootkitReport.created_at.desc())
        .limit(1)
    )).first()
    if rk_row:
        rootkit_infected = rk_row[0]

    # Latest brute-force source count
    brute_force = 0
    al_row = (await session.execute(
        select(AuthLogReport.brute_force_sources)
        .where(AuthLogReport.asset_id == asset_id, AuthLogReport.status == "completed")
        .order_by(AuthLogReport.created_at.desc())
        .limit(1)
    )).first()
    if al_row:
        brute_force = al_row[0]

    # IOC matches (threat intelligence correlation)
    ioc_match_count = 0
    ioc_max_severity: str | None = None
    try:
        from netlanventory.models.threat_ioc import ThreatIoc
        from netlanventory.models.asset_dns import AssetDns

        # Match by IP
        ip_iocs = (await session.execute(
            select(ThreatIoc.severity)
            .where(ThreatIoc.indicator == str(asset.ip), ThreatIoc.ioc_type == "ip")
        )).scalars().all()

        # Match by DNS domains
        dns_names = (await session.execute(
            select(AssetDns.fqdn).where(AssetDns.asset_id == asset_id)
        )).scalars().all()
        domain_iocs = []
        if dns_names:
            domain_iocs = (await session.execute(
                select(ThreatIoc.severity)
                .where(ThreatIoc.indicator.in_([d.lower() for d in dns_names]), ThreatIoc.ioc_type == "domain")
            )).scalars().all()

        all_ioc_severities = list(ip_iocs) + list(domain_iocs)
        ioc_match_count = len(all_ioc_severities)
        if all_ioc_severities:
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            ioc_max_severity = min(all_ioc_severities, key=lambda s: severity_order.get(s.lower(), 4))
    except Exception as exc:
        logger.debug("ioc_correlation_query_failed", asset_id=str(asset_id), error=str(exc))

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
        ioc_match_count=ioc_match_count,
        ioc_max_severity=ioc_max_severity,
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
        ioc_matches=ioc_match_count,
    )
    return score
