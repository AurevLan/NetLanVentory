"""ISO 27001:2022 compliance evaluator.

Evaluates ISO 27001:2022 Annex A controls based on the data available in
NetLanVentory: assets, CVEs, hardening reports, SSL scans, audit logs.

This is a heuristic evaluation — not a formal audit tool. It provides a
risk-based score per domain to guide improvement priorities.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


# ISO 27001:2022 Annex A control domains
_DOMAINS = [
    "A.5 Organizational controls",
    "A.6 People controls",
    "A.7 Physical controls",
    "A.8 Technological controls",
]

# Controls we can evaluate automatically
_EVALUATABLE_CONTROLS = [
    {
        "id": "A.8.2",
        "title": "Privileged access rights",
        "domain": "A.8 Technological controls",
        "metric": "privileged_access",
        "weight": 8,
    },
    {
        "id": "A.8.5",
        "title": "Secure authentication",
        "domain": "A.8 Technological controls",
        "metric": "secure_auth",
        "weight": 7,
    },
    {
        "id": "A.8.8",
        "title": "Management of technical vulnerabilities",
        "domain": "A.8 Technological controls",
        "metric": "vuln_management",
        "weight": 9,
    },
    {
        "id": "A.8.9",
        "title": "Configuration management",
        "domain": "A.8 Technological controls",
        "metric": "config_mgmt",
        "weight": 6,
    },
    {
        "id": "A.8.16",
        "title": "Monitoring activities",
        "domain": "A.8 Technological controls",
        "metric": "monitoring",
        "weight": 7,
    },
    {
        "id": "A.8.20",
        "title": "Network security",
        "domain": "A.8 Technological controls",
        "metric": "network_security",
        "weight": 8,
    },
    {
        "id": "A.8.23",
        "title": "Web filtering",
        "domain": "A.8 Technological controls",
        "metric": "web_filtering",
        "weight": 5,
    },
    {
        "id": "A.8.25",
        "title": "Secure development life cycle",
        "domain": "A.8 Technological controls",
        "metric": "secure_dev",
        "weight": 6,
    },
    {
        "id": "A.5.14",
        "title": "Information transfer",
        "domain": "A.5 Organizational controls",
        "metric": "info_transfer",
        "weight": 5,
    },
    {
        "id": "A.5.23",
        "title": "Information security for use of cloud services",
        "domain": "A.5 Organizational controls",
        "metric": "cloud_security",
        "weight": 6,
    },
]


async def evaluate_iso27001(db: Any) -> dict:
    """Evaluate ISO 27001:2022 compliance based on available scan data.

    Returns a dict with:
    - framework: "ISO 27001:2022"
    - score: int 0-100
    - status: "compliant" | "partial" | "non-compliant"
    - findings: list of control evaluations
    - domains: per-domain score breakdown
    - evaluated_at: ISO timestamp
    """
    from sqlalchemy import func, select

    from netlanventory.models.asset import Asset
    from netlanventory.models.asset_cve import AssetCve
    from netlanventory.models.cve import Cve
    from netlanventory.models.hardening_report import HardeningReport
    from netlanventory.models.ssl_scan_report import SslScanReport

    now = datetime.now(timezone.utc)
    cutoff_30d = now - timedelta(days=30)
    cutoff_90d = now - timedelta(days=90)

    # Gather metrics
    total_assets = (await db.execute(select(func.count()).select_from(Asset))).scalar_one()
    active_assets = (
        await db.execute(
            select(func.count()).select_from(Asset).where(Asset.is_active.is_(True))
        )
    ).scalar_one()

    # Unacknowledged critical CVEs
    critical_unacked = (
        await db.execute(
            select(func.count())
            .select_from(AssetCve)
            .join(Cve, AssetCve.cve_id == Cve.id)
            .where(
                AssetCve.ack_status == "none",
                func.lower(Cve.severity) == "critical",
            )
        )
    ).scalar_one()

    # Recent hardening reports
    hardening_count = (
        await db.execute(
            select(func.count())
            .select_from(HardeningReport)
            .where(
                HardeningReport.status == "completed",
                HardeningReport.created_at >= cutoff_90d,
            )
        )
    ).scalar_one()

    # SSL scans
    ssl_valid = (
        await db.execute(
            select(func.count())
            .select_from(SslScanReport)
            .where(SslScanReport.status == "valid")
        )
    ).scalar_one()

    ssl_expired = (
        await db.execute(
            select(func.count())
            .select_from(SslScanReport)
            .where(SslScanReport.status.in_(["expired", "invalid"]))
        )
    ).scalar_one()

    # Build metrics dict
    metrics = {
        "vuln_management": _score_vuln_management(critical_unacked, active_assets),
        "config_mgmt": _score_config_mgmt(hardening_count, active_assets),
        "secure_auth": 70,  # Partial — JWT auth exists, OIDC optional
        "privileged_access": 75,  # Role-based (admin/user) exists
        "monitoring": 65,  # Audit logging exists
        "network_security": _score_network_security(ssl_valid, ssl_expired, active_assets),
        "web_filtering": 50,  # ZAP scanning exists but partial
        "secure_dev": 60,  # Security headers, input validation
        "info_transfer": 60,  # TLS enforced where scanned
        "cloud_security": 40,  # Cloud discovery optional
    }

    # Evaluate each control
    findings = []
    total_weight = 0
    weighted_score = 0

    for ctrl in _EVALUATABLE_CONTROLS:
        metric_val = metrics.get(ctrl["metric"], 50)
        weight = ctrl["weight"]
        status = "compliant" if metric_val >= 75 else "partial" if metric_val >= 40 else "non-compliant"
        severity = "low" if metric_val >= 75 else "medium" if metric_val >= 40 else "high"

        findings.append({
            "control_id": ctrl["id"],
            "title": ctrl["title"],
            "domain": ctrl["domain"],
            "score": metric_val,
            "status": status,
            "severity": severity,
        })

        total_weight += weight
        weighted_score += metric_val * weight

    overall_score = int(weighted_score / total_weight) if total_weight > 0 else 0

    # Per-domain scores
    domain_scores: dict[str, list[int]] = {d: [] for d in _DOMAINS}
    for f in findings:
        domain = f["domain"]
        if domain in domain_scores:
            domain_scores[domain].append(f["score"])

    domains = {
        d: int(sum(scores) / len(scores)) if scores else 0
        for d, scores in domain_scores.items()
    }

    status_label = (
        "compliant" if overall_score >= 75
        else "partial" if overall_score >= 40
        else "non-compliant"
    )

    return {
        "framework": "ISO 27001:2022",
        "score": overall_score,
        "status": status_label,
        "findings": findings,
        "domains": domains,
        "evaluated_at": now.isoformat(),
        "total_assets": total_assets,
        "critical_unacked_cves": critical_unacked,
    }


def _score_vuln_management(critical_unacked: int, active_assets: int) -> int:
    if active_assets == 0:
        return 100
    ratio = critical_unacked / max(active_assets, 1)
    if ratio == 0:
        return 100
    if ratio < 0.05:
        return 80
    if ratio < 0.2:
        return 50
    return 20


def _score_config_mgmt(hardening_count: int, active_assets: int) -> int:
    if active_assets == 0:
        return 50
    coverage = hardening_count / max(active_assets, 1)
    if coverage >= 0.8:
        return 90
    if coverage >= 0.5:
        return 70
    if coverage >= 0.2:
        return 50
    return 20


def _score_network_security(ssl_valid: int, ssl_expired: int, active_assets: int) -> int:
    if ssl_valid + ssl_expired == 0:
        return 50  # Unknown
    if ssl_expired == 0:
        return 90
    ratio = ssl_expired / (ssl_valid + ssl_expired)
    if ratio < 0.1:
        return 75
    if ratio < 0.3:
        return 50
    return 25
