"""NIS2 Directive compliance evaluator.

Evaluates the 10 mandatory security measures from the NIS2 Directive
(EU 2022/2555) Article 21. Based on available scan data.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


_NIS2_MEASURES = [
    {
        "id": "NIS2-1",
        "title": "Policies on risk analysis and information system security",
        "article": "Art. 21(2)(a)",
        "metric": "risk_policies",
        "weight": 8,
    },
    {
        "id": "NIS2-2",
        "title": "Incident handling",
        "article": "Art. 21(2)(b)",
        "metric": "incident_handling",
        "weight": 9,
    },
    {
        "id": "NIS2-3",
        "title": "Business continuity and crisis management",
        "article": "Art. 21(2)(c)",
        "metric": "business_continuity",
        "weight": 7,
    },
    {
        "id": "NIS2-4",
        "title": "Supply chain security",
        "article": "Art. 21(2)(d)",
        "metric": "supply_chain",
        "weight": 6,
    },
    {
        "id": "NIS2-5",
        "title": "Security in network and information systems acquisition/development",
        "article": "Art. 21(2)(e)",
        "metric": "secure_dev",
        "weight": 7,
    },
    {
        "id": "NIS2-6",
        "title": "Policies and procedures to assess effectiveness of cybersecurity measures",
        "article": "Art. 21(2)(f)",
        "metric": "effectiveness_assessment",
        "weight": 8,
    },
    {
        "id": "NIS2-7",
        "title": "Basic cyber hygiene practices and training",
        "article": "Art. 21(2)(g)",
        "metric": "cyber_hygiene",
        "weight": 7,
    },
    {
        "id": "NIS2-8",
        "title": "Policies and procedures regarding cryptography",
        "article": "Art. 21(2)(h)",
        "metric": "cryptography",
        "weight": 8,
    },
    {
        "id": "NIS2-9",
        "title": "Human resources security and access control policies",
        "article": "Art. 21(2)(i)",
        "metric": "access_control",
        "weight": 9,
    },
    {
        "id": "NIS2-10",
        "title": "Use of multi-factor authentication and secure communication",
        "article": "Art. 21(2)(j)",
        "metric": "mfa",
        "weight": 9,
    },
]


async def evaluate_nis2(db: Any) -> dict:
    """Evaluate NIS2 Directive compliance based on available scan data."""
    from sqlalchemy import func, select

    from netlanventory.models.asset import Asset
    from netlanventory.models.asset_cve import AssetCve
    from netlanventory.models.audit_log import AuditLog
    from netlanventory.models.cve import Cve
    from netlanventory.models.hardening_report import HardeningReport
    from netlanventory.models.ssh_audit_report import SshAuditReport
    from netlanventory.models.ssl_scan_report import SslScanReport

    now = datetime.now(timezone.utc)

    active_assets = (
        await db.execute(
            select(func.count()).select_from(Asset).where(Asset.is_active.is_(True))
        )
    ).scalar_one()

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

    hardening_count = (
        await db.execute(
            select(func.count())
            .select_from(HardeningReport)
            .where(HardeningReport.status == "completed")
        )
    ).scalar_one()

    audit_events_30d = (
        await db.execute(
            select(func.count())
            .select_from(AuditLog)
        )
    ).scalar_one()

    ssl_expired = (
        await db.execute(
            select(func.count())
            .select_from(SslScanReport)
            .where(SslScanReport.status.in_(["expired", "invalid"]))
        )
    ).scalar_one()

    ssh_audit_count = (
        await db.execute(
            select(func.count())
            .select_from(SshAuditReport)
            .where(SshAuditReport.status == "completed")
        )
    ).scalar_one()

    # Metrics
    metrics = {
        "risk_policies": 50,  # Partially implemented via scan policies
        "incident_handling": 60 if audit_events_30d > 0 else 30,
        "business_continuity": 40,
        "supply_chain": 40,
        "secure_dev": 65,
        "effectiveness_assessment": 70 if hardening_count > 0 else 30,
        "cyber_hygiene": _score_cyber_hygiene(critical_unacked, active_assets),
        "cryptography": 75 if ssl_expired == 0 else 50,
        "access_control": 70,  # JWT + RBAC
        "mfa": 50,  # OIDC available but optional
    }

    findings = []
    total_weight = 0
    weighted_score = 0

    for measure in _NIS2_MEASURES:
        metric_val = metrics.get(measure["metric"], 50)
        weight = measure["weight"]
        status = "compliant" if metric_val >= 75 else "partial" if metric_val >= 40 else "non-compliant"
        severity = "low" if metric_val >= 75 else "medium" if metric_val >= 40 else "high"

        findings.append({
            "control_id": measure["id"],
            "title": measure["title"],
            "article": measure["article"],
            "score": metric_val,
            "status": status,
            "severity": severity,
        })

        total_weight += weight
        weighted_score += metric_val * weight

    overall_score = int(weighted_score / total_weight) if total_weight > 0 else 0
    status_label = (
        "compliant" if overall_score >= 75
        else "partial" if overall_score >= 40
        else "non-compliant"
    )

    return {
        "framework": "NIS2 Directive",
        "score": overall_score,
        "status": status_label,
        "findings": findings,
        "evaluated_at": now.isoformat(),
        "total_active_assets": active_assets,
        "critical_unacked_cves": critical_unacked,
    }


def _score_cyber_hygiene(critical_unacked: int, active_assets: int) -> int:
    if active_assets == 0:
        return 100
    ratio = critical_unacked / max(active_assets, 1)
    if ratio == 0:
        return 95
    if ratio < 0.05:
        return 75
    if ratio < 0.2:
        return 50
    return 25
