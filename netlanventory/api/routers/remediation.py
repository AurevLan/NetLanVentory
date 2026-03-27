"""Remediation plan endpoint.

Aggregates all active (non-dismissed) CVE exposures into prioritised groups so
that security teams can plan remediation work in the most impactful order.

Grouping key: (package_name, fixed_version)
  - Package CVEs: "Update libssl 1.1.0 → 1.1.1w"
  - No-package CVEs: each CVE gets its own group keyed by CVE id

Scoring formula (multiplicative, yields 0–100):
  base  = max_cvss × 10              (0–100 raw)
  score = base
          × (1 + epss_max)           [1.0 – 2.0]  EPSS amplifier
          × kev_mult                 [1.0 or 1.5]  KEV membership
          × (1 + log1p(assets-1))    [≥ 1.0]       breadth (log-scaled)
          × (1 + 0.5 × sla_ratio)   [1.0 – 1.5]   SLA pressure
          × crit_factor              [0.5 – 2.0]   asset criticality
  capped at 100.
"""

from __future__ import annotations

import math
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import get_current_active_user, get_db
from netlanventory.core.risk import _CRITICALITY_FACTORS
from netlanventory.models.asset_cve import AssetCve
from netlanventory.schemas.remediation import RemediationGroup, RemediationPlanResponse

router = APIRouter(prefix="/remediation-plan", tags=["remediation"])

DbDep = Annotated[AsyncSession, Depends(get_db)]

_DISMISSED = {"accepted", "false_positive"}

# Severity ordering for "max criticality" display
_SEV_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "unknown": 0,
}


def _crit_factor(criticality: str | None) -> float:
    return _CRITICALITY_FACTORS.get((criticality or "medium").lower(), 1.0)


def _build_action(package_name: str | None, fixed_version: str | None, cve_ids: list[str]) -> str:
    if package_name and fixed_version:
        return f"Update {package_name} to {fixed_version}"
    if package_name:
        return f"Review and update {package_name}"
    # No-package CVE group (e.g. ZAP / generic findings)
    if len(cve_ids) == 1:
        return f"Investigate and remediate {cve_ids[0]}"
    return f"Investigate and remediate {cve_ids[0]} (+{len(cve_ids) - 1} more)"


@router.get("", response_model=RemediationPlanResponse)
async def get_remediation_plan(
    db: DbDep,
    _current_user: Annotated[object, Depends(get_current_active_user)],
    min_score: float = Query(0.0, ge=0.0, le=100.0, description="Minimum group risk score"),
    source: str | None = Query(None, description="Filter by source (e.g. 'ssh', 'zap', 'nuclei')"),
    only_kev: bool = Query(False, description="Only include groups that contain a KEV CVE"),
    only_sla_breached: bool = Query(False, description="Only include groups with at least one SLA-breached exposure"),
    limit: int = Query(50, ge=1, le=500, description="Max number of groups to return"),
) -> RemediationPlanResponse:
    """Return a prioritised remediation plan grouped by (package, fixed_version).

    Each group represents a single remediation action (e.g. one package upgrade)
    and is scored by impact, breadth, and urgency so teams know where to start.
    """
    # Single query — load all active (non-dismissed) exposures with CVE and Asset
    q = (
        select(AssetCve)
        .where(AssetCve.ack_status.notin_(_DISMISSED))
        .options(
            selectinload(AssetCve.cve),
            selectinload(AssetCve.asset),
        )
    )
    if source:
        q = q.where(AssetCve.source.ilike(f"%{source}%"))

    links: list[AssetCve] = list((await db.execute(q)).scalars().all())

    # ── Group in Python ───────────────────────────────────────────────────────
    # key → { cve_ids, asset_ids, cvss_scores, epss_scores, severity_breakdown,
    #          in_kev, exploit_verified, sla_breached_count, sources,
    #          criticality_scores, package_name, fixed_version }
    groups: dict[tuple, dict] = {}

    for link in links:
        cve = link.cve
        asset = link.asset
        if cve is None or asset is None:
            continue

        # Grouping key: package CVEs → (pkg, fixed_ver); bare CVEs → (None, cve_id_str)
        if link.package_name:
            key = (link.package_name, link.fixed_version or "")
        else:
            key = (None, cve.cve_id)

        if key not in groups:
            groups[key] = {
                "package_name": link.package_name,
                "fixed_version": link.fixed_version if link.package_name else None,
                "cve_ids": set(),
                "asset_ids": set(),
                "cvss_scores": [],
                "epss_scores": [],
                "severity_breakdown": {},
                "in_kev": False,
                "exploit_verified": False,
                "sla_breached_count": 0,
                "sources": set(),
                "criticality_factors": [],
            }

        g = groups[key]
        g["cve_ids"].add(cve.cve_id)
        g["asset_ids"].add(str(asset.id))

        if cve.cvss_score is not None:
            g["cvss_scores"].append(cve.cvss_score)

        epss = cve.epss_score or 0.0
        g["epss_scores"].append(epss)

        sev = (cve.severity or "Unknown").capitalize()
        g["severity_breakdown"][sev] = g["severity_breakdown"].get(sev, 0) + 1

        if cve.kev_date_added is not None:
            g["in_kev"] = True

        if link.exploit_verified:
            g["exploit_verified"] = True

        if link.sla_breached:
            g["sla_breached_count"] += 1

        if link.source:
            g["sources"].add(link.source)

        g["criticality_factors"].append(_crit_factor(asset.criticality))

    # ── Apply post-group filters ──────────────────────────────────────────────
    if only_kev:
        groups = {k: v for k, v in groups.items() if v["in_kev"]}
    if only_sla_breached:
        groups = {k: v for k, v in groups.items() if v["sla_breached_count"] > 0}

    # ── Score each group ──────────────────────────────────────────────────────
    scored: list[tuple[float, dict]] = []
    for g in groups.values():
        max_cvss = max(g["cvss_scores"]) if g["cvss_scores"] else 0.0
        epss_max = max(g["epss_scores"]) if g["epss_scores"] else 0.0
        asset_count = len(g["asset_ids"])
        sla_ratio = g["sla_breached_count"] / max(asset_count, 1)
        crit_factor = max(g["criticality_factors"]) if g["criticality_factors"] else 1.0
        kev_mult = 1.5 if g["in_kev"] else 1.0

        raw = (
            (max_cvss * 10.0)
            * (1.0 + epss_max)
            * kev_mult
            * (1.0 + math.log1p(asset_count - 1))
            * (1.0 + 0.5 * sla_ratio)
            * crit_factor
        )
        score = round(min(raw, 100.0), 2)
        g["_score"] = score
        g["_epss_max"] = epss_max
        scored.append((score, g))

    # ── Filter by min_score and sort descending ───────────────────────────────
    scored = [(s, g) for s, g in scored if s >= min_score]
    scored.sort(key=lambda t: t[0], reverse=True)
    scored = scored[:limit]

    # ── Build response objects ────────────────────────────────────────────────
    result_groups: list[RemediationGroup] = []
    for rank, (score, g) in enumerate(scored, start=1):
        cve_ids_sorted = sorted(g["cve_ids"])
        sources_list = sorted(g["sources"])

        # Max criticality label across assets in this group
        max_crit = max(
            g["severity_breakdown"].keys(),
            key=lambda s: _SEV_RANK.get(s.lower(), 0),
            default="Unknown",
        )

        result_groups.append(
            RemediationGroup(
                rank=rank,
                action=_build_action(g["package_name"], g["fixed_version"], cve_ids_sorted),
                package_name=g["package_name"],
                fixed_version=g["fixed_version"],
                cve_ids=cve_ids_sorted,
                affected_assets=len(g["asset_ids"]),
                asset_ids=sorted(g["asset_ids"]),
                severity_breakdown=g["severity_breakdown"],
                in_kev=g["in_kev"],
                epss_max=round(g["_epss_max"], 4),
                exploit_verified=g["exploit_verified"],
                sla_breached_count=g["sla_breached_count"],
                risk_score=score,
                sources=sources_list,
                criticality_max=max_crit,
            )
        )

    filters_applied = {
        "min_score": min_score,
        "source": source,
        "only_kev": only_kev,
        "only_sla_breached": only_sla_breached,
        "limit": limit,
    }

    return RemediationPlanResponse(
        total_groups=len(result_groups),
        filters_applied=filters_applied,
        groups=result_groups,
    )
