"""Priority matrix router — returns CVEs for an asset sorted by composite exploitability risk.

Combines KEV (Known Exploited), EPSS percentile, exploit_verified status, and CVSS score
into a weighted composite score, then groups CVEs into 4 priority tiers:

  P1 (Immediate <24h)  — KEV + actively exploitable or very high EPSS
  P2 (High <7d)        — Exploitable or high EPSS + CVSS >= 7
  P3 (Medium <30d)     — CVSS >= 7 without confirmed exploit
  P4 (Low / Backlog)   — Everything else
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import get_current_active_user, get_db
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve

router = APIRouter(prefix="/assets/{asset_id}/priority-matrix", tags=["priority-matrix"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]


# ── Schemas ───────────────────────────────────────────────────────────────────

class PriorityEntry(BaseModel):
    asset_cve_id: uuid.UUID
    cve_id: str
    tier: str                       # P1 / P2 / P3 / P4
    score: float                    # 0.0–1.0 composite
    kev: bool
    epss_percentile: float | None
    epss_score: float | None
    exploit_verified: bool | None
    cvss_score: float | None
    severity: str | None
    package_name: str | None
    package_version: str | None
    fixed_version: str | None
    source: str | None
    sla_deadline_label: str         # "<24h" | "<7d" | "<30d" | "backlog"
    remediation_action: str         # Human-readable recommended action


class PriorityMatrixOut(BaseModel):
    asset_id: uuid.UUID
    asset_ip: str | None
    asset_name: str | None
    P1: list[PriorityEntry]
    P2: list[PriorityEntry]
    P3: list[PriorityEntry]
    P4: list[PriorityEntry]
    total: int
    generated_at: datetime


# ── Scoring logic ─────────────────────────────────────────────────────────────

def _composite_score(link: AssetCve, cve: Cve) -> float:
    """Weighted composite score [0.0–1.0].

    Weights:
      KEV presence         40% — being in CISA KEV means actively exploited in the wild
      EPSS percentile      30% — probability of exploitation in the next 30 days
      exploit_verified     20% — Nuclei or Metasploit confirmed exploitability
      CVSS score norm.     10% — base severity as tiebreaker
    """
    kev = 1.0 if cve.kev_date_added else 0.0
    epss = float(cve.epss_percentile or 0.0)
    expl = 1.0 if link.exploit_verified is True else 0.0
    cvss_norm = min(float(cve.cvss_score or 0.0) / 10.0, 1.0)
    return round(0.40 * kev + 0.30 * epss + 0.20 * expl + 0.10 * cvss_norm, 4)


def _tier(link: AssetCve, cve: Cve) -> str:
    """Classify into priority tier P1–P4."""
    is_kev = bool(cve.kev_date_added)
    is_expl = link.exploit_verified is True
    epss_high = float(cve.epss_percentile or 0.0) > 0.5
    cvss_high = float(cve.cvss_score or 0.0) >= 7.0

    if is_kev and (is_expl or epss_high):
        return "P1"
    if (is_expl or epss_high) and cvss_high:
        return "P2"
    if cvss_high:
        return "P3"
    return "P4"


_TIER_LABEL = {
    "P1": "<24h",
    "P2": "<7d",
    "P3": "<30d",
    "P4": "backlog",
}

_TIER_ACTION = {
    "P1": "Patch immédiatement — vulnérabilité confirmée exploitée dans la nature (KEV + exploit confirmé / EPSS élevé).",
    "P2": "Planifier un patch urgent — exploitabilité confirmée ou très probable, criticité élevée.",
    "P3": "Inclure dans le prochain cycle de patches — CVSS ≥ 7 sans exploit confirmé.",
    "P4": "Traiter en backlog — faible probabilité d'exploitation ou impact limité.",
}


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.get("", response_model=PriorityMatrixOut)
async def get_priority_matrix(
    asset_id: uuid.UUID,
    db: DbDep,
    _user: UserDep,
) -> PriorityMatrixOut:
    """Return a prioritised CVE remediation matrix for an asset.

    CVEs are grouped into 4 tiers (P1–P4) using a composite score combining
    KEV status, EPSS percentile, confirmed exploitability, and CVSS score.
    Within each tier, CVEs are sorted by composite score descending.
    """
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Load all CVE links with the related Cve row
    cve_result = await db.execute(
        select(AssetCve)
        .where(AssetCve.asset_id == asset_id)
        .options(selectinload(AssetCve.cve))
    )
    links = list(cve_result.scalars().all())

    tiers: dict[str, list[PriorityEntry]] = {"P1": [], "P2": [], "P3": [], "P4": []}

    for link in links:
        cve: Cve | None = link.cve
        if not cve:
            continue

        score = _composite_score(link, cve)
        tier = _tier(link, cve)

        entry = PriorityEntry(
            asset_cve_id=link.id,
            cve_id=cve.cve_id,
            tier=tier,
            score=score,
            kev=bool(cve.kev_date_added),
            epss_percentile=cve.epss_percentile,
            epss_score=cve.epss_score,
            exploit_verified=link.exploit_verified,
            cvss_score=cve.cvss_score,
            severity=cve.severity,
            package_name=link.package_name,
            package_version=link.package_version,
            fixed_version=link.fixed_version,
            source=link.source,
            sla_deadline_label=_TIER_LABEL[tier],
            remediation_action=_TIER_ACTION[tier],
        )
        tiers[tier].append(entry)

    # Sort each tier by composite score descending
    for tier_list in tiers.values():
        tier_list.sort(key=lambda e: e.score, reverse=True)

    total = sum(len(v) for v in tiers.values())

    return PriorityMatrixOut(
        asset_id=asset_id,
        asset_ip=asset.ip,
        asset_name=asset.name,
        P1=tiers["P1"],
        P2=tiers["P2"],
        P3=tiers["P3"],
        P4=tiers["P4"],
        total=total,
        generated_at=datetime.now(timezone.utc),
    )
