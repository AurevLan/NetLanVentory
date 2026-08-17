"""Priority matrix router — the unified patching verdict, grouped by tier.

Since v0.16 the tiers are the SSVC decision re-expressed (act → P1,
attend → P2, track* → P3, track → P4), modulated by compensating controls
and ordered by the EPSS/effective-severity tie-breaker — all computed by
`core/prioritization`, the single source of truth also feeding the dashboard
and executive summary. The endpoint shape is unchanged; SSVC fields are
additive.

  P1 (Immediate <24h)  — SSVC Act
  P2 (High <7d)        — SSVC Attend
  P3 (Medium <30d)     — SSVC Track*
  P4 (Low / Backlog)   — SSVC Track
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_current_active_user, get_db
from netlanventory.core.prioritization import verdicts_for_asset

router = APIRouter(prefix="/assets/{asset_id}/priority-matrix", tags=["priority-matrix"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]


# ── Schemas ───────────────────────────────────────────────────────────────────

class PriorityEntry(BaseModel):
    asset_cve_id: uuid.UUID
    cve_id: str
    tier: str                       # P1 / P2 / P3 / P4
    score: float                    # 0.0–1.0 intra-tier tie-breaker
    ssvc_decision: str              # track | track* | attend | act
    ssvc_source: str                # stored | live
    effective_severity: float       # post compensating-controls CVSS
    demoted_by_controls: bool
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


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.get("", response_model=PriorityMatrixOut)
async def get_priority_matrix(
    asset_id: uuid.UUID,
    db: DbDep,
    _user: UserDep,
) -> PriorityMatrixOut:
    """Return the prioritised CVE remediation matrix for an asset.

    Tiers come from the unified verdict (SSVC backbone, compensating-controls
    modulation); within each tier entries are sorted by the tie-breaker score
    descending.
    """
    result = await verdicts_for_asset(db, asset_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    tiers: dict[str, list[PriorityEntry]] = {"P1": [], "P2": [], "P3": [], "P4": []}

    for e in result.entries:
        v = e.verdict
        tiers[v.tier].append(
            PriorityEntry(
                asset_cve_id=e.link.id,
                cve_id=e.cve.cve_id,
                tier=v.tier,
                score=v.score,
                ssvc_decision=v.decision.value,
                ssvc_source=v.decision_source,
                effective_severity=v.effective_severity,
                demoted_by_controls=v.demoted_by_controls,
                kev=bool(e.cve.kev_date_added),
                epss_percentile=e.cve.epss_percentile,
                epss_score=e.cve.epss_score,
                exploit_verified=e.link.exploit_verified,
                cvss_score=e.cve.cvss_score,
                severity=e.cve.severity,
                package_name=e.link.package_name,
                package_version=e.link.package_version,
                fixed_version=e.link.fixed_version,
                source=e.link.source,
                sla_deadline_label=v.sla_label,
                remediation_action=v.action,
            )
        )

    for tier_list in tiers.values():
        tier_list.sort(key=lambda entry: entry.score, reverse=True)

    return PriorityMatrixOut(
        asset_id=asset_id,
        asset_ip=result.asset.ip,
        asset_name=result.asset.name,
        P1=tiers["P1"],
        P2=tiers["P2"],
        P3=tiers["P3"],
        P4=tiers["P4"],
        total=sum(len(v) for v in tiers.values()),
        generated_at=datetime.now(timezone.utc),
    )
