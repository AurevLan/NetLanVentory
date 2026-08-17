"""Prioritization router — the fleet-wide « À traiter » (to-treat) feed.

Backs the home view (étape 2 of the v0.16 convergence): headline counts plus
the ranked list of open (asset, CVE) exposures, ordered by the unified verdict
from `core/prioritization` (SSVC decision first, tie-breaker second).

Only pairs with a stored SSVC decision are listed — the hourly scheduler
recompute owns evaluation; pairs it has not visited yet are surfaced through
`counts.unevaluated` so the UI can report coverage honestly instead of
silently hiding them. (The per-asset priority matrix, by contrast, evaluates
live: its scope is one asset, this feed is the whole fleet.)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import get_current_active_user, get_db
from netlanventory.core import ssvc
from netlanventory.core.compensating_controls import (
    build_context,
    compute_effective_severity,
)
from netlanventory.core.prioritization import compute_verdict, open_decision_counts
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.asset_tag import AssetTag
from netlanventory.models.cve import Cve

router = APIRouter(prefix="/prioritization", tags=["prioritization"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]

# Tags that mark an asset as internet-facing (same convention as
# compensating_controls.build_context).
_INTERNET_TAGS = ("internet-facing", "public")

_DECISION_RANK_SQL = case(
    (AssetCve.ssvc_decision == "act", 3),
    (AssetCve.ssvc_decision == "attend", 2),
    (AssetCve.ssvc_decision == "track*", 1),
    else_=0,
)


# ── Schemas ───────────────────────────────────────────────────────────────────

class TodoCounts(BaseModel):
    act_open: int
    attend_open: int
    internet_facing_open: int
    sla_breached: int
    unevaluated: int


class TodoItem(BaseModel):
    asset_cve_id: uuid.UUID
    asset_id: uuid.UUID
    asset_ip: str | None
    asset_name: str | None
    asset_criticality: str
    internet_facing: bool
    cve_id: str
    severity: str | None
    cvss_score: float | None
    effective_severity: float
    epss_percentile: float | None
    kev: bool
    exploit_verified: bool | None
    package_name: str | None
    fixed_version: str | None
    decision: str                   # act | attend | track* | track
    ssvc_source: str                # always "stored" in this feed
    tier: str                       # P1..P4
    sla_label: str
    score: float
    demoted_by_controls: bool
    action: str
    reasons: list[str]


class TodoOut(BaseModel):
    counts: TodoCounts
    total_open: int
    items: list[TodoItem]
    generated_at: datetime


# ── Helpers ───────────────────────────────────────────────────────────────────

def _reasons(
    *,
    kev: bool,
    exploit_verified: bool | None,
    internet_facing: bool,
    criticality: str,
    demoted: bool,
    fixed_version: str | None,
) -> list[str]:
    reasons: list[str] = []
    if kev:
        reasons.append("Exploitée dans la nature (KEV)")
    if exploit_verified is True:
        reasons.append("Exploit vérifié sur cet asset")
    if internet_facing:
        reasons.append("Exposé à Internet")
    if criticality == "critical":
        reasons.append("Asset critique")
    elif criticality == "high":
        reasons.append("Asset à criticité élevée")
    if demoted:
        reasons.append("Rétrogradée : contrôles compensatoires")
    if fixed_version:
        reasons.append(f"Correctif disponible ({fixed_version})")
    return reasons


# ── Endpoint ──────────────────────────────────────────────────────────────────

@router.get("/todo", response_model=TodoOut)
async def get_todo(
    db: DbDep,
    _user: UserDep,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> TodoOut:
    """Return the ranked fleet-wide patching to-do list plus headline counts."""
    decision_counts = await open_decision_counts(db)

    total_open = (
        await db.execute(
            select(func.count()).select_from(AssetCve).where(AssetCve.ack_status == "none")
        )
    ).scalar_one()

    sla_breached = (
        await db.execute(
            select(func.count())
            .select_from(AssetCve)
            .where(AssetCve.ack_status == "none", AssetCve.sla_breached.is_(True))
        )
    ).scalar_one()

    internet_asset_ids = (
        select(AssetTag.asset_id)
        .where(func.lower(AssetTag.name).in_(_INTERNET_TAGS))
        .scalar_subquery()
    )
    internet_facing_open = (
        await db.execute(
            select(func.count())
            .select_from(AssetCve)
            .where(
                AssetCve.ack_status == "none",
                AssetCve.asset_id.in_(internet_asset_ids),
            )
        )
    ).scalar_one()

    # The ranked slice: SQL pre-sort by decision rank then EPSS, then the
    # exact verdict (controls modulation + tie-breaker) refines the page.
    rows = (
        await db.execute(
            select(AssetCve, Cve, Asset)
            .join(Cve, Cve.id == AssetCve.cve_id)
            .join(Asset, Asset.id == AssetCve.asset_id)
            .where(
                AssetCve.ack_status == "none",
                AssetCve.ssvc_decision.isnot(None),
            )
            .order_by(
                _DECISION_RANK_SQL.desc(),
                Cve.epss_percentile.desc().nullslast(),
            )
            .limit(limit)
        )
    ).all()

    # One compensating-controls context per distinct asset in the slice.
    asset_ids = {asset.id for _, _, asset in rows}
    contexts = {}
    if asset_ids:
        assets = (
            await db.execute(
                select(Asset)
                .where(Asset.id.in_(asset_ids))
                .options(selectinload(Asset.tags))
            )
        ).scalars().all()
        for asset in assets:
            contexts[asset.id] = await build_context(db, asset)

    items: list[TodoItem] = []
    for link, cve, asset in rows:
        if link.ssvc_decision not in ssvc.Decision._value2member_map_:
            continue
        ctx = contexts[asset.id]
        eff = compute_effective_severity(cve, ctx)
        verdict = compute_verdict(
            decision=ssvc.Decision(link.ssvc_decision),
            eff=eff,
            epss_percentile=cve.epss_percentile,
        )
        criticality = (asset.criticality or "medium").lower()
        items.append(
            TodoItem(
                asset_cve_id=link.id,
                asset_id=asset.id,
                asset_ip=asset.ip,
                asset_name=asset.name,
                asset_criticality=criticality,
                internet_facing=ctx.is_internet_facing,
                cve_id=cve.cve_id,
                severity=cve.severity,
                cvss_score=cve.cvss_score,
                effective_severity=verdict.effective_severity,
                epss_percentile=cve.epss_percentile,
                kev=bool(cve.kev_date_added),
                exploit_verified=link.exploit_verified,
                package_name=link.package_name,
                fixed_version=link.fixed_version,
                decision=verdict.decision.value,
                ssvc_source="stored",
                tier=verdict.tier,
                sla_label=verdict.sla_label,
                score=verdict.score,
                demoted_by_controls=verdict.demoted_by_controls,
                action=verdict.action,
                reasons=_reasons(
                    kev=bool(cve.kev_date_added),
                    exploit_verified=link.exploit_verified,
                    internet_facing=ctx.is_internet_facing,
                    criticality=criticality,
                    demoted=verdict.demoted_by_controls,
                    fixed_version=link.fixed_version,
                ),
            )
        )

    items.sort(
        key=lambda i: (ssvc.DECISION_RANK[ssvc.Decision(i.decision)], i.score),
        reverse=True,
    )

    return TodoOut(
        counts=TodoCounts(
            act_open=decision_counts["act"],
            attend_open=decision_counts["attend"],
            internet_facing_open=internet_facing_open,
            sla_breached=sla_breached,
            unevaluated=decision_counts["unevaluated"],
        ),
        total_open=total_open,
        items=items,
        generated_at=datetime.now(timezone.utc),
    )
