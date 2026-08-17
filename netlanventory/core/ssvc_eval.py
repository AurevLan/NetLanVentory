"""SSVC evaluation glue — bridges the pure tree (core/ssvc) to the DB.

Loads the Cve / Asset / AssetCve facts, reuses the compensating-controls
engine for asset exposure + effective severity, computes the SSVC decision
per (cve, asset), and persists it on `AssetCve` (the source of truth for
patch triage).

Kept separate from `core/ssvc` so the decision tree stays pure and trivially
unit-testable with no DB or network.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.core import ssvc
from netlanventory.core.compensating_controls import (
    ControlContext,
    build_context,
    compute_effective_severity,
)
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve

logger = get_logger(__name__)


def evaluate_pair(
    cve: Cve,
    asset_cve: AssetCve,
    asset: Asset,
    ctx: ControlContext,
) -> ssvc.SsvcResult:
    """Compute the SSVC decision for one (cve, asset) — the single source.

    `ctx` carries the asset exposure (`is_internet_facing`) and lets us derive
    the effective (post-controls) severity for the audit rationale. Used by
    both the per-asset recompute loop and the API endpoint.
    """
    eff = compute_effective_severity(cve, ctx)
    return ssvc.evaluate(
        in_kev=cve.kev_date_added is not None,
        exploit_verified=asset_cve.exploit_verified,
        exploit_maturity=cve.exploit_maturity,
        poc_available=bool(cve.poc_available),
        exploit_db_id=cve.exploit_db_id,
        cvss_score=cve.cvss_score,
        cvss_vector_str=cve.cvss_vector,
        epss_percentile=cve.epss_percentile,
        internet_facing=ctx.is_internet_facing,
        asset_criticality=asset.criticality,
        effective_severity=eff.effective,
    )


async def recompute_for_asset(session: AsyncSession, asset_id: uuid.UUID) -> dict:
    """Recompute & persist the SSVC decision for every CVE on one asset.

    Returns a summary {decision: count, ..., "top": <decision|None>} so the
    caller (scheduler / priority engine) can act on the most urgent decision
    without re-querying.
    """
    asset = (
        await session.execute(
            select(Asset).where(Asset.id == asset_id).options(selectinload(Asset.tags))
        )
    ).scalar_one_or_none()
    if asset is None:
        return {"top": None}

    ctx = await build_context(session, asset)

    rows = (
        await session.execute(
            select(AssetCve, Cve)
            .join(Cve, Cve.id == AssetCve.cve_id)
            .where(AssetCve.asset_id == asset_id)
        )
    ).all()

    now = datetime.now(timezone.utc)
    counts: dict[str, int] = {}
    decisions: list[ssvc.Decision] = []
    for asset_cve, cve in rows:
        result = evaluate_pair(cve, asset_cve, asset, ctx)
        asset_cve.ssvc_decision = result.decision.value
        asset_cve.ssvc_inputs = result.to_dict()
        asset_cve.ssvc_evaluated_at = now
        counts[result.decision.value] = counts.get(result.decision.value, 0) + 1
        decisions.append(result.decision)

    top = ssvc.most_urgent(decisions)
    summary = dict(counts)
    summary["top"] = top.value if top else None
    return summary


async def top_decision_for_asset(
    session: AsyncSession, asset_id: uuid.UUID
) -> ssvc.Decision | None:
    """Read the most urgent stored SSVC decision across an asset's CVEs.

    Reads persisted values only (no recompute) — used by the scan-priority
    engine to inject the SSVC weight into the re-scan score.
    """
    values = (
        await session.execute(
            select(AssetCve.ssvc_decision)
            .where(
                AssetCve.asset_id == asset_id,
                AssetCve.ssvc_decision.isnot(None),
            )
        )
    ).scalars().all()
    decisions = [ssvc.Decision(v) for v in values if v in ssvc.Decision._value2member_map_]
    return ssvc.most_urgent(decisions)
