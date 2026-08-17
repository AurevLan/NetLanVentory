"""Unified prioritization — ONE verdict per (asset, CVE) for the whole app.

Convergence layer (v0.16): before this module, four systems answered "what do
I patch first?" with four different answers (priority-matrix composite score,
SSVC decision, compensating-controls effective severity, smart-scheduler
score). This module merges them into a single `Verdict` that every consumer
(priority matrix, dashboard, executive summary, reports) reads instead of
computing its own:

  - **SSVC decision = backbone.** The CISA tree (core/ssvc) picks the tier:
    act → P1, attend → P2, track* → P3, track → P4. Deterministic, auditable.
  - **Compensating controls = modulator.** A strong post-controls downgrade
    (>= CONTROLS_DEMOTION_POINTS) demotes attend/track* by one tier. An `act`
    is never demoted — active exploitation on a mission-critical target beats
    any compensation. The KEV clamp (max 1.0 downgrade) already prevents KEV
    CVEs from ever reaching the demotion threshold.
  - **EPSS + effective severity = tie-breaker.** Orders entries *within* a
    tier; it never changes the tier itself.
  - **AI triage = optional explanation layer** — deliberately not consumed
    here; the UI fetches it separately when enabled.

The smart re-scan scheduler keeps its own score (core/scan_priority): it
answers "what do I re-scan next?", not "what do I patch first?" — but its
dominant term is already the same SSVC decision, so both rankings agree.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.core import ssvc, ssvc_eval
from netlanventory.core.compensating_controls import (
    EffectiveSeverity,
    build_context,
    compute_effective_severity,
)
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve

# A compensating-controls downgrade of at least this many CVSS points demotes
# the verdict by one tier (attend/track* only — see module docstring).
CONTROLS_DEMOTION_POINTS = 2.0

TIER_BY_DECISION: dict[ssvc.Decision, str] = {
    ssvc.Decision.ACT: "P1",
    ssvc.Decision.ATTEND: "P2",
    ssvc.Decision.TRACK_STAR: "P3",
    ssvc.Decision.TRACK: "P4",
}

_DEMOTED_TIER = {"P2": "P3", "P3": "P4"}

TIER_LABEL = {
    "P1": "<24h",
    "P2": "<7d",
    "P3": "<30d",
    "P4": "backlog",
}

TIER_ACTION = {
    "P1": "Patcher immédiatement — décision SSVC « Act » : exploitation active "
          "sur un périmètre critique.",
    "P2": "Planifier un patch urgent — décision SSVC « Attend » : exploitation "
          "probable ou impact élevé, surveiller de près.",
    "P3": "Inclure dans le prochain cycle de patches — décision SSVC "
          "« Track* » : à suivre avec une attention particulière.",
    "P4": "Traiter en backlog — décision SSVC « Track » : pas d'action "
          "urgente requise.",
}

_DEMOTION_NOTE = (
    "Rétrogradé d'un cran : contrôles compensatoires forts "
    "(-{downgrade:.1f} points de sévérité effective)."
)


@dataclass(frozen=True)
class Verdict:
    """The single patching answer for one (asset, CVE) pair."""

    decision: ssvc.Decision
    tier: str                       # P1..P4, after controls modulation
    sla_label: str                  # "<24h" | "<7d" | "<30d" | "backlog"
    action: str                     # human-readable recommendation
    score: float                    # 0.0–1.0 tie-breaker *within* a tier
    base_severity: float            # raw CVSS
    effective_severity: float       # post compensating-controls
    demoted_by_controls: bool
    decision_source: str            # "stored" | "live"

    @property
    def urgency(self) -> str:
        return ssvc.DECISION_TO_URGENCY[self.decision]


def tie_breaker_score(
    *, epss_percentile: float | None, effective_severity: float
) -> float:
    """Intra-tier ordering: exploitation probability first, then impact left
    after controls. Bounded [0, 1]; never influences the tier."""
    epss = min(max(float(epss_percentile or 0.0), 0.0), 1.0)
    eff = min(max(effective_severity, 0.0), 10.0) / 10.0
    return round(0.6 * epss + 0.4 * eff, 4)


def compute_verdict(
    *,
    decision: ssvc.Decision,
    eff: EffectiveSeverity,
    epss_percentile: float | None,
    decision_source: str = "stored",
) -> Verdict:
    """Pure merge of the SSVC decision and the compensating-controls result."""
    tier = TIER_BY_DECISION[decision]
    demoted = False
    action = TIER_ACTION[tier]
    if tier in _DEMOTED_TIER and eff.downgrade >= CONTROLS_DEMOTION_POINTS:
        note = _DEMOTION_NOTE.format(downgrade=eff.downgrade)
        tier = _DEMOTED_TIER[tier]
        demoted = True
        action = f"{TIER_ACTION[tier]} {note}"

    return Verdict(
        decision=decision,
        tier=tier,
        sla_label=TIER_LABEL[tier],
        action=action,
        score=tie_breaker_score(
            epss_percentile=epss_percentile,
            effective_severity=eff.effective,
        ),
        base_severity=eff.base,
        effective_severity=eff.effective,
        demoted_by_controls=demoted,
        decision_source=decision_source,
    )


# ── ORM glue ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class VerdictEntry:
    """A verdict with the rows it was computed from, for API serialization."""

    link: AssetCve
    cve: Cve
    verdict: Verdict


@dataclass(frozen=True)
class AssetVerdicts:
    asset: Asset
    entries: list[VerdictEntry]


async def verdicts_for_asset(
    session: AsyncSession, asset_id: uuid.UUID
) -> AssetVerdicts | None:
    """Compute the verdict for every CVE on one asset (None if asset missing).

    Uses the SSVC decision persisted by the hourly recompute when present;
    falls back to a live evaluation for pairs not yet visited (fresh scan
    results stay actionable without waiting for the scheduler). Live results
    are not persisted here — this is a read path; the scheduler owns writes.
    """
    asset = (
        await session.execute(
            select(Asset).where(Asset.id == asset_id).options(selectinload(Asset.tags))
        )
    ).scalar_one_or_none()
    if asset is None:
        return None

    ctx = await build_context(session, asset)

    rows = (
        await session.execute(
            select(AssetCve, Cve)
            .join(Cve, Cve.id == AssetCve.cve_id)
            .where(AssetCve.asset_id == asset_id)
        )
    ).all()

    entries: list[VerdictEntry] = []
    for link, cve in rows:
        eff = compute_effective_severity(cve, ctx)
        stored = link.ssvc_decision
        if stored in ssvc.Decision._value2member_map_:
            decision, source = ssvc.Decision(stored), "stored"
        else:
            decision = ssvc_eval.evaluate_pair(cve, link, asset, ctx).decision
            source = "live"
        entries.append(
            VerdictEntry(
                link=link,
                cve=cve,
                verdict=compute_verdict(
                    decision=decision,
                    eff=eff,
                    epss_percentile=cve.epss_percentile,
                    decision_source=source,
                ),
            )
        )
    return AssetVerdicts(asset=asset, entries=entries)


async def open_decision_counts(session: AsyncSession) -> dict[str, int]:
    """Count unacknowledged (asset, CVE) pairs per SSVC decision, fleet-wide.

    Pairs the hourly recompute has not visited yet are reported under
    "unevaluated" so dashboards can show evaluation coverage honestly.
    """
    rows = (
        await session.execute(
            select(AssetCve.ssvc_decision, func.count(AssetCve.id))
            .where(AssetCve.ack_status == "none")
            .group_by(AssetCve.ssvc_decision)
        )
    ).all()
    counts = {d.value: 0 for d in ssvc.Decision}
    counts["unevaluated"] = 0
    for decision, count in rows:
        key = decision if decision in counts else "unevaluated"
        counts[key] += count
    return counts
