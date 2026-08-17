"""Tests for core/prioritization — the unified (asset, CVE) patching verdict.

Pure part: SSVC decision → tier mapping, compensating-controls demotion,
intra-tier tie-breaker. ORM part: verdicts_for_asset (stored vs live SSVC
decision) and open_decision_counts (dashboard/executive aggregate).
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.core import ssvc
from netlanventory.core.compensating_controls import ControlFactor, EffectiveSeverity
from netlanventory.core.prioritization import (
    CONTROLS_DEMOTION_POINTS,
    TIER_LABEL,
    compute_verdict,
    open_decision_counts,
    tie_breaker_score,
    verdicts_for_asset,
)
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve


def _eff(base: float, effective: float) -> EffectiveSeverity:
    factors = []
    if effective != base:
        factors.append(
            ControlFactor(
                rule="test_rule",
                delta=effective - base,
                evidence="test",
                confidence="medium",
            )
        )
    return EffectiveSeverity(base=base, effective=effective, factors=factors)


# ── Decision → tier backbone ──────────────────────────────────────────────────


class TestTierMapping:
    @pytest.mark.parametrize(
        ("decision", "tier"),
        [
            (ssvc.Decision.ACT, "P1"),
            (ssvc.Decision.ATTEND, "P2"),
            (ssvc.Decision.TRACK_STAR, "P3"),
            (ssvc.Decision.TRACK, "P4"),
        ],
    )
    def test_backbone(self, decision, tier):
        v = compute_verdict(
            decision=decision, eff=_eff(8.0, 8.0), epss_percentile=0.5
        )
        assert v.tier == tier
        assert v.sla_label == TIER_LABEL[tier]
        assert v.demoted_by_controls is False

    def test_urgency_follows_decision(self):
        v = compute_verdict(
            decision=ssvc.Decision.ACT, eff=_eff(9.8, 9.8), epss_percentile=0.99
        )
        assert v.urgency == "now"


# ── Compensating-controls modulation ─────────────────────────────────────────


class TestControlsDemotion:
    def test_attend_demoted_to_p3(self):
        v = compute_verdict(
            decision=ssvc.Decision.ATTEND,
            eff=_eff(8.0, 8.0 - CONTROLS_DEMOTION_POINTS),
            epss_percentile=0.5,
        )
        assert v.tier == "P3"
        assert v.sla_label == "<30d"
        assert v.demoted_by_controls is True
        assert "Rétrogradé" in v.action

    def test_track_star_demoted_to_p4(self):
        v = compute_verdict(
            decision=ssvc.Decision.TRACK_STAR,
            eff=_eff(7.5, 4.0),
            epss_percentile=0.5,
        )
        assert v.tier == "P4"
        assert v.demoted_by_controls is True

    def test_act_never_demoted(self):
        v = compute_verdict(
            decision=ssvc.Decision.ACT,
            eff=_eff(9.8, 4.0),
            epss_percentile=0.5,
        )
        assert v.tier == "P1"
        assert v.demoted_by_controls is False

    def test_below_threshold_not_demoted(self):
        v = compute_verdict(
            decision=ssvc.Decision.ATTEND,
            eff=_eff(8.0, 8.0 - CONTROLS_DEMOTION_POINTS + 0.1),
            epss_percentile=0.5,
        )
        assert v.tier == "P2"
        assert v.demoted_by_controls is False

    def test_track_stays_p4(self):
        v = compute_verdict(
            decision=ssvc.Decision.TRACK, eff=_eff(6.0, 2.0), epss_percentile=0.1
        )
        assert v.tier == "P4"
        assert v.demoted_by_controls is False

    def test_upgrade_never_demotes(self):
        # effective > base (rare positive delta) must not trip the demotion
        v = compute_verdict(
            decision=ssvc.Decision.ATTEND, eff=_eff(5.0, 7.0), epss_percentile=0.5
        )
        assert v.tier == "P2"


# ── Intra-tier tie-breaker ────────────────────────────────────────────────────


class TestTieBreaker:
    def test_bounds(self):
        assert tie_breaker_score(epss_percentile=None, effective_severity=0.0) == 0.0
        assert tie_breaker_score(epss_percentile=1.0, effective_severity=10.0) == 1.0

    def test_epss_dominates_severity(self):
        high_epss = tie_breaker_score(epss_percentile=0.95, effective_severity=5.0)
        high_sev = tie_breaker_score(epss_percentile=0.30, effective_severity=9.8)
        assert high_epss > high_sev

    def test_severity_breaks_equal_epss(self):
        a = tie_breaker_score(epss_percentile=0.5, effective_severity=9.0)
        b = tie_breaker_score(epss_percentile=0.5, effective_severity=4.0)
        assert a > b

    def test_uses_effective_not_base(self):
        v = compute_verdict(
            decision=ssvc.Decision.ATTEND, eff=_eff(9.8, 3.0), epss_percentile=0.0
        )
        assert v.score == tie_breaker_score(
            epss_percentile=0.0, effective_severity=3.0
        )


# ── ORM glue ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_verdicts_for_asset_missing(db_session: AsyncSession):
    import uuid

    assert await verdicts_for_asset(db_session, uuid.uuid4()) is None


@pytest.mark.asyncio
async def test_verdicts_stored_and_live(db_session: AsyncSession):
    """Stored SSVC decisions are trusted; unevaluated pairs get a live one."""
    asset = Asset(ip="10.99.0.1", name="verdict-host", is_active=True, criticality="critical")
    db_session.add(asset)
    await db_session.flush()

    stored_cve = Cve(cve_id="CVE-2025-1111", severity="High", cvss_score=8.0)
    live_cve = Cve(cve_id="CVE-2025-2222", severity="Critical", cvss_score=9.8)
    db_session.add_all([stored_cve, live_cve])
    await db_session.flush()

    db_session.add_all([
        AssetCve(
            asset_id=asset.id, cve_id=stored_cve.id, source="test",
            ssvc_decision="attend",
        ),
        AssetCve(asset_id=asset.id, cve_id=live_cve.id, source="test"),
    ])
    await db_session.flush()

    result = await verdicts_for_asset(db_session, asset.id)
    assert result is not None
    assert result.asset.id == asset.id
    by_cve = {e.cve.cve_id: e.verdict for e in result.entries}

    stored_v = by_cve["CVE-2025-1111"]
    assert stored_v.decision is ssvc.Decision.ATTEND
    assert stored_v.decision_source == "stored"
    assert stored_v.tier == "P2"

    live_v = by_cve["CVE-2025-2222"]
    assert live_v.decision_source == "live"
    # No KEV / exploit / PoC facts → exploitation "none" → track family
    assert live_v.decision in (ssvc.Decision.TRACK, ssvc.Decision.TRACK_STAR)


@pytest.mark.asyncio
async def test_open_decision_counts(db_session: AsyncSession):
    asset = Asset(ip="10.99.0.2", name="counts-host", is_active=True)
    db_session.add(asset)
    await db_session.flush()

    rows = []
    for i, (decision, ack) in enumerate([
        ("act", "none"),
        ("act", "accepted"),      # acked → excluded
        ("attend", "none"),
        (None, "none"),           # not yet evaluated
    ]):
        cve = Cve(cve_id=f"CVE-2025-30{i:02d}", severity="High", cvss_score=7.0)
        db_session.add(cve)
        await db_session.flush()
        rows.append(
            AssetCve(
                asset_id=asset.id, cve_id=cve.id, source="test",
                ssvc_decision=decision, ack_status=ack,
            )
        )
    db_session.add_all(rows)
    await db_session.flush()

    counts = await open_decision_counts(db_session)
    assert counts["act"] == 1
    assert counts["attend"] == 1
    assert counts["unevaluated"] == 1
    assert counts["track"] == 0
    assert counts["track*"] == 0
