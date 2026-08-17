"""Tests for core/sla_policy and the SSVC decision-timestamp anchor.

Étape 3: the SLA clock starts at the verdict. The pure rule takes the
earlier of the severity deadline and the verdict deadline; the anchor test
guards the property that makes the verdict deadline stable — the hourly
recompute must not move `ssvc_evaluated_at` while the decision is unchanged.
"""

from __future__ import annotations

from datetime import date, datetime, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.core import ssvc_eval
from netlanventory.core.sla_policy import DECISION_SLA_DAYS, effective_sla_deadline
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve

_DISCOVERED = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)
_DECIDED = datetime(2026, 8, 10, 9, 0, tzinfo=timezone.utc)


class TestEffectiveSlaDeadline:
    def test_severity_only_without_decision(self):
        d = effective_sla_deadline(
            discovered_at=_DISCOVERED, severity_days=30,
            ssvc_decision=None, ssvc_decided_at=None,
        )
        assert d == date(2026, 8, 31)

    def test_act_tightens_late_verdict(self):
        # Medium severity (30 d) but the verdict lands later: act → +1 day.
        d = effective_sla_deadline(
            discovered_at=_DISCOVERED, severity_days=30,
            ssvc_decision="act", ssvc_decided_at=_DECIDED,
        )
        assert d == date(2026, 8, 11)

    def test_severity_wins_when_earlier(self):
        # Critical severity (3 d) beats a later attend verdict (+7 d).
        d = effective_sla_deadline(
            discovered_at=_DISCOVERED, severity_days=3,
            ssvc_decision="attend", ssvc_decided_at=_DECIDED,
        )
        assert d == date(2026, 8, 4)

    def test_track_imposes_nothing(self):
        d = effective_sla_deadline(
            discovered_at=_DISCOVERED, severity_days=90,
            ssvc_decision="track", ssvc_decided_at=_DECIDED,
        )
        assert d == date(2026, 10, 30)
        assert "track" not in DECISION_SLA_DAYS

    def test_decision_without_timestamp_ignored(self):
        d = effective_sla_deadline(
            discovered_at=_DISCOVERED, severity_days=30,
            ssvc_decision="act", ssvc_decided_at=None,
        )
        assert d == date(2026, 8, 31)

    def test_naive_datetimes_accepted(self):
        d = effective_sla_deadline(
            discovered_at=_DISCOVERED.replace(tzinfo=None), severity_days=30,
            ssvc_decision="act", ssvc_decided_at=_DECIDED.replace(tzinfo=None),
        )
        assert d == date(2026, 8, 11)


@pytest.mark.asyncio
async def test_evaluated_at_stable_while_decision_unchanged(db_session: AsyncSession):
    """Two recomputes with identical facts must not move the anchor."""
    asset = Asset(ip="10.99.1.1", name="anchor-host", is_active=True, criticality="critical")
    db_session.add(asset)
    await db_session.flush()

    cve = Cve(
        cve_id="CVE-2025-4242", severity="Critical", cvss_score=9.8,
        epss_percentile=0.99, kev_date_added=date(2025, 1, 1),
    )
    db_session.add(cve)
    await db_session.flush()
    db_session.add(AssetCve(asset_id=asset.id, cve_id=cve.id, source="test"))
    await db_session.flush()

    await ssvc_eval.recompute_for_asset(db_session, asset.id)
    link = (
        await db_session.execute(select(AssetCve).where(AssetCve.asset_id == asset.id))
    ).scalar_one()
    first_decision, first_ts = link.ssvc_decision, link.ssvc_evaluated_at
    assert first_ts is not None

    # recompute mutates the same identity-mapped instance — read it directly
    # (refresh() would reload from DB and discard unflushed changes).
    await ssvc_eval.recompute_for_asset(db_session, asset.id)
    assert link.ssvc_decision == first_decision
    assert link.ssvc_evaluated_at == first_ts

    # A fact change that flips the decision must move the anchor.
    cve.kev_date_added = None
    cve.epss_percentile = 0.0
    cve.exploit_maturity = "none"
    await db_session.flush()
    await ssvc_eval.recompute_for_asset(db_session, asset.id)
    assert link.ssvc_decision != first_decision
    assert link.ssvc_evaluated_at != first_ts
