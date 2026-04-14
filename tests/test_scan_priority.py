"""Unit tests for the smart re-scan scoring formula.

Pure-function tests — no DB. Exercises every weighting factor of
`compute_score()` independently, then a few stacking scenarios.
"""

from __future__ import annotations

import pytest

from netlanventory.core.scan_priority import (
    COOLDOWN_PENALTY,
    CRITICALITY_WEIGHT,
    PriorityInputs,
    WEIGHT_AGE_PER_HOUR,
    WEIGHT_EPSS_DELTA,
    WEIGHT_NEW_KEV,
    WEIGHT_UNACK_CRITICAL,
    compute_score,
)


def _baseline(**overrides) -> PriorityInputs:
    defaults = dict(
        asset_criticality="medium",
        max_epss_delta_24h=0.0,
        new_kev_matches=0,
        hours_since_last_scan=0.0,
        has_unack_critical_cve=False,
        scanned_within_cooldown=False,
    )
    defaults.update(overrides)
    return PriorityInputs(**defaults)


def test_baseline_score_is_two():
    """1.0 base + 1.0 medium criticality = 2.0."""
    assert compute_score(_baseline()) == 2.0


def test_low_criticality_score_is_one():
    """1.0 base + 0.0 low criticality = 1.0."""
    assert compute_score(_baseline(asset_criticality="low")) == 1.0


def test_critical_criticality_adds_5():
    score = compute_score(_baseline(asset_criticality="critical"))
    assert score == 1.0 + CRITICALITY_WEIGHT["critical"]
    assert score == 6.0


def test_unknown_criticality_falls_back_to_medium_weight():
    """Unknown values use 1.0 (medium) — defensive default."""
    assert compute_score(_baseline(asset_criticality="weird")) == 2.0


def test_epss_delta_contributes_linearly():
    score = compute_score(_baseline(max_epss_delta_24h=0.5))
    # baseline 2.0 + 5.0 * 0.5 = 4.5
    assert score == 2.0 + WEIGHT_EPSS_DELTA * 0.5


def test_negative_epss_delta_is_clamped():
    score = compute_score(_baseline(max_epss_delta_24h=-1.0))
    assert score == 2.0  # clamped at 0


def test_new_kev_matches_capped_at_5():
    """Score boost from new KEV matches caps at 5 hits."""
    s_one = compute_score(_baseline(new_kev_matches=1))
    s_five = compute_score(_baseline(new_kev_matches=5))
    s_huge = compute_score(_baseline(new_kev_matches=999))
    assert s_one == 2.0 + WEIGHT_NEW_KEV
    assert s_five == 2.0 + WEIGHT_NEW_KEV * 5
    assert s_huge == s_five  # capped


def test_age_per_hour_contributes():
    score = compute_score(_baseline(hours_since_last_scan=20))
    assert score == 2.0 + WEIGHT_AGE_PER_HOUR * 20


def test_negative_age_clamped():
    score = compute_score(_baseline(hours_since_last_scan=-5))
    assert score == 2.0


def test_unack_critical_cve_adds_8():
    score = compute_score(_baseline(has_unack_critical_cve=True))
    assert score == 2.0 + WEIGHT_UNACK_CRITICAL


def test_cooldown_penalty_applied_then_clamped():
    """Cooldown subtracts COOLDOWN_PENALTY, final score clamped to >= 0."""
    score = compute_score(_baseline(scanned_within_cooldown=True))
    raw = 2.0 + COOLDOWN_PENALTY  # 2.0 + (-5.0) = -3.0
    assert raw < 0
    assert score == max(0.0, raw)
    assert score == 0.0


def test_cooldown_offset_by_high_criticality():
    """A critical asset still keeps a positive score even in cooldown."""
    score = compute_score(
        _baseline(asset_criticality="critical", scanned_within_cooldown=True)
    )
    # 1.0 + 5.0 (critical) + (-5.0) cooldown = 1.0
    assert score == 1.0


def test_full_stacking_realistic_scenario():
    """A critical asset with KEV, fresh CVE and 48h old scan should be hot."""
    score = compute_score(
        _baseline(
            asset_criticality="critical",
            max_epss_delta_24h=0.8,
            new_kev_matches=2,
            hours_since_last_scan=48,
            has_unack_critical_cve=True,
            scanned_within_cooldown=False,
        )
    )
    expected = (
        1.0                                 # base
        + WEIGHT_EPSS_DELTA * 0.8           # +4.0
        + WEIGHT_NEW_KEV * 2                # +20.0
        + WEIGHT_AGE_PER_HOUR * 48          # +2.4
        + CRITICALITY_WEIGHT["critical"]    # +5.0
        + WEIGHT_UNACK_CRITICAL             # +8.0
    )
    assert score == pytest.approx(expected)
    assert score > 30  # this asset must be near the top of the queue


def test_two_assets_ordering():
    """A critical asset under attack must outrank a low one with stale scan."""
    hot = compute_score(
        _baseline(asset_criticality="critical", new_kev_matches=1, has_unack_critical_cve=True)
    )
    cold = compute_score(
        _baseline(asset_criticality="low", hours_since_last_scan=30)
    )
    assert hot > cold
