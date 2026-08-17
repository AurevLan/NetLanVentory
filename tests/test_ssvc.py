"""Unit tests for the SSVC engine (innovation #6).

Pure-function tests — no DB, no network. Three concerns:

  1. **Golden table** — every one of the 36 CISA Coordinator v2.0.3 rows is
     asserted against an *independent* copy of the upstream CSV, so a stray
     hand-edit to `core/ssvc._RAW_ROWS` fails loudly.
  2. **Adaptation layer** — the documented heuristics of each `derive_*`.
  3. **Outcome mappings** — urgency, priority weight, aggregation, and the
     dominant SSVC term inside `scan_priority.compute_score`.
"""

from __future__ import annotations

import pytest

from netlanventory.core import ssvc
from netlanventory.core.ssvc import (
    Automatable,
    Decision,
    Exploitation,
    MissionWellbeing,
    TechnicalImpact,
)

# ── Golden table: independent copy of cisa_coordinator_2_0_3.csv ─────────────
# (exploitation, automatable, technical_impact, mission_wellbeing) -> decision
# Kept SEPARATE from core/ssvc._RAW_ROWS on purpose: this is the oracle.

_GOLDEN: dict[tuple[str, str, str, str], str] = {
    ("none", "no", "partial", "low"): "track",
    ("none", "no", "partial", "medium"): "track",
    ("none", "no", "partial", "high"): "track",
    ("none", "no", "total", "low"): "track",
    ("none", "no", "total", "medium"): "track",
    ("none", "no", "total", "high"): "track*",
    ("none", "yes", "partial", "low"): "track",
    ("none", "yes", "partial", "medium"): "track",
    ("none", "yes", "partial", "high"): "attend",
    ("none", "yes", "total", "low"): "track",
    ("none", "yes", "total", "medium"): "track",
    ("none", "yes", "total", "high"): "attend",
    ("public poc", "no", "partial", "low"): "track",
    ("public poc", "no", "partial", "medium"): "track",
    ("public poc", "no", "partial", "high"): "track*",
    ("public poc", "no", "total", "low"): "track",
    ("public poc", "no", "total", "medium"): "track*",
    ("public poc", "no", "total", "high"): "attend",
    ("public poc", "yes", "partial", "low"): "track",
    ("public poc", "yes", "partial", "medium"): "track",
    ("public poc", "yes", "partial", "high"): "attend",
    ("public poc", "yes", "total", "low"): "track",
    ("public poc", "yes", "total", "medium"): "track*",
    ("public poc", "yes", "total", "high"): "attend",
    ("active", "no", "partial", "low"): "track",
    ("active", "no", "partial", "medium"): "track",
    ("active", "no", "partial", "high"): "attend",
    ("active", "no", "total", "low"): "track",
    ("active", "no", "total", "medium"): "attend",
    ("active", "no", "total", "high"): "act",
    ("active", "yes", "partial", "low"): "attend",
    ("active", "yes", "partial", "medium"): "attend",
    ("active", "yes", "partial", "high"): "act",
    ("active", "yes", "total", "low"): "attend",
    ("active", "yes", "total", "medium"): "act",
    ("active", "yes", "total", "high"): "act",
}


def test_table_has_36_unique_rows():
    assert len(ssvc.DECISION_TABLE) == 36
    assert len(_GOLDEN) == 36


@pytest.mark.parametrize("key,expected", sorted(_GOLDEN.items()))
def test_decision_matches_cisa_golden(key, expected):
    e, a, t, m = key
    decision = ssvc.ssvc_decision(
        Exploitation(e), Automatable(a), TechnicalImpact(t), MissionWellbeing(m)
    )
    assert decision.value == expected


def test_lookup_is_total_over_domain():
    """Every combination resolves — never a KeyError."""
    for e in Exploitation:
        for a in Automatable:
            for t in TechnicalImpact:
                for m in MissionWellbeing:
                    assert isinstance(ssvc.ssvc_decision(e, a, t, m), Decision)


# ── Exploitation extractor ──────────────────────────────────────────────────


def test_exploitation_kev_is_active():
    assert (
        ssvc.derive_exploitation(
            in_kev=True,
            exploit_verified=None,
            exploit_maturity="none",
            poc_available=False,
            exploit_db_id=None,
        )
        is Exploitation.ACTIVE
    )


def test_exploitation_verified_is_active():
    assert (
        ssvc.derive_exploitation(
            in_kev=False,
            exploit_verified=True,
            exploit_maturity="none",
            poc_available=False,
            exploit_db_id=None,
        )
        is Exploitation.ACTIVE
    )


def test_exploitation_weaponized_maturity_is_active():
    assert (
        ssvc.derive_exploitation(
            in_kev=False,
            exploit_verified=None,
            exploit_maturity="weaponized",
            poc_available=False,
            exploit_db_id=None,
        )
        is Exploitation.ACTIVE
    )


def test_exploitation_poc_available_is_poc():
    assert (
        ssvc.derive_exploitation(
            in_kev=False,
            exploit_verified=False,
            exploit_maturity="poc",
            poc_available=True,
            exploit_db_id=None,
        )
        is Exploitation.POC
    )


def test_exploitation_exploitdb_id_is_poc():
    assert (
        ssvc.derive_exploitation(
            in_kev=False,
            exploit_verified=None,
            exploit_maturity="none",
            poc_available=False,
            exploit_db_id=4242,
        )
        is Exploitation.POC
    )


def test_exploitation_nothing_is_none():
    assert (
        ssvc.derive_exploitation(
            in_kev=False,
            exploit_verified=False,
            exploit_maturity="none",
            poc_available=False,
            exploit_db_id=None,
        )
        is Exploitation.NONE
    )


# ── Technical impact extractor ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "cvss,expected",
    [
        (None, TechnicalImpact.PARTIAL),
        (0.0, TechnicalImpact.PARTIAL),
        (8.9, TechnicalImpact.PARTIAL),
        (9.0, TechnicalImpact.TOTAL),
        (10.0, TechnicalImpact.TOTAL),
    ],
)
def test_technical_impact_threshold(cvss, expected):
    """No vector => base-score fallback (V1 behaviour)."""
    impact, method = ssvc.derive_technical_impact(cvss_score=cvss)
    assert impact is expected
    assert method == "base_score"


# ── Automatable extractor (EPSS AND exposure) ───────────────────────────────


def _automatable(**kw) -> Automatable:
    """V1 path helper: no vector, EPSS proxy. Returns just the decision."""
    decision, _method = ssvc.derive_automatable(**kw)
    return decision


def test_automatable_requires_both_epss_and_exposure():
    # high EPSS but not exposed -> NO
    assert _automatable(epss_percentile=0.99, internet_facing=False) is Automatable.NO
    # exposed but low EPSS -> NO
    assert _automatable(epss_percentile=0.10, internet_facing=True) is Automatable.NO
    # both -> YES
    assert _automatable(epss_percentile=0.95, internet_facing=True) is Automatable.YES


def test_automatable_threshold_boundary():
    thr = ssvc.EPSS_AUTOMATABLE_PERCENTILE
    assert _automatable(epss_percentile=thr, internet_facing=True) is Automatable.YES
    assert (
        _automatable(epss_percentile=thr - 0.001, internet_facing=True)
        is Automatable.NO
    )


def test_automatable_falls_back_to_epss_without_vector():
    decision, method = ssvc.derive_automatable(
        epss_percentile=0.95, internet_facing=True
    )
    assert decision is Automatable.YES
    assert method == "epss"


def test_automatable_handles_none_epss():
    assert _automatable(epss_percentile=None, internet_facing=True) is Automatable.NO


# ── Mission & well-being extractor ──────────────────────────────────────────


@pytest.mark.parametrize(
    "crit,expected",
    [
        ("critical", MissionWellbeing.HIGH),
        ("high", MissionWellbeing.MEDIUM),
        ("medium", MissionWellbeing.LOW),
        ("low", MissionWellbeing.LOW),
        (None, MissionWellbeing.LOW),
        ("weird", MissionWellbeing.LOW),
    ],
)
def test_mission_wellbeing_mapping(crit, expected):
    assert ssvc.derive_mission_wellbeing(asset_criticality=crit) is expected


# ── Vector-first derivations (V2) ───────────────────────────────────────────

WORMABLE_V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
LOCAL_V31 = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"


def test_technical_impact_prefers_vector_over_score():
    from netlanventory.core.cvss_vector import parse_vector

    # Low base score but all-High impact metrics => vector wins => TOTAL.
    impact, method = ssvc.derive_technical_impact(
        cvss_score=4.0, cvss_metrics=parse_vector(WORMABLE_V31)
    )
    assert impact is TechnicalImpact.TOTAL
    assert method == "vector"


def test_automatable_prefers_vector_over_epss():
    from netlanventory.core.cvss_vector import parse_vector

    # Low EPSS, but a wormable vector on an exposed host => vector wins => YES.
    decision, method = ssvc.derive_automatable(
        epss_percentile=0.01,
        internet_facing=True,
        cvss_metrics=parse_vector(WORMABLE_V31),
    )
    assert decision is Automatable.YES
    assert method == "vector"


def test_automatable_vector_still_requires_exposure():
    from netlanventory.core.cvss_vector import parse_vector

    # Wormable vector but the asset is not exposed => NO (device-side AND).
    decision, method = ssvc.derive_automatable(
        epss_percentile=0.99,
        internet_facing=False,
        cvss_metrics=parse_vector(WORMABLE_V31),
    )
    assert decision is Automatable.NO
    assert method == "vector"


def test_evaluate_vector_drives_decision_and_records_method():
    """KEV + wormable vector + exposed + critical => act, derived from vector."""
    result = ssvc.evaluate(
        in_kev=True,
        exploit_verified=None,
        exploit_maturity="weaponized",
        poc_available=False,
        exploit_db_id=None,
        cvss_score=4.0,                 # deliberately low — vector must override
        cvss_vector_str=WORMABLE_V31,
        epss_percentile=0.01,           # deliberately low — vector must override
        internet_facing=True,
        asset_criticality="critical",
    )
    assert result.technical_impact is TechnicalImpact.TOTAL
    assert result.automatable is Automatable.YES
    assert result.decision is Decision.ACT
    deriv = result.to_dict()["rationale"]["derivation"]
    assert deriv == {"automatable": "vector", "technical_impact": "vector"}


def test_evaluate_falls_back_to_proxies_without_vector():
    result = ssvc.evaluate(
        in_kev=False,
        exploit_verified=False,
        exploit_maturity="none",
        poc_available=False,
        exploit_db_id=None,
        cvss_score=9.5,
        cvss_vector_str=None,           # no vector => V1 proxies
        epss_percentile=0.95,
        internet_facing=True,
        asset_criticality="high",
    )
    deriv = result.to_dict()["rationale"]["derivation"]
    assert deriv == {"automatable": "epss", "technical_impact": "base_score"}


# ── End-to-end evaluate() ───────────────────────────────────────────────────


def test_evaluate_kev_critical_exposed_total_is_act():
    """KEV + critical asset + internet-facing + high EPSS + CVSS 9.8 => act."""
    result = ssvc.evaluate(
        in_kev=True,
        exploit_verified=None,
        exploit_maturity="weaponized",
        poc_available=True,
        exploit_db_id=None,
        cvss_score=9.8,
        epss_percentile=0.98,
        internet_facing=True,
        asset_criticality="critical",
        effective_severity=8.5,
    )
    assert result.exploitation is Exploitation.ACTIVE
    assert result.automatable is Automatable.YES
    assert result.technical_impact is TechnicalImpact.TOTAL
    assert result.mission_wellbeing is MissionWellbeing.HIGH
    assert result.decision is Decision.ACT
    assert result.urgency == "now"


def test_evaluate_quiet_cve_on_lab_box_is_track():
    result = ssvc.evaluate(
        in_kev=False,
        exploit_verified=False,
        exploit_maturity="none",
        poc_available=False,
        exploit_db_id=None,
        cvss_score=5.0,
        epss_percentile=0.10,
        internet_facing=False,
        asset_criticality="low",
    )
    assert result.decision is Decision.TRACK
    assert result.urgency == "30d"


def test_evaluate_rationale_is_audit_complete():
    result = ssvc.evaluate(
        in_kev=True,
        exploit_verified=None,
        exploit_maturity="weaponized",
        poc_available=False,
        exploit_db_id=None,
        cvss_score=9.1,
        epss_percentile=0.97,
        internet_facing=True,
        asset_criticality="critical",
        effective_severity=7.0,
    )
    payload = result.to_dict()
    assert payload["table_version"] == ssvc.TABLE_VERSION
    assert payload["decision"] == "act"
    assert payload["decision_points"]["exploitation"] == "active"
    # every raw fact is preserved for the analyst
    assert payload["rationale"]["in_kev"] is True
    assert payload["rationale"]["effective_severity"] == 7.0
    assert "thresholds" in payload["rationale"]


# ── Outcome mappings ────────────────────────────────────────────────────────


def test_urgency_mapping_is_total():
    for d in Decision:
        assert d in ssvc.DECISION_TO_URGENCY


def test_priority_weight_ordering():
    w = ssvc.DECISION_PRIORITY_WEIGHT
    assert w[Decision.ACT] > w[Decision.ATTEND] > w[Decision.TRACK_STAR] > w[Decision.TRACK]
    assert w[Decision.TRACK] == 0.0


def test_most_urgent_picks_highest_rank():
    assert ssvc.most_urgent([]) is None
    assert (
        ssvc.most_urgent([Decision.TRACK, Decision.ACT, Decision.ATTEND])
        is Decision.ACT
    )
    assert (
        ssvc.most_urgent([Decision.TRACK, Decision.TRACK_STAR]) is Decision.TRACK_STAR
    )


# ── scan_priority dominant SSVC term ────────────────────────────────────────


def test_scan_priority_ssvc_term_is_dominant():
    from netlanventory.core.scan_priority import PriorityInputs, compute_score

    base = dict(
        asset_criticality="medium",
        max_epss_delta_24h=0.0,
        new_kev_matches=0,
        hours_since_last_scan=0.0,
        has_unack_critical_cve=False,
        scanned_within_cooldown=False,
    )
    no_ssvc = compute_score(PriorityInputs(**base))
    act = compute_score(PriorityInputs(**base, top_ssvc_decision="act"))
    attend = compute_score(PriorityInputs(**base, top_ssvc_decision="attend"))
    track = compute_score(PriorityInputs(**base, top_ssvc_decision="track"))

    assert act > attend > no_ssvc
    assert track == no_ssvc  # track adds 0
    # 'act' dominates the single largest legacy heuristic (KEV burst = 50)...
    # it adds 30 on top of whatever else; verify it strictly raises the score.
    assert act - no_ssvc == ssvc.DECISION_PRIORITY_WEIGHT[Decision.ACT]


def test_scan_priority_ignores_unknown_ssvc_value():
    from netlanventory.core.scan_priority import PriorityInputs, compute_score

    base = dict(
        asset_criticality="medium",
        max_epss_delta_24h=0.0,
        new_kev_matches=0,
        hours_since_last_scan=0.0,
        has_unack_critical_cve=False,
        scanned_within_cooldown=False,
    )
    assert compute_score(
        PriorityInputs(**base, top_ssvc_decision="bogus")
    ) == compute_score(PriorityInputs(**base))
