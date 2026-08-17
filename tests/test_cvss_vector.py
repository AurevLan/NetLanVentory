"""Unit tests for the CVSS vector parser (innovation #6, V2).

Pure functions — no DB, no network. Covers parsing of v3.0/v3.1/v4.0 vectors
and the SSVC-facing derivations (Automatable, Technical Impact), including the
"insufficient data -> None" contract that drives the EPSS / base-score
fallback in core/ssvc.
"""

from __future__ import annotations

import pytest

from netlanventory.core.cvss_vector import (
    is_automatable_from_vector,
    is_total_impact_from_vector,
    parse_vector,
)

# Canonical worm-friendly RCE: network, low complexity, no privs, no UI, all-High.
WORMABLE_V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
# Local, high complexity, requires privileges + user interaction, partial impact.
LOCAL_V31 = "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"
# v4.0 wormable.
WORMABLE_V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


# ── parse_vector ────────────────────────────────────────────────────────────


def test_parse_basic_v31():
    m = parse_vector(WORMABLE_V31)
    assert m["CVSS"] == "3.1"
    assert m["AV"] == "N"
    assert m["AC"] == "L"
    assert m["C"] == "H"


def test_parse_v40_impact_metrics():
    m = parse_vector(WORMABLE_V40)
    assert m["CVSS"] == "4.0"
    assert m["AT"] == "N"
    assert m["VC"] == "H"


@pytest.mark.parametrize("bad", [None, "", "   ", "not-a-vector", "AV:N/AC:L", 1234, "/"])
def test_parse_rejects_garbage(bad):
    assert parse_vector(bad) is None


def test_parse_is_case_insensitive_and_trims():
    m = parse_vector("  cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h  ")
    assert m is not None
    assert m["AV"] == "N" and m["C"] == "H"


# ── is_automatable_from_vector ──────────────────────────────────────────────


def test_automatable_yes_for_wormable_v31():
    assert is_automatable_from_vector(parse_vector(WORMABLE_V31)) is True


def test_automatable_yes_for_wormable_v40():
    assert is_automatable_from_vector(parse_vector(WORMABLE_V40)) is True


def test_automatable_no_for_local_high_complexity():
    assert is_automatable_from_vector(parse_vector(LOCAL_V31)) is False


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",  # high complexity
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",  # needs privileges
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",  # needs user interaction
        "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # physical access
    ],
)
def test_automatable_no_when_any_factor_blocks(vector):
    assert is_automatable_from_vector(parse_vector(vector)) is False


def test_automatable_v40_attack_requirements_block():
    # AT:P (attack requirements present) -> not reliably automatable.
    v = "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    assert is_automatable_from_vector(parse_vector(v)) is False


def test_automatable_none_when_metrics_missing():
    assert is_automatable_from_vector(None) is None
    assert is_automatable_from_vector({"CVSS": "3.1", "AV": "N"}) is None  # no AC/PR/UI


# ── is_total_impact_from_vector ─────────────────────────────────────────────


def test_total_impact_all_high_v31():
    assert is_total_impact_from_vector(parse_vector(WORMABLE_V31)) is True


def test_total_impact_all_high_v40():
    assert is_total_impact_from_vector(parse_vector(WORMABLE_V40)) is True


def test_partial_impact_when_not_all_high():
    assert is_total_impact_from_vector(parse_vector(LOCAL_V31)) is False
    mixed = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
    assert is_total_impact_from_vector(parse_vector(mixed)) is False


def test_total_impact_none_when_missing():
    assert is_total_impact_from_vector(None) is None
    assert is_total_impact_from_vector({"CVSS": "3.1", "AV": "N"}) is None
