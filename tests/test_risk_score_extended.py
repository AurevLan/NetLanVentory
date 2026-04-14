"""Unit tests for the extended risk score computation.

Tests the new penalty parameters added for internal audit features:
  - privesc_risk_count
  - firewall_active
  - rootkit_infected_count
  - brute_force_sources
"""

from __future__ import annotations

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-unit-tests")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-for-tests")
os.environ.setdefault("ADMIN_PASSWORD", "Test1234!@#$")
os.environ.setdefault("APP_DEBUG", "true")

import pytest

from netlanventory.core.risk import compute_risk_score


class TestRiskScoreBaseline:
    """Verify existing behavior is unchanged."""

    def test_zero_score_when_no_data(self):
        score = compute_risk_score("medium", [], 0)
        assert score == 0.0

    def test_base_score_from_cvss(self):
        score = compute_risk_score("medium", [7.5], 0)
        assert 0 < score < 100

    def test_criticality_amplifies(self):
        medium = compute_risk_score("medium", [7.5], 0)
        critical = compute_risk_score("critical", [7.5], 0)
        assert critical > medium

    def test_exposure_amplifies(self):
        few_ports = compute_risk_score("medium", [7.5], 2)
        many_ports = compute_risk_score("medium", [7.5], 20)
        assert many_ports > few_ports

    def test_default_creds_penalty(self):
        without = compute_risk_score("medium", [], 0)
        with_dc = compute_risk_score("medium", [], 0, default_creds_vulnerable_count=1)
        assert with_dc > without
        assert with_dc >= 35.0

    def test_max_score_capped_at_100(self):
        score = compute_risk_score(
            "critical", [10.0], 30,
            default_creds_vulnerable_count=4,
            exploit_verified_count=3,
            ssh_audit_critical_count=3,
            testssl_grade="F",
            privesc_risk_count=5,
            firewall_active=False,
            rootkit_infected_count=3,
            brute_force_sources=5,
        )
        assert score == 100.0


class TestPrivescRiskPenalty:
    def test_no_privesc_no_penalty(self):
        base = compute_risk_score("medium", [], 0)
        with_zero = compute_risk_score("medium", [], 0, privesc_risk_count=0)
        assert base == with_zero

    def test_single_privesc_risk(self):
        without = compute_risk_score("medium", [], 0)
        with_one = compute_risk_score("medium", [], 0, privesc_risk_count=1)
        assert with_one > without
        assert with_one - without == pytest.approx(10.0, abs=0.1)

    def test_multiple_privesc_risks(self):
        one = compute_risk_score("medium", [], 0, privesc_risk_count=1)
        three = compute_risk_score("medium", [], 0, privesc_risk_count=3)
        assert three > one

    def test_privesc_with_criticality(self):
        medium = compute_risk_score("medium", [], 0, privesc_risk_count=3)
        critical = compute_risk_score("critical", [], 0, privesc_risk_count=3)
        assert critical > medium


class TestFirewallPenalty:
    def test_no_firewall_data_no_penalty(self):
        base = compute_risk_score("medium", [], 0)
        none_fw = compute_risk_score("medium", [], 0, firewall_active=None)
        assert base == none_fw

    def test_firewall_active_no_penalty(self):
        base = compute_risk_score("medium", [], 0)
        active = compute_risk_score("medium", [], 0, firewall_active=True)
        assert base == active

    def test_no_firewall_adds_penalty(self):
        base = compute_risk_score("medium", [], 0)
        inactive = compute_risk_score("medium", [], 0, firewall_active=False)
        assert inactive > base
        assert inactive - base == pytest.approx(15.0, abs=0.1)

    def test_no_firewall_with_cves(self):
        with_fw = compute_risk_score("medium", [9.0], 5, firewall_active=True)
        without_fw = compute_risk_score("medium", [9.0], 5, firewall_active=False)
        assert without_fw > with_fw


class TestRootkitPenalty:
    def test_no_rootkit_no_penalty(self):
        base = compute_risk_score("medium", [], 0)
        clean = compute_risk_score("medium", [], 0, rootkit_infected_count=0)
        assert base == clean

    def test_single_rootkit_infection(self):
        base = compute_risk_score("medium", [], 0)
        infected = compute_risk_score("medium", [], 0, rootkit_infected_count=1)
        assert infected > base
        assert infected - base == pytest.approx(30.0, abs=0.1)

    def test_multiple_infections_increase_penalty(self):
        one = compute_risk_score("medium", [], 0, rootkit_infected_count=1)
        three = compute_risk_score("medium", [], 0, rootkit_infected_count=3)
        assert three > one

    def test_rootkit_is_severe(self):
        """Rootkit penalty (30+) should be close to default_creds (35+)."""
        rootkit = compute_risk_score("medium", [], 0, rootkit_infected_count=1)
        default_creds = compute_risk_score("medium", [], 0, default_creds_vulnerable_count=1)
        # Both are severe; rootkit is slightly less than default_creds
        assert rootkit >= 25.0
        assert default_creds >= 30.0


class TestBruteForcePenalty:
    def test_no_brute_force_no_penalty(self):
        base = compute_risk_score("medium", [], 0)
        clean = compute_risk_score("medium", [], 0, brute_force_sources=0)
        assert base == clean

    def test_single_source(self):
        base = compute_risk_score("medium", [], 0)
        bf = compute_risk_score("medium", [], 0, brute_force_sources=1)
        assert bf > base
        assert bf - base == pytest.approx(5.0, abs=0.1)

    def test_multiple_sources(self):
        one = compute_risk_score("medium", [], 0, brute_force_sources=1)
        five = compute_risk_score("medium", [], 0, brute_force_sources=5)
        assert five > one

    def test_brute_force_modest_penalty(self):
        """Brute-force is informational — penalty should be less than CVE-based ones."""
        bf = compute_risk_score("medium", [], 0, brute_force_sources=3)
        exploit = compute_risk_score("medium", [], 0, exploit_verified_count=1)
        assert exploit > bf


class TestCombinedPenalties:
    def test_all_penalties_stack(self):
        """All internal audit penalties should stack together."""
        base = compute_risk_score("medium", [7.5], 5)
        full = compute_risk_score(
            "medium", [7.5], 5,
            privesc_risk_count=2,
            firewall_active=False,
            rootkit_infected_count=1,
            brute_force_sources=3,
        )
        assert full > base

    def test_internal_audit_can_push_to_max(self):
        """Combined with existing penalties, should reach 100."""
        score = compute_risk_score(
            "critical", [10.0], 10,
            default_creds_vulnerable_count=2,
            exploit_verified_count=2,
            privesc_risk_count=5,
            firewall_active=False,
            rootkit_infected_count=2,
        )
        assert score == 100.0

    def test_backwards_compatible(self):
        """Calling without new params should produce same result as before."""
        old_style = compute_risk_score(
            "high", [8.5], 3,
            testssl_grade="C",
            default_creds_vulnerable_count=1,
            ssh_audit_critical_count=1,
            exploit_verified_count=1,
        )
        new_style = compute_risk_score(
            "high", [8.5], 3,
            testssl_grade="C",
            default_creds_vulnerable_count=1,
            ssh_audit_critical_count=1,
            exploit_verified_count=1,
            privesc_risk_count=0,
            firewall_active=None,
            rootkit_infected_count=0,
            brute_force_sources=0,
        )
        assert old_style == new_style
