"""Unit tests for the Compensating Controls engine.

Pure-function tests — no DB. Builds Cve and ControlContext objects in-memory
and exercises every rule + the KEV clamp.
"""

from __future__ import annotations

import uuid
from datetime import date
from types import SimpleNamespace

import pytest

from netlanventory.core.compensating_controls import (
    ControlContext,
    EffectiveSeverity,
    compute_effective_severity,
)


def _cve(cvss=9.8, description="", kev=None):
    return SimpleNamespace(
        cvss_score=cvss,
        description=description,
        kev_date_added=kev,
    )


def _ctx(
    *,
    tags=(),
    is_internet_facing=False,
    fw=None,
    pr=None,
    hd=None,
):
    return ControlContext(
        asset_id=uuid.uuid4(),
        asset_tags=frozenset(tags),
        is_internet_facing=is_internet_facing,
        firewall=fw,
        privesc=pr,
        headers=hd,
    )


def _firewall(active=True, rules=20, open_inputs=2, status="completed", backend="ufw"):
    return SimpleNamespace(
        status=status,
        firewall_active=active,
        rules_count=rules,
        open_input_count=open_inputs,
        backend=backend,
    )


def _privesc(risk_count=0, status="completed"):
    return SimpleNamespace(status=status, risk_findings_count=risk_count)


def _headers(server_value="cloudflare"):
    return SimpleNamespace(
        status="completed",
        findings={"details": {"Server": f"{server_value}/2"}},
    )


# ── Baseline ──────────────────────────────────────────────────────────────────


def test_no_factors_returns_base():
    cve = _cve(cvss=7.5)
    ctx = _ctx()
    eff = compute_effective_severity(cve, ctx)
    assert eff.base == 7.5
    assert eff.effective == 7.5
    assert eff.factors == []
    assert eff.kev_clamped is False


def test_zero_cvss_stays_zero():
    cve = _cve(cvss=0.0)
    ctx = _ctx(tags={"isolated"})
    eff = compute_effective_severity(cve, ctx)
    assert eff.effective == 0.0


# ── Individual rules ──────────────────────────────────────────────────────────


def test_low_priority_tag_downgrades_2():
    cve = _cve(cvss=9.0)
    ctx = _ctx(tags={"isolated"})
    eff = compute_effective_severity(cve, ctx)
    assert eff.effective == 7.0
    assert any(f.rule == "low_priority_asset" for f in eff.factors)


def test_firewall_hardened_downgrades_2():
    cve = _cve(cvss=8.0)
    ctx = _ctx(fw=_firewall(active=True, rules=30, open_inputs=2))
    eff = compute_effective_severity(cve, ctx)
    assert eff.effective == 6.0
    assert any(f.rule == "firewall_hardened" for f in eff.factors)


def test_firewall_with_too_many_open_ports_does_not_downgrade():
    cve = _cve(cvss=8.0)
    ctx = _ctx(fw=_firewall(active=True, rules=30, open_inputs=10))
    eff = compute_effective_severity(cve, ctx)
    assert eff.effective == 8.0
    assert all(f.rule != "firewall_hardened" for f in eff.factors)


def test_firewall_inactive_does_not_downgrade():
    cve = _cve(cvss=8.0)
    ctx = _ctx(fw=_firewall(active=False))
    eff = compute_effective_severity(cve, ctx)
    assert eff.effective == 8.0


def test_firewall_pending_status_ignored():
    cve = _cve(cvss=8.0)
    ctx = _ctx(fw=_firewall(status="pending"))
    eff = compute_effective_severity(cve, ctx)
    assert eff.effective == 8.0


def test_privesc_clean_downgrades_05():
    cve = _cve(cvss=6.0)
    ctx = _ctx(pr=_privesc(risk_count=0))
    eff = compute_effective_severity(cve, ctx)
    assert eff.effective == 5.5


def test_privesc_with_findings_does_not_downgrade():
    cve = _cve(cvss=6.0)
    ctx = _ctx(pr=_privesc(risk_count=4))
    eff = compute_effective_severity(cve, ctx)
    assert eff.effective == 6.0


def test_waf_only_for_web_cves():
    web_cve = _cve(cvss=7.0, description="Reflected XSS in admin panel")
    other_cve = _cve(cvss=7.0, description="Heap overflow in dhcpd")
    ctx = _ctx(hd=_headers(server_value="cloudflare"))

    assert compute_effective_severity(web_cve, ctx).effective == 5.5
    assert compute_effective_severity(other_cve, ctx).effective == 7.0


def test_waf_signature_detection():
    web_cve = _cve(cvss=7.0, description="SQL injection in search endpoint")
    for vendor in ("akamai", "cloudfront", "fastly", "modsecurity"):
        ctx = _ctx(hd=_headers(server_value=vendor))
        eff = compute_effective_severity(web_cve, ctx)
        assert eff.effective == 5.5, f"WAF {vendor} did not match"


def test_not_internet_facing_low_confidence():
    cve = _cve(cvss=8.0, description="Remote unauthenticated RCE")
    ctx = _ctx(is_internet_facing=False)
    eff = compute_effective_severity(cve, ctx)
    assert eff.effective == 7.0
    assert any(f.rule == "not_internet_facing" for f in eff.factors)


def test_internet_facing_keeps_severity():
    cve = _cve(cvss=8.0, description="Remote unauthenticated RCE")
    ctx = _ctx(is_internet_facing=True)
    eff = compute_effective_severity(cve, ctx)
    assert eff.effective == 8.0


# ── Stacking + clamps ─────────────────────────────────────────────────────────


def test_factors_stack_but_clamp_to_zero():
    cve = _cve(cvss=3.0)
    ctx = _ctx(
        tags={"honeypot"},                  # -2.0
        fw=_firewall(),                     # -2.0
        pr=_privesc(risk_count=0),          # -0.5
    )
    eff = compute_effective_severity(cve, ctx)
    assert eff.effective == 0.0   # clamped, not negative
    assert len(eff.factors) == 3


def test_kev_clamp_caps_downgrade_to_one():
    cve = _cve(cvss=9.8, kev=date(2024, 1, 1))
    ctx = _ctx(
        tags={"isolated"},                  # -2.0
        fw=_firewall(),                     # -2.0
        pr=_privesc(risk_count=0),          # -0.5
    )
    eff = compute_effective_severity(cve, ctx)
    # raw delta = -4.5, but KEV clamps to base - 1.0
    assert eff.effective == 8.8
    assert eff.kev_clamped is True
    assert any(f.rule == "kev_clamp" for f in eff.factors)


def test_kev_with_small_downgrade_not_clamped():
    cve = _cve(cvss=9.8, kev=date(2024, 1, 1))
    ctx = _ctx(pr=_privesc(risk_count=0))   # -0.5 only
    eff = compute_effective_severity(cve, ctx)
    assert eff.effective == 9.3
    assert eff.kev_clamped is False


# ── Serialisation ─────────────────────────────────────────────────────────────


def test_to_dict_shape():
    cve = _cve(cvss=8.0)
    ctx = _ctx(tags={"isolated"})
    eff = compute_effective_severity(cve, ctx)
    payload = eff.to_dict()
    assert set(payload.keys()) == {"base", "effective", "downgrade", "kev_clamped", "factors"}
    assert payload["base"] == 8.0
    assert payload["effective"] == 6.0
    assert payload["downgrade"] == 2.0
    assert isinstance(payload["factors"], list)
    assert payload["factors"][0]["rule"] == "low_priority_asset"
