"""Unit tests for the web-recon parser cores (js-secrets, dns/email).

These exercise the pure logic — secret detection / masking and SPF/DKIM/DMARC
interpretation — without any network I/O. The only async dependency
(`_resolve_txt`) is monkeypatched, so the DNS-record *interpretation* branches
are covered deterministically.
"""

from __future__ import annotations

import os

# Settings validator needs non-default secrets before importing app modules.
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-unit-tests")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-for-tests")
os.environ.setdefault("ADMIN_PASSWORD", "Test1234!@#$")
os.environ.setdefault("APP_DEBUG", "true")

import pytest

from netlanventory.api.routers import dns_email_audit
from netlanventory.api.routers.dns_email_audit import _check_dkim, _check_dmarc, _check_spf
from netlanventory.api.routers.js_secrets_scan import (
    _SECRET_PATTERNS,
    _extract_context,
    _is_false_positive,
)


# ── JS secrets: detection patterns ───────────────────────────────────────────


def _detect(text: str) -> set[str]:
    """Return the set of pattern names that match `text`."""
    return {name for name, _sev, pat in _SECRET_PATTERNS if pat.search(text)}


class TestSecretPatterns:
    def test_aws_access_key_detected(self):
        assert "AWS Access Key" in _detect("const k = 'AKIAIOSFODNN7EXAMPLE'")

    def test_stripe_live_key_detected(self):
        assert "Stripe Secret Key" in _detect("sk_live_" + "a" * 30)

    def test_github_token_detected(self):
        assert "GitHub Token" in _detect("ghp_" + "A" * 40)

    def test_private_key_block_detected(self):
        assert "Private Key" in _detect("-----BEGIN RSA PRIVATE KEY-----")

    def test_clean_code_matches_nothing(self):
        # Ordinary code with no credentials must not trip any pattern.
        assert _detect("function add(a, b) { return a + b; }") == set()


class TestFalsePositiveFilter:
    @pytest.mark.parametrize(
        "text",
        [
            "YOUR_API_KEY_HERE",
            "REPLACE_WITH_REAL_KEY",
            "apiKey = process.env.API_KEY",
            "token: import.meta.env.VITE_TOKEN",
            "secret = ${MY_SECRET}",
            "key = '{{ vault_key }}'",
            "// TODO put the real key",
        ],
    )
    def test_placeholders_and_refs_are_false_positives(self, text):
        assert _is_false_positive(text) is True

    def test_realistic_key_is_not_false_positive(self):
        assert _is_false_positive("AKIAIOSFODNN7EXAMPLE") is False
        assert _is_false_positive("ghp_" + "A" * 40) is False


class TestExtractContext:
    def test_secret_value_is_masked(self):
        secret = "sk_live_" + "a" * 30
        content = f"const stripe = '{secret}'; // init"
        pattern = next(p for n, _s, p in _SECRET_PATTERNS if n == "Stripe Secret Key")
        match = pattern.search(content)
        out = _extract_context(content, match)
        # The full secret must never appear verbatim in stored context.
        assert secret not in out
        # First 6 and last 4 chars are kept as a hint.
        assert secret[:6] in out
        assert secret[-4:] in out
        assert "…" in out

    def test_short_match_still_masked(self):
        content = "BEGIN -----BEGIN EC PRIVATE KEY----- END"
        pattern = next(p for n, _s, p in _SECRET_PATTERNS if n == "Private Key")
        match = pattern.search(content)
        out = _extract_context(content, match)
        assert match.group(0) not in out


# ── DNS / email: SPF interpretation ──────────────────────────────────────────


def _patch_txt(monkeypatch, mapping: dict[str, list[str]]):
    """Patch _resolve_txt to return records from `mapping` (default: empty)."""

    async def fake_resolve(domain: str) -> list[str]:
        return mapping.get(domain, [])

    monkeypatch.setattr(dns_email_audit, "_resolve_txt", fake_resolve)


@pytest.mark.asyncio
class TestSpf:
    async def test_missing_record(self, monkeypatch):
        _patch_txt(monkeypatch, {})
        res = await _check_spf("example.com")
        assert res["present"] is False
        assert res["valid"] is False

    async def test_hardfail_is_valid(self, monkeypatch):
        _patch_txt(monkeypatch, {"example.com": ["v=spf1 mx -all"]})
        res = await _check_spf("example.com")
        assert res["present"] is True
        assert res["valid"] is True
        assert res["issues"] == []

    async def test_pass_all_flagged_invalid(self, monkeypatch):
        _patch_txt(monkeypatch, {"example.com": ["v=spf1 +all"]})
        res = await _check_spf("example.com")
        assert res["valid"] is False
        assert any("+all" in i for i in res["issues"])

    async def test_softfail_still_valid(self, monkeypatch):
        _patch_txt(monkeypatch, {"example.com": ["v=spf1 include:_spf.google.com ~all"]})
        res = await _check_spf("example.com")
        # ~all is the only issue → treated as valid (acceptable softfail).
        assert res["valid"] is True
        assert any("~all" in i for i in res["issues"])

    async def test_multiple_records_flagged(self, monkeypatch):
        _patch_txt(monkeypatch, {"example.com": ["v=spf1 -all", "v=spf1 ~all"]})
        res = await _check_spf("example.com")
        assert any("Multiple SPF" in i for i in res["issues"])

    async def test_too_many_lookups_flagged(self, monkeypatch):
        record = "v=spf1 " + "include:a.example.com " * 11 + "-all"
        _patch_txt(monkeypatch, {"example.com": [record]})
        res = await _check_spf("example.com")
        assert any("10 DNS lookup" in i for i in res["issues"])


# ── DNS / email: DMARC interpretation ────────────────────────────────────────


@pytest.mark.asyncio
class TestDmarc:
    async def test_missing_record(self, monkeypatch):
        _patch_txt(monkeypatch, {})
        res = await _check_dmarc("example.com")
        assert res["present"] is False
        assert any("spoofing" in i for i in res["issues"])

    async def test_strict_policy_clean(self, monkeypatch):
        rec = "v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@example.com"
        _patch_txt(monkeypatch, {"_dmarc.example.com": [rec]})
        res = await _check_dmarc("example.com")
        assert res["policy"] == "reject"
        assert res["has_rua"] is True
        assert res["issues"] == []

    async def test_policy_none_flagged(self, monkeypatch):
        _patch_txt(monkeypatch, {"_dmarc.example.com": ["v=DMARC1; p=none"]})
        res = await _check_dmarc("example.com")
        assert res["policy"] == "none"
        assert any("'none'" in i for i in res["issues"])

    async def test_partial_pct_flagged(self, monkeypatch):
        rec = "v=DMARC1; p=quarantine; sp=quarantine; rua=mailto:x@example.com; pct=50"
        _patch_txt(monkeypatch, {"_dmarc.example.com": [rec]})
        res = await _check_dmarc("example.com")
        assert any("pct=50" in i for i in res["issues"])


# ── DNS / email: DKIM interpretation ─────────────────────────────────────────


@pytest.mark.asyncio
class TestDkim:
    async def test_no_selectors(self, monkeypatch):
        _patch_txt(monkeypatch, {})
        res = await _check_dkim("example.com")
        assert res["present"] is False
        assert any("No DKIM" in i for i in res["issues"])

    async def test_strong_key_no_issue(self, monkeypatch):
        async def fake_resolve(domain: str) -> list[str]:
            if "_domainkey" in domain:
                return ["v=DKIM1; k=rsa; p=" + "A" * 200]
            return []

        monkeypatch.setattr(dns_email_audit, "_resolve_txt", fake_resolve)
        res = await _check_dkim("example.com")
        assert res["present"] is True
        assert res["issues"] == []

    async def test_weak_key_flagged(self, monkeypatch):
        async def fake_resolve(domain: str) -> list[str]:
            if "_domainkey" in domain:
                return ["v=DKIM1; k=rsa; p=ABCD"]  # ~24-bit → weak
            return []

        monkeypatch.setattr(dns_email_audit, "_resolve_txt", fake_resolve)
        res = await _check_dkim("example.com")
        assert res["present"] is True
        assert any("weak key" in i for i in res["issues"])
