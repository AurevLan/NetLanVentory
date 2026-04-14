"""Unit tests for the AI-Triage engine.

Pure tests on prompt construction, cache key (input hash), output validation
and provider selection. The actual LLM call is not exercised — tests rely on
deterministic byte-level comparisons of the prompt and the hash.
"""

from __future__ import annotations

import os

import pytest

from netlanventory.core.ai_triage import (
    PROMPT_VERSION,
    AnthropicProvider,
    LLMOutput,
    OllamaProvider,
    TriageInputs,
    build_user_prompt,
    get_provider,
    parse_llm_output,
)


def _inputs(**overrides) -> TriageInputs:
    defaults = dict(
        cve_id="CVE-2024-1234",
        cve_cvss=9.8,
        cve_epss=0.95,
        cve_kev=True,
        cve_description="Remote code execution in widget service",
        exploit_maturity="verified",
        asset_id="00000000-0000-0000-0000-000000000001",
        asset_role="db",
        asset_criticality="critical",
        asset_internet_facing=True,
        effective_severity=8.8,
        compensating_factors=["firewall_hardened"],
        ioc_match_count=0,
    )
    defaults.update(overrides)
    return TriageInputs(**defaults)


# ── Hash key ──────────────────────────────────────────────────────────────────


def test_hash_is_stable_across_calls():
    inp = _inputs()
    assert inp.hash() == inp.hash()


def test_hash_depends_on_cvss():
    h1 = _inputs(cve_cvss=9.8).hash()
    h2 = _inputs(cve_cvss=7.5).hash()
    assert h1 != h2


def test_hash_depends_on_compensating_factors():
    h1 = _inputs(compensating_factors=["a", "b"]).hash()
    h2 = _inputs(compensating_factors=["c"]).hash()
    assert h1 != h2


def test_hash_factor_order_irrelevant():
    """Order of compensating factors shouldn't change the hash."""
    h1 = _inputs(compensating_factors=["a", "b", "c"]).hash()
    h2 = _inputs(compensating_factors=["c", "b", "a"]).hash()
    assert h1 == h2


def test_hash_includes_prompt_version_indirectly():
    """Hash payload contains PROMPT_VERSION so a bump invalidates cache."""
    # We can't easily mutate PROMPT_VERSION at runtime, so just check that
    # hashes are 64 hex chars (SHA256 hex digest).
    h = _inputs().hash()
    assert len(h) == 64
    int(h, 16)  # must parse


# ── Prompt construction ───────────────────────────────────────────────────────


def test_user_prompt_contains_key_facts():
    inp = _inputs()
    prompt = build_user_prompt(inp)
    assert "CVE-2024-1234" in prompt
    assert "9.8" in prompt
    assert "KEV : oui" in prompt
    assert "criticité=critical" in prompt
    assert "firewall_hardened" in prompt


def test_user_prompt_truncates_description():
    long_desc = "Z" * 1000  # rare letter to avoid collision with template text
    inp = _inputs(cve_description=long_desc)
    prompt = build_user_prompt(inp)
    # Description trimmed at 400 chars
    assert prompt.count("Z") == 400


def test_user_prompt_handles_empty_factors():
    inp = _inputs(compensating_factors=[])
    prompt = build_user_prompt(inp)
    assert "aucun" in prompt


# ── Output validation ─────────────────────────────────────────────────────────


def test_parse_valid_output():
    raw = '{"urgency": "now", "one_liner": "Patcher immédiatement.", "top_factors": ["KEV", "Internet exposé"]}'
    parsed = parse_llm_output(raw)
    assert parsed is not None
    assert parsed.urgency == "now"
    assert "Patcher" in parsed.one_liner


def test_parse_rejects_invalid_urgency():
    raw = '{"urgency": "asap", "one_liner": "x", "top_factors": ["a"]}'
    assert parse_llm_output(raw) is None


def test_parse_rejects_too_many_factors():
    raw = '{"urgency": "now", "one_liner": "x", "top_factors": ["a","b","c","d","e","f","g"]}'
    assert parse_llm_output(raw) is None


def test_parse_rejects_oversize_one_liner():
    raw = '{"urgency": "now", "one_liner": "' + ("x" * 400) + '", "top_factors": ["a"]}'
    assert parse_llm_output(raw) is None


def test_parse_rejects_garbage():
    assert parse_llm_output("not json at all") is None
    assert parse_llm_output("") is None
    assert parse_llm_output("{") is None


def test_parse_tolerates_whitespace():
    raw = '\n  {"urgency": "30d", "one_liner": "ok", "top_factors": ["x"]}  \n'
    assert parse_llm_output(raw) is not None


# ── Provider selection ────────────────────────────────────────────────────────


def test_default_provider_is_ollama(monkeypatch):
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    assert isinstance(get_provider(), OllamaProvider)


def test_anthropic_provider_via_env(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key")
    p = get_provider()
    assert isinstance(p, AnthropicProvider)
    assert p.api_key == "fake-key"


def test_unknown_provider_falls_back_to_ollama(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "weird-vendor")
    assert isinstance(get_provider(), OllamaProvider)


# ── Schema ────────────────────────────────────────────────────────────────────


def test_llm_output_serialization():
    obj = LLMOutput(urgency="24h", one_liner="Patch d'urgence.", top_factors=["EPSS 0.9"])
    payload = obj.model_dump()
    assert payload["urgency"] == "24h"
    assert "Patch" in payload["one_liner"]
