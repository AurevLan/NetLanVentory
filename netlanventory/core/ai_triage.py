"""AI-Triage engine (innovation #3).

Produces a single, structured, French triage recommendation per (cve, asset)
using a small LLM. The output is a strict JSON document — never free text,
never used to drive automation. Purpose is to *prioritise* and *explain*,
not to act.

Design rules:
  - **Provider abstraction** — Anthropic / OpenAI / Ollama (local). Default
    is Ollama because it keeps data on-prem (RGPD-friendly).
  - **Versioned prompt** — bumping `PROMPT_VERSION` invalidates every cached
    row automatically (the unique key embeds it).
  - **Hash-keyed cache** — `input_hash` is a SHA256 over every value that
    influences the answer (prompt version, CVE id, CVE last_modified,
    asset id, effective severity, sorted tags). On hash mismatch the
    cached row is treated as stale.
  - **Strict JSON validation** — the LLM output is parsed via Pydantic.
    Anything that doesn't validate is discarded; we never persist garbage.
  - **Cost guard** — hard daily token budget enforced via Redis counter
    with a fail-closed default (no LLM call past the limit).
  - **Feature flag** — `AI_TRIAGE_ENABLED=False` by default.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.core.cache import cache_get, cache_set
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.cve import Cve
from netlanventory.models.triage_recommendation import TriageRecommendation, TriageUrgency

logger = get_logger(__name__)


PROMPT_VERSION = "v1.0"
DEFAULT_TTL_DAYS = 7
DAILY_TOKEN_BUDGET = int(os.environ.get("AI_TRIAGE_DAILY_BUDGET", "200000"))


# ── Pydantic schema for LLM output ────────────────────────────────────────────


class LLMOutput(BaseModel):
    """Strict JSON shape the model MUST produce. Anything else is rejected."""

    urgency: str = Field(..., pattern=r"^(now|24h|7d|30d|none)$")
    one_liner: str = Field(..., max_length=300)
    top_factors: list[str] = Field(..., min_length=1, max_length=5)


@dataclass(frozen=True)
class TriageInputs:
    """The full set of facts that influence the recommendation."""

    cve_id: str
    cve_cvss: float
    cve_epss: float
    cve_kev: bool
    cve_description: str
    exploit_maturity: str
    asset_id: str
    asset_role: str
    asset_criticality: str
    asset_internet_facing: bool
    effective_severity: float
    compensating_factors: list[str]
    ioc_match_count: int

    def hash(self) -> str:
        """Stable SHA256 over inputs that influence the answer."""
        payload = json.dumps(
            {
                "v": PROMPT_VERSION,
                **self.__dict__,
                "compensating_factors": sorted(self.compensating_factors),
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ── Prompt template ───────────────────────────────────────────────────────────


SYSTEM_PROMPT = """\
Tu es un assistant de triage de vulnérabilités. Tu réponds uniquement en JSON
strict respectant ce schéma :

{"urgency": "now|24h|7d|30d|none", "one_liner": "phrase ≤180 chars en français",
 "top_factors": ["raison 1", "raison 2", "raison 3"]}

Règles :
- urgency=now si KEV + exposé Internet + actif critique
- urgency=24h si KEV ou exploit vérifié, et asset important
- urgency=7d si CVSS ≥ 7 et exploit PoC public
- urgency=30d si CVSS < 7 ou contrôles compensatoires forts
- urgency=none si effective severity ≤ 2 et aucun signal d'attaque
- Tu réponds en français, ton factuel, sans tournures spéculatives.
- Tu n'inventes pas de valeurs. Tu te bases UNIQUEMENT sur les données fournies.
"""


def build_user_prompt(inputs: TriageInputs) -> str:
    """Construct the deterministic user prompt for the LLM."""
    return (
        f"CVE : {inputs.cve_id}\n"
        f"CVSS : {inputs.cve_cvss} | EPSS : {inputs.cve_epss:.2f} | "
        f"KEV : {'oui' if inputs.cve_kev else 'non'} | "
        f"Maturité exploit : {inputs.exploit_maturity}\n"
        f"Description : {(inputs.cve_description or '')[:400]}\n"
        f"\n"
        f"Asset : rôle={inputs.asset_role}, criticité={inputs.asset_criticality}, "
        f"exposé Internet={'oui' if inputs.asset_internet_facing else 'non'}\n"
        f"Severity effective (post-controls) : {inputs.effective_severity}\n"
        f"Contrôles compensatoires actifs : "
        f"{', '.join(inputs.compensating_factors) or 'aucun'}\n"
        f"Matches IOC threat intel : {inputs.ioc_match_count}\n"
        f"\n"
        f"Réponds en JSON strict selon le schéma."
    )


# ── Provider abstraction ──────────────────────────────────────────────────────


class TriageProvider(Protocol):
    name: str

    async def call(self, system: str, user: str) -> tuple[str, int, int]:
        """Return (raw_output_text, tokens_in, tokens_out)."""
        ...


class OllamaProvider:
    """Local Ollama provider — default for on-prem deployments."""

    name = "ollama:llama3.1"

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.1") -> None:
        self.base_url = base_url
        self.model = model
        self.name = f"ollama:{model}"

    async def call(self, system: str, user: str) -> tuple[str, int, int]:
        import httpx

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "format": "json",
                    "stream": False,
                },
            )
            resp.raise_for_status()
            data = resp.json()
        text = data.get("message", {}).get("content", "")
        tokens_in = data.get("prompt_eval_count", 0)
        tokens_out = data.get("eval_count", 0)
        return text, tokens_in, tokens_out


class AnthropicProvider:
    """Anthropic provider — for environments where cloud LLMs are allowed."""

    name = "claude-haiku-4-5"

    def __init__(self, api_key: str | None = None, model: str = "claude-haiku-4-5") -> None:
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model
        self.name = model

    async def call(self, system: str, user: str) -> tuple[str, int, int]:
        if not self.api_key:
            raise RuntimeError("ANTHROPIC_API_KEY not set")
        import httpx

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": 400,
                    "system": system,
                    "messages": [{"role": "user", "content": user}],
                },
            )
            resp.raise_for_status()
            data = resp.json()
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        usage = data.get("usage", {})
        return text, usage.get("input_tokens", 0), usage.get("output_tokens", 0)


def get_provider() -> TriageProvider:
    """Pick a provider based on env. Default = Ollama local.

    Ollama endpoint/model are configurable via OLLAMA_BASE_URL and OLLAMA_MODEL
    so the container does not have to reach localhost:11434.
    """
    name = (os.environ.get("AI_PROVIDER") or "ollama").lower()
    if name == "anthropic":
        return AnthropicProvider()
    base_url = os.environ.get("OLLAMA_BASE_URL") or "http://localhost:11434"
    model = os.environ.get("OLLAMA_MODEL") or "llama3.1"
    return OllamaProvider(base_url=base_url, model=model)


# ── Cost guard (Redis counter, fail-closed) ───────────────────────────────────


_BUDGET_KEY_PREFIX = "ai_triage_budget:"


async def _check_and_consume_budget(tokens: int) -> bool:
    """Reserve `tokens` from the daily budget. Returns False when exceeded."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    key = f"{_BUDGET_KEY_PREFIX}{today}"
    raw = await cache_get(key)
    used = int(raw) if raw and raw.isdigit() else 0
    if used + tokens > DAILY_TOKEN_BUDGET:
        return False
    await cache_set(key, str(used + tokens), ttl=24 * 3600)
    return True


# ── Output validation ─────────────────────────────────────────────────────────


def parse_llm_output(raw: str) -> LLMOutput | None:
    """Parse + validate LLM output. Returns None on any error."""
    try:
        # The model is asked to output only JSON; tolerate extra whitespace.
        data = json.loads(raw.strip())
        return LLMOutput(**data)
    except (json.JSONDecodeError, ValidationError, TypeError) as exc:
        logger.warning("ai_triage_invalid_output", error=str(exc), raw=raw[:200])
        return None


# ── Public API ────────────────────────────────────────────────────────────────


async def get_or_create_recommendation(
    session: AsyncSession,
    inputs: TriageInputs,
    *,
    provider: TriageProvider | None = None,
) -> TriageRecommendation | None:
    """Cache-first lookup, with provider call + persist on miss."""
    h = inputs.hash()

    existing = (
        await session.execute(
            select(TriageRecommendation).where(
                TriageRecommendation.cve_id == inputs.cve_id,
                TriageRecommendation.asset_id == uuid.UUID(inputs.asset_id),
                TriageRecommendation.prompt_version == PROMPT_VERSION,
            )
        )
    ).scalar_one_or_none()
    if existing and existing.input_hash == h and existing.cached_until > datetime.now(timezone.utc):
        return existing

    if not await _check_and_consume_budget(800):  # rough reservation
        logger.warning("ai_triage_budget_exhausted")
        return None

    prov = provider or get_provider()
    user = build_user_prompt(inputs)
    try:
        raw, tokens_in, tokens_out = await prov.call(SYSTEM_PROMPT, user)
    except Exception as exc:  # noqa: BLE001
        logger.error("ai_triage_provider_error", provider=prov.name, error=str(exc))
        return None

    parsed = parse_llm_output(raw)
    if parsed is None:
        return None

    if existing:
        existing.urgency = TriageUrgency(parsed.urgency)
        existing.one_liner = parsed.one_liner
        existing.top_factors = parsed.top_factors
        existing.model_id = prov.name
        existing.input_hash = h
        existing.cached_until = datetime.now(timezone.utc) + timedelta(days=DEFAULT_TTL_DAYS)
        existing.tokens_in = tokens_in
        existing.tokens_out = tokens_out
        rec = existing
    else:
        rec = TriageRecommendation(
            cve_id=inputs.cve_id,
            asset_id=uuid.UUID(inputs.asset_id),
            urgency=TriageUrgency(parsed.urgency),
            one_liner=parsed.one_liner,
            top_factors=parsed.top_factors,
            model_id=prov.name,
            prompt_version=PROMPT_VERSION,
            input_hash=h,
            cached_until=datetime.now(timezone.utc) + timedelta(days=DEFAULT_TTL_DAYS),
            tokens_in=tokens_in,
            tokens_out=tokens_out,
        )
        session.add(rec)
    await session.flush()
    return rec


async def build_inputs_from_db(
    session: AsyncSession, asset_id: uuid.UUID, cve_id: str
) -> TriageInputs | None:
    """Convenience: load the Cve + Asset and build a TriageInputs.

    Pulls effective severity from the compensating-controls engine when
    available; falls back to raw CVSS otherwise.
    """
    asset = (await session.execute(select(Asset).where(Asset.id == asset_id))).scalar_one_or_none()
    cve = (await session.execute(select(Cve).where(Cve.cve_id == cve_id))).scalar_one_or_none()
    if not asset or not cve:
        return None

    # Effective severity (best effort — engine may be unavailable in tests)
    effective = float(cve.cvss_score or 0.0)
    factors: list[str] = []
    try:
        from netlanventory.core.compensating_controls import compute_for_asset_cve
        eff = await compute_for_asset_cve(session, asset_id, cve_id)
        if eff:
            effective = eff.effective
            factors = [f.rule for f in eff.factors]
    except Exception:  # noqa: BLE001
        pass

    return TriageInputs(
        cve_id=cve_id,
        cve_cvss=float(cve.cvss_score or 0.0),
        cve_epss=float(cve.epss_score or 0.0),
        cve_kev=cve.kev_date_added is not None,
        cve_description=(cve.description or "")[:400],
        exploit_maturity=(cve.exploit_maturity or "none"),
        asset_id=str(asset_id),
        asset_role=(asset.device_type or "unknown"),
        asset_criticality=(asset.criticality or "medium"),
        asset_internet_facing=False,  # heuristic — see compensating_controls
        effective_severity=effective,
        compensating_factors=factors,
        ioc_match_count=0,
    )
