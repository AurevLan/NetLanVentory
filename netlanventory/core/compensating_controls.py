"""Compensating Controls Engine — effective severity per (asset, cve).

Produces an `EffectiveSeverity` dataclass that downgrades a raw CVSS score
based on hardening signals collected from the asset's latest scan reports
(firewall, privesc, headers/WAF) and asset tags.

Goal: reduce alert fatigue by reflecting context. A CVSS 9.8 RCE on an
isolated honeypot tagged "lab" is not a fire; a CVSS 7.5 web vuln behind
a WAF on a non-internet-facing host is less urgent than the raw score
suggests.

Design rules:
  - **Pure function** for `compute_effective_severity(cve, context)` — easy
    to unit-test and to invoke from `core/risk.py`.
  - **All factors are explicit and human-readable** — never hide *why* a
    severity was downgraded. The frontend must show the factor list.
  - **KEV clamp**: a CVE in CISA's Known Exploited Vulnerabilities list
    cannot be downgraded by more than 1.0 point, regardless of context.
  - **Raw severity is never overwritten** — both `base` and `effective` are
    always returned. The risk score may use either, but alerts/UI must
    display both.

V1 limitations (documented):
  - The `Cve` model has no `attack_vector` / `affected_port` fields, so the
    engine cannot perform port-precise firewall correlation. V2 should add
    a CPE→port map populated from NVD enrichment.
  - WAF detection is heuristic (Server header substring match), not based
    on a vendor signature DB.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Literal

import hashlib

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.core.cache import cache_get_json, cache_invalidate_prefix, cache_set_json
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.cve import Cve
from netlanventory.models.firewall_report import FirewallReport
from netlanventory.models.headers_audit_report import HeadersAuditReport
from netlanventory.models.privesc_report import PrivescReport

logger = get_logger(__name__)

Confidence = Literal["high", "medium", "low"]


# ── Heuristics ────────────────────────────────────────────────────────────────

# Tags that signal an asset is intentionally exposed / disposable / non-prod.
# A CVE on these assets is genuinely less urgent.
_LOW_PRIORITY_TAGS = frozenset({"isolated", "honeypot", "lab", "test", "dev", "staging"})

# Substrings indicating a WAF/CDN sits in front (Server header).
_WAF_SIGNATURES = (
    "cloudflare", "akamai", "incapsula", "imperva", "sucuri", "f5",
    "barracuda", "fortiweb", "modsecurity", "awselb", "cloudfront",
    "azurefd", "fastly",
)

# CWE / keyword markers indicating a CVE is web-application class
# (so a WAF in front is genuinely a compensating control).
_WEB_CVE_KEYWORDS = (
    "xss", "cross-site scripting", "sql injection", "sqli",
    "csrf", "cross-site request forgery", "lfi", "rfi",
    "path traversal", "directory traversal", "ssti",
    "open redirect", "command injection",
)


# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ControlFactor:
    """A single rule that altered the severity, with evidence."""

    rule: str
    delta: float                 # negative = downgrade, positive = upgrade (rare)
    evidence: str
    confidence: Confidence


@dataclass(frozen=True)
class EffectiveSeverity:
    base: float                  # raw CVSS
    effective: float             # post-controls, clamped to [0, 10]
    factors: list[ControlFactor] = field(default_factory=list)
    kev_clamped: bool = False

    @property
    def downgrade(self) -> float:
        return max(0.0, self.base - self.effective)

    def to_dict(self) -> dict:
        return {
            "base": round(self.base, 1),
            "effective": round(self.effective, 1),
            "downgrade": round(self.downgrade, 1),
            "kev_clamped": self.kev_clamped,
            "factors": [
                {
                    "rule": f.rule,
                    "delta": round(f.delta, 1),
                    "evidence": f.evidence,
                    "confidence": f.confidence,
                }
                for f in self.factors
            ],
        }


@dataclass
class ControlContext:
    """Snapshot of an asset's compensating-control posture.

    Built once per asset (one DB roundtrip per report type) and reused for
    every CVE evaluation on that asset.
    """

    asset_id: uuid.UUID
    asset_tags: frozenset[str]
    is_internet_facing: bool
    firewall: FirewallReport | None
    privesc: PrivescReport | None
    headers: HeadersAuditReport | None

    @property
    def waf_vendor(self) -> str | None:
        if not self.headers or not self.headers.findings:
            return None
        details = (self.headers.findings or {}).get("details") or {}
        # try common header capitalizations
        server = (details.get("Server") or details.get("server") or "").lower()
        for sig in _WAF_SIGNATURES:
            if sig in server:
                return sig
        return None


# ── Pure rules ────────────────────────────────────────────────────────────────


def _is_web_cve(cve: Cve) -> bool:
    desc = (cve.description or "").lower()
    return any(kw in desc for kw in _WEB_CVE_KEYWORDS)


def _rule_firewall_hardened(ctx: ControlContext) -> ControlFactor | None:
    fw = ctx.firewall
    if not fw or fw.status != "completed":
        return None
    if fw.firewall_active and fw.rules_count > 0 and fw.open_input_count <= 5:
        return ControlFactor(
            rule="firewall_hardened",
            delta=-2.0,
            evidence=(
                f"{fw.backend or 'firewall'} active with {fw.rules_count} rules, "
                f"{fw.open_input_count} input ports exposed"
            ),
            confidence="medium",
        )
    return None


def _rule_privesc_clean(ctx: ControlContext) -> ControlFactor | None:
    pr = ctx.privesc
    if not pr or pr.status != "completed":
        return None
    if pr.risk_findings_count == 0:
        return ControlFactor(
            rule="privesc_clean",
            delta=-0.5,
            evidence="PrivescReport: no SUID/sudo risk findings",
            confidence="medium",
        )
    return None


def _rule_waf_in_front(cve: Cve, ctx: ControlContext) -> ControlFactor | None:
    waf = ctx.waf_vendor
    if not waf:
        return None
    if not _is_web_cve(cve):
        return None
    return ControlFactor(
        rule="waf_in_front",
        delta=-1.5,
        evidence=f"WAF/CDN detected via Server header: {waf}",
        confidence="medium",
    )


def _rule_low_priority_asset(ctx: ControlContext) -> ControlFactor | None:
    matched = ctx.asset_tags & _LOW_PRIORITY_TAGS
    if not matched:
        return None
    tag = sorted(matched)[0]
    return ControlFactor(
        rule="low_priority_asset",
        delta=-2.0,
        evidence=f"asset tagged '{tag}'",
        confidence="high",
    )


def _rule_not_internet_facing(cve: Cve, ctx: ControlContext) -> ControlFactor | None:
    if ctx.is_internet_facing:
        return None
    # Network-attack CVE on a private host: small downgrade.
    # Heuristic: presence of "remote" or "network" or CVSS attack vector hints
    # in description. We're conservative.
    desc = (cve.description or "").lower()
    if "remote" in desc or "network" in desc or "unauthenticated" in desc:
        return ControlFactor(
            rule="not_internet_facing",
            delta=-1.0,
            evidence="asset is not internet-facing",
            confidence="low",
        )
    return None


_RULES = (
    _rule_firewall_hardened,
    _rule_privesc_clean,
    _rule_low_priority_asset,
)


# ── Public API ────────────────────────────────────────────────────────────────


def compute_effective_severity(cve: Cve, ctx: ControlContext) -> EffectiveSeverity:
    """Pure function: given a CVE and an asset context, return effective severity.

    Always returns a result — if no factors apply, `effective == base`.
    """
    base = float(cve.cvss_score or 0.0)
    factors: list[ControlFactor] = []

    # Generic rules (asset-only)
    for rule in _RULES:
        f = rule(ctx)
        if f:
            factors.append(f)

    # CVE-aware rules
    f = _rule_waf_in_front(cve, ctx)
    if f:
        factors.append(f)
    f = _rule_not_internet_facing(cve, ctx)
    if f:
        factors.append(f)

    raw_delta = sum(f.delta for f in factors)
    effective = max(0.0, min(10.0, base + raw_delta))

    # KEV clamp: never downgrade more than 1.0 if CVE is in CISA KEV.
    kev_clamped = False
    if cve.kev_date_added is not None and (base - effective) > 1.0:
        effective = base - 1.0
        kev_clamped = True
        factors.append(
            ControlFactor(
                rule="kev_clamp",
                delta=0.0,
                evidence=f"CVE in CISA KEV (added {cve.kev_date_added}); downgrade capped to 1.0",
                confidence="high",
            )
        )

    return EffectiveSeverity(
        base=base,
        effective=round(effective, 1),
        factors=factors,
        kev_clamped=kev_clamped,
    )


async def build_context(session: AsyncSession, asset: Asset) -> ControlContext:
    """Build a ControlContext for an asset (one query per report type).

    The asset is expected to be loaded; tags are loaded lazily here if needed.
    """
    # Latest completed FirewallReport
    fw = (
        await session.execute(
            select(FirewallReport)
            .where(FirewallReport.asset_id == asset.id, FirewallReport.status == "completed")
            .order_by(FirewallReport.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    pr = (
        await session.execute(
            select(PrivescReport)
            .where(PrivescReport.asset_id == asset.id, PrivescReport.status == "completed")
            .order_by(PrivescReport.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    hd = (
        await session.execute(
            select(HeadersAuditReport)
            .where(
                HeadersAuditReport.asset_id == asset.id,
                HeadersAuditReport.status == "completed",
            )
            .order_by(HeadersAuditReport.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    # Load tags if not already eager-loaded
    tags: frozenset[str] = frozenset()
    try:
        tag_objs = asset.tags or []
        tags = frozenset(t.name.lower() for t in tag_objs)
    except Exception:
        # tags relation not loaded — fetch separately
        from netlanventory.models.asset_tag import AssetTag
        tag_rows = (
            await session.execute(select(AssetTag.name).where(AssetTag.asset_id == asset.id))
        ).scalars().all()
        tags = frozenset(n.lower() for n in tag_rows)

    # is_internet_facing isn't a column today — infer from a tag for V1.
    is_internet_facing = "internet-facing" in tags or "public" in tags

    return ControlContext(
        asset_id=asset.id,
        asset_tags=tags,
        is_internet_facing=is_internet_facing,
        firewall=fw,
        privesc=pr,
        headers=hd,
    )


async def compute_for_asset_cve(
    session: AsyncSession, asset_id: uuid.UUID, cve_id: str
) -> EffectiveSeverity | None:
    """Convenience wrapper: load asset + cve, build context, compute."""
    asset = (
        await session.execute(
            select(Asset).where(Asset.id == asset_id).options(selectinload(Asset.tags))
        )
    ).scalar_one_or_none()
    if asset is None:
        return None
    cve = (
        await session.execute(select(Cve).where(Cve.cve_id == cve_id))
    ).scalar_one_or_none()
    if cve is None:
        return None
    ctx = await build_context(session, asset)
    return compute_effective_severity(cve, ctx)


# ── Redis cache layer ─────────────────────────────────────────────────────────
#
# Key convention: effsev:{asset_id}:{cve_id}
# We deliberately do NOT include the controls hash in the key — instead, the
# cached payload embeds the hash and the consumer compares. On a hash mismatch
# we treat it as a miss and recompute. This makes invalidation by asset cheap
# (one prefix delete) and robust against stale entries.

_CACHE_TTL_SECONDS = 24 * 3600          # 24 h hard TTL ceiling
_CACHE_PREFIX = "effsev:"


def _context_hash(ctx: ControlContext) -> str:
    """Stable hash of the inputs that influence severity, for cache validation."""
    parts = [
        sorted(ctx.asset_tags),
        ctx.is_internet_facing,
        getattr(ctx.firewall, "id", None) and str(ctx.firewall.id),
        getattr(ctx.privesc, "id", None) and str(ctx.privesc.id),
        getattr(ctx.headers, "id", None) and str(ctx.headers.id),
    ]
    raw = repr(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


async def get_or_compute_effective_severity(
    session: AsyncSession,
    asset_id: uuid.UUID,
    cve_id: str,
    *,
    ctx: ControlContext | None = None,
) -> EffectiveSeverity | None:
    """Cached wrapper around `compute_for_asset_cve`.

    Reads Redis first; on hit and matching context hash returns immediately.
    Otherwise computes, stores, and returns. Falls through gracefully if Redis
    is unavailable.
    """
    cache_key = f"{_CACHE_PREFIX}{asset_id}:{cve_id}"
    cached = await cache_get_json(cache_key)

    if ctx is None:
        asset = (
            await session.execute(
                select(Asset).where(Asset.id == asset_id).options(selectinload(Asset.tags))
            )
        ).scalar_one_or_none()
        if asset is None:
            return None
        ctx = await build_context(session, asset)

    expected_hash = _context_hash(ctx)
    if cached and cached.get("ctx_hash") == expected_hash:
        # Re-hydrate from JSON
        return EffectiveSeverity(
            base=cached["base"],
            effective=cached["effective"],
            kev_clamped=cached.get("kev_clamped", False),
            factors=[
                ControlFactor(
                    rule=f["rule"],
                    delta=f["delta"],
                    evidence=f["evidence"],
                    confidence=f["confidence"],
                )
                for f in cached.get("factors", [])
            ],
        )

    cve = (
        await session.execute(select(Cve).where(Cve.cve_id == cve_id))
    ).scalar_one_or_none()
    if cve is None:
        return None

    eff = compute_effective_severity(cve, ctx)
    payload = eff.to_dict()
    payload["ctx_hash"] = expected_hash
    await cache_set_json(cache_key, payload, ttl=_CACHE_TTL_SECONDS)
    return eff


async def invalidate_asset_cache(asset_id: uuid.UUID) -> None:
    """Drop all cached effective severities for an asset.

    Call this whenever a new FirewallReport/PrivescReport/HeadersAuditReport
    completes, when asset tags change, or after a CVE is acknowledged.
    """
    await cache_invalidate_prefix(f"{_CACHE_PREFIX}{asset_id}:")
