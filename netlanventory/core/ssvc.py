"""CISA SSVC engine — the *primary* patch-prioritisation signal (innovation #6).

SSVC (Stakeholder-Specific Vulnerability Categorization) replaces "sort by
CVSS" with a deterministic decision tree that answers a different question:
*what should we do about this vulnerability, on this specific asset, right now?*

Why deterministic and not the LLM triage (innovation #3):
  - **Auditable** — every decision is a pure table lookup; we persist the four
    inputs that produced it (`ssvc_inputs`) so an analyst can see *why*.
  - **Free & always-on** — no tokens, no provider, works with
    `AI_TRIAGE_ENABLED=false` (the default). AI triage becomes the optional
    "nuance / explanation" layer *on top of* the SSVC decision, not the
    primary call.
  - **Per (cve, asset)** — SSVC is stakeholder-specific: the same CVE is `Act`
    on an internet-facing critical server and `Track` on an isolated lab box.
    The decision therefore lives on `AssetCve`, not on `Cve`.

The decision tree is the **CISA Coordinator v2.0.3** table, copied verbatim
from the CERT/CC SSVC repository
(`data/csv/cisa/cisa_coordinator_2_0_3.csv`). Do not hand-edit the cells —
regenerate `_RAW_ROWS` from the upstream CSV when CISA publishes a new
version, and bump `TABLE_VERSION`.

Input derivation (the "adaptation layer", `derive_*` below) maps NetLanVentory
facts onto the four SSVC decision points. Where a fact is not available with
full fidelity the heuristic is documented inline and recorded in the audit
rationale:
  - **Exploitation**  ← KEV / Nuclei verification / exploit maturity / PoC.
  - **Technical Impact** ← CVSS base score threshold (intrinsic to the vuln).
  - **Automatable**   ← EPSS percentile (CVE side) **AND** asset exposure
    (device side). V2 will refine the CVE side by parsing the CVSS vector
    (AV:N / AC:L) once it is stored on the Cve model.
  - **Mission & Well-being** ← asset criticality.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from netlanventory.core import cvss_vector

TABLE_VERSION = "cisa-coordinator-2.0.3"

# Thresholds for the adaptation layer. Module constants (not env vars) for V1:
# easy to unit-test and tune in one place. Promote to settings once stable.
EPSS_AUTOMATABLE_PERCENTILE = 0.90   # CVE side of "Automatable=yes"
TECHNICAL_IMPACT_TOTAL_CVSS = 9.0    # CVSS >= this => Technical Impact = total


# ── Decision points & outcomes ─────────────────────────────────────────────
# String values match the upstream CSV verbatim so the table can be built and
# validated directly against it.


class Exploitation(str, Enum):
    NONE = "none"
    POC = "public poc"
    ACTIVE = "active"


class Automatable(str, Enum):
    NO = "no"
    YES = "yes"


class TechnicalImpact(str, Enum):
    PARTIAL = "partial"
    TOTAL = "total"


class MissionWellbeing(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Decision(str, Enum):
    TRACK = "track"
    TRACK_STAR = "track*"
    ATTEND = "attend"
    ACT = "act"


# ── CISA Coordinator v2.0.3 decision table (verbatim) ───────────────────────
# Source: CERTCC/SSVC data/csv/cisa/cisa_coordinator_2_0_3.csv
# (exploitation, automatable, technical_impact, mission_wellbeing, decision)

_RAW_ROWS: tuple[tuple[str, str, str, str, str], ...] = (
    ("none", "no", "partial", "low", "track"),
    ("none", "no", "partial", "medium", "track"),
    ("none", "no", "partial", "high", "track"),
    ("none", "no", "total", "low", "track"),
    ("none", "no", "total", "medium", "track"),
    ("none", "no", "total", "high", "track*"),
    ("none", "yes", "partial", "low", "track"),
    ("none", "yes", "partial", "medium", "track"),
    ("none", "yes", "partial", "high", "attend"),
    ("none", "yes", "total", "low", "track"),
    ("none", "yes", "total", "medium", "track"),
    ("none", "yes", "total", "high", "attend"),
    ("public poc", "no", "partial", "low", "track"),
    ("public poc", "no", "partial", "medium", "track"),
    ("public poc", "no", "partial", "high", "track*"),
    ("public poc", "no", "total", "low", "track"),
    ("public poc", "no", "total", "medium", "track*"),
    ("public poc", "no", "total", "high", "attend"),
    ("public poc", "yes", "partial", "low", "track"),
    ("public poc", "yes", "partial", "medium", "track"),
    ("public poc", "yes", "partial", "high", "attend"),
    ("public poc", "yes", "total", "low", "track"),
    ("public poc", "yes", "total", "medium", "track*"),
    ("public poc", "yes", "total", "high", "attend"),
    ("active", "no", "partial", "low", "track"),
    ("active", "no", "partial", "medium", "track"),
    ("active", "no", "partial", "high", "attend"),
    ("active", "no", "total", "low", "track"),
    ("active", "no", "total", "medium", "attend"),
    ("active", "no", "total", "high", "act"),
    ("active", "yes", "partial", "low", "attend"),
    ("active", "yes", "partial", "medium", "attend"),
    ("active", "yes", "partial", "high", "act"),
    ("active", "yes", "total", "low", "attend"),
    ("active", "yes", "total", "medium", "act"),
    ("active", "yes", "total", "high", "act"),
)

DECISION_TABLE: dict[
    tuple[Exploitation, Automatable, TechnicalImpact, MissionWellbeing], Decision
] = {
    (
        Exploitation(e),
        Automatable(a),
        TechnicalImpact(t),
        MissionWellbeing(m),
    ): Decision(d)
    for e, a, t, m, d in _RAW_ROWS
}

# Defensive: the tree must enumerate every combination exactly once (3*2*2*3).
assert len(DECISION_TABLE) == 36, "CISA SSVC table must have 36 unique rows"


# ── Outcome mappings ────────────────────────────────────────────────────────

# SSVC decision -> existing TriageUrgency vocabulary (now|24h|7d|30d|none).
# SSVC always recommends at least tracking, so "none" is never produced here.
DECISION_TO_URGENCY: dict[Decision, str] = {
    Decision.ACT: "now",
    Decision.ATTEND: "24h",
    Decision.TRACK_STAR: "7d",
    Decision.TRACK: "30d",
}

# Additive weight injected into the smart re-scan priority score
# (core/scan_priority.compute_score). SSVC is the dominant term: an `Act`
# outranks every other heuristic so urgent-to-patch assets are re-scanned
# first.
DECISION_PRIORITY_WEIGHT: dict[Decision, float] = {
    Decision.ACT: 30.0,
    Decision.ATTEND: 12.0,
    Decision.TRACK_STAR: 4.0,
    Decision.TRACK: 0.0,
}

# Total order for aggregating many (cve) decisions to one (asset) decision.
DECISION_RANK: dict[Decision, int] = {
    Decision.TRACK: 0,
    Decision.TRACK_STAR: 1,
    Decision.ATTEND: 2,
    Decision.ACT: 3,
}


def most_urgent(decisions: list[Decision]) -> Decision | None:
    """Return the highest-ranked decision in a list (None if empty)."""
    if not decisions:
        return None
    return max(decisions, key=lambda d: DECISION_RANK[d])


# ── Core lookup ─────────────────────────────────────────────────────────────


def ssvc_decision(
    exploitation: Exploitation,
    automatable: Automatable,
    technical_impact: TechnicalImpact,
    mission_wellbeing: MissionWellbeing,
) -> Decision:
    """Pure table lookup. Total over the input domain — never raises KeyError."""
    return DECISION_TABLE[
        (exploitation, automatable, technical_impact, mission_wellbeing)
    ]


# ── Adaptation layer: NetLanVentory facts -> SSVC decision points ────────────
# Each derive_* takes primitive values (not ORM objects) so it is trivially
# unit-testable, and records nothing — provenance is assembled by `evaluate`.


def derive_exploitation(
    *,
    in_kev: bool,
    exploit_verified: bool | None,
    exploit_maturity: str | None,
    poc_available: bool,
    exploit_db_id: int | None,
) -> Exploitation:
    """ACTIVE if exploited in the wild, POC if exploit code exists, else NONE.

    - in_kev: CVE is in CISA KEV (observed active exploitation) => ACTIVE.
    - exploit_verified: Nuclei confirmed it fires on *this* asset => ACTIVE.
    - exploit_maturity 'weaponized'/'active' => ACTIVE; 'poc'/'exploit' => POC.
    - poc_available / exploit_db_id => POC.
    """
    maturity = (exploit_maturity or "none").lower()
    if in_kev or exploit_verified is True or maturity in ("weaponized", "active"):
        return Exploitation.ACTIVE
    if maturity in ("poc", "exploit") or poc_available or exploit_db_id:
        return Exploitation.POC
    return Exploitation.NONE


def derive_technical_impact(
    *,
    cvss_score: float | None,
    cvss_metrics: dict[str, str] | None = None,
) -> tuple[TechnicalImpact, str]:
    """SSVC Technical Impact. Returns (impact, method) for audit provenance.

    Intrinsic to the vulnerability — asset context does not change it.
      - **vector** (V2, preferred): TOTAL iff C:H/I:H/A:H (or VC/VI/VA on v4).
      - **base_score** (V1 fallback): TOTAL when CVSS >= TECHNICAL_IMPACT_TOTAL_CVSS.
    """
    total = cvss_vector.is_total_impact_from_vector(cvss_metrics)
    if total is not None:
        return (TechnicalImpact.TOTAL if total else TechnicalImpact.PARTIAL, "vector")
    if (cvss_score or 0.0) >= TECHNICAL_IMPACT_TOTAL_CVSS:
        return (TechnicalImpact.TOTAL, "base_score")
    return (TechnicalImpact.PARTIAL, "base_score")


def derive_automatable(
    *,
    epss_percentile: float | None,
    internet_facing: bool,
    cvss_metrics: dict[str, str] | None = None,
) -> tuple[Automatable, str]:
    """SSVC Automatable. Returns (automatable, method) for audit provenance.

    "Automatable=yes" means kill-chain steps 1-4 can be reliably automated.
    The CVE side is ANDed with asset exposure (`internet_facing`) — a wormable
    CVE on a fully firewalled host is not automatable *against that host*.

    CVE side:
      - **vector** (V2, preferred): AV:N/A + AC:L + PR:N + UI:N (+ AT:N on v4).
      - **epss** (V1 fallback): EPSS percentile >= EPSS_AUTOMATABLE_PERCENTILE.
    """
    vector_side = cvss_vector.is_automatable_from_vector(cvss_metrics)
    if vector_side is not None:
        cve_side, method = vector_side, "vector"
    else:
        cve_side = (epss_percentile or 0.0) >= EPSS_AUTOMATABLE_PERCENTILE
        method = "epss"
    return (
        Automatable.YES if (cve_side and internet_facing) else Automatable.NO,
        method,
    )


def derive_mission_wellbeing(*, asset_criticality: str | None) -> MissionWellbeing:
    """Map asset criticality to SSVC Mission & Well-being impact.

    critical -> high, high -> medium, medium/low/unknown -> low. Mission impact
    reflects how essential the *asset* is, not the severity of the vuln, so it
    is driven by criticality alone; compensating-control context flows into
    Automatable instead.
    """
    crit = (asset_criticality or "medium").lower()
    if crit == "critical":
        return MissionWellbeing.HIGH
    if crit == "high":
        return MissionWellbeing.MEDIUM
    return MissionWellbeing.LOW


# ── Result container ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SsvcResult:
    """A decision plus the full provenance needed to audit / persist it."""

    decision: Decision
    exploitation: Exploitation
    automatable: Automatable
    technical_impact: TechnicalImpact
    mission_wellbeing: MissionWellbeing
    rationale: dict  # raw facts behind each decision point

    @property
    def urgency(self) -> str:
        return DECISION_TO_URGENCY[self.decision]

    @property
    def priority_weight(self) -> float:
        return DECISION_PRIORITY_WEIGHT[self.decision]

    def to_dict(self) -> dict:
        """Stored as AssetCve.ssvc_inputs — the auditable record of *why*."""
        return {
            "table_version": TABLE_VERSION,
            "decision": self.decision.value,
            "decision_points": {
                "exploitation": self.exploitation.value,
                "automatable": self.automatable.value,
                "technical_impact": self.technical_impact.value,
                "mission_wellbeing": self.mission_wellbeing.value,
            },
            "rationale": self.rationale,
        }


def evaluate(
    *,
    in_kev: bool,
    exploit_verified: bool | None,
    exploit_maturity: str | None,
    poc_available: bool,
    exploit_db_id: int | None,
    cvss_score: float | None,
    cvss_vector_str: str | None = None,
    epss_percentile: float | None,
    internet_facing: bool,
    asset_criticality: str | None,
    effective_severity: float | None = None,
) -> SsvcResult:
    """Derive the four decision points from primitive facts and look up the tree.

    When `cvss_vector_str` is present, Automatable and Technical Impact are
    derived from the real CVSS sub-metrics (V2); otherwise they fall back to the
    EPSS proxy / base-score threshold (V1). The method used for each is recorded
    in the rationale.

    `effective_severity` (post compensating-controls) is not a decision point
    in CISA's tree; it is recorded in the rationale for the analyst and may
    drive UI nuance. ORM glue lives in `core/ssvc_eval.py`.
    """
    metrics = cvss_vector.parse_vector(cvss_vector_str)

    exploitation = derive_exploitation(
        in_kev=in_kev,
        exploit_verified=exploit_verified,
        exploit_maturity=exploit_maturity,
        poc_available=poc_available,
        exploit_db_id=exploit_db_id,
    )
    technical_impact, ti_method = derive_technical_impact(
        cvss_score=cvss_score, cvss_metrics=metrics
    )
    automatable, auto_method = derive_automatable(
        epss_percentile=epss_percentile,
        internet_facing=internet_facing,
        cvss_metrics=metrics,
    )
    mission_wellbeing = derive_mission_wellbeing(asset_criticality=asset_criticality)

    decision = ssvc_decision(
        exploitation, automatable, technical_impact, mission_wellbeing
    )

    rationale = {
        "in_kev": in_kev,
        "exploit_verified": exploit_verified,
        "exploit_maturity": exploit_maturity,
        "poc_available": poc_available,
        "exploit_db_id": exploit_db_id,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector_str,
        "epss_percentile": epss_percentile,
        "internet_facing": internet_facing,
        "asset_criticality": asset_criticality,
        "effective_severity": effective_severity,
        "derivation": {
            "automatable": auto_method,        # "vector" | "epss"
            "technical_impact": ti_method,      # "vector" | "base_score"
        },
        "thresholds": {
            "epss_automatable_percentile": EPSS_AUTOMATABLE_PERCENTILE,
            "technical_impact_total_cvss": TECHNICAL_IMPACT_TOTAL_CVSS,
        },
    }

    return SsvcResult(
        decision=decision,
        exploitation=exploitation,
        automatable=automatable,
        technical_impact=technical_impact,
        mission_wellbeing=mission_wellbeing,
        rationale=rationale,
    )
