"""CVSS vector parsing — feeds the SSVC adaptation layer (innovation #6, V2).

A CVSS base vector carries the exploitability and impact sub-metrics that map
far more faithfully onto SSVC's *Automatable* and *Technical Impact* decision
points than the collapsed base *score* does. V1 used proxies (EPSS percentile
for Automatable, a CVSS≥9 threshold for Technical Impact); V2 prefers the real
vector when it is present and falls back to the V1 proxies when it is not.

Supports CVSS v3.0 / v3.1 (AV/AC/PR/UI/S + C/I/A) and v4.0 (adds AT, and uses
VC/VI/VA for the vulnerable-system impact). Pure functions, no I/O — trivially
unit-testable.

Mapping rationale (documented, conservative):
  - **Automatable = yes** when kill-chain steps 1-4 can be reliably automated:
    the vuln is remotely/adjacently reachable (AV:N/A), needs no privileges
    (PR:N), no user interaction (UI:N), low attack complexity (AC:L) and — on
    v4 — no attack requirements (AT:N). Any one of those failing means an
    attacker step that resists naive automation, so we answer "no".
  - **Technical Impact = total** when the vuln yields total control of the
    component: all of confidentiality/integrity/availability are High. Anything
    less is "partial". (CISA's SSVC defines total as "total control … or total
    disclosure"; requiring all-High is the common, conservative reading.)
"""

from __future__ import annotations


def parse_vector(vector: str | None) -> dict[str, str] | None:
    """Parse a CVSS vector string into a metric->value dict.

    Returns None when the input is empty or not a recognised CVSS vector.
    The version prefix is preserved under the ``CVSS`` key (e.g. "3.1").

    >>> parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")["AV"]
    'N'
    """
    if not vector or not isinstance(vector, str):
        return None
    parts = [p for p in vector.strip().split("/") if p]
    if not parts:
        return None
    metrics: dict[str, str] = {}
    for part in parts:
        key, _, value = part.partition(":")
        if not key or not value:
            continue
        metrics[key.upper()] = value.upper()
    # A valid CVSS vector starts with "CVSS:<version>" and carries at least the
    # attack vector. Reject anything that does not look like one.
    if "CVSS" not in metrics or "AV" not in metrics:
        return None
    return metrics


def is_automatable_from_vector(metrics: dict[str, str] | None) -> bool | None:
    """SSVC Automatable from a parsed vector. None if metrics are insufficient.

    yes  <=> AV in {N, A} and AC:L and PR:N and UI:N (and AT:N on v4).
    """
    if not metrics:
        return None
    required = ("AV", "AC", "PR", "UI")
    if any(k not in metrics for k in required):
        return None
    reachable = metrics["AV"] in ("N", "A")
    low_complexity = metrics["AC"] == "L"
    no_privs = metrics["PR"] == "N"
    no_interaction = metrics["UI"] == "N"
    # v4.0 Attack Requirements: AT:N means none (easier to automate).
    no_requirements = metrics.get("AT", "N") == "N"
    return bool(
        reachable and low_complexity and no_privs and no_interaction and no_requirements
    )


def is_total_impact_from_vector(metrics: dict[str, str] | None) -> bool | None:
    """SSVC Technical Impact 'total' from a parsed vector. None if insufficient.

    total <=> C:H and I:H and A:H  (v3)   /   VC:H and VI:H and VA:H  (v4).
    """
    if not metrics:
        return None
    # v4.0 uses VC/VI/VA for the vulnerable system; v3 uses C/I/A.
    if {"VC", "VI", "VA"} <= metrics.keys():
        cia = (metrics["VC"], metrics["VI"], metrics["VA"])
    elif {"C", "I", "A"} <= metrics.keys():
        cia = (metrics["C"], metrics["I"], metrics["A"])
    else:
        return None
    return all(v == "H" for v in cia)
