"""SLA policy — one deadline rule shared by every SLA computation (v0.16).

Étape 3 of the convergence: the SLA clock starts at the SSVC verdict, not
only at discovery. The effective deadline for an open (asset, CVE) pair is
the EARLIER of:

  - the legacy severity deadline: discovered_at + configured days per
    severity (Critical 3 / High 7 / Medium 30 / Low 90 by default), and
  - the verdict deadline: ssvc_decided_at + days per decision
    (act 1 / attend 7 / track* 30; track imposes nothing).

`ssvc_evaluated_at` is the anchor: since étape 3 it is only refreshed when
the decision *changes* ("act since Tuesday"), so the verdict deadline is
stable across the hourly recompute instead of sliding forward every run.

Both recompute paths (the scheduler task and POST /sla/compute) call
`effective_sla_deadline` so the two can never diverge again.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

# Days granted once a decision is reached — aligned with the tier labels the
# UI shows (<24h / <7d / <30d). `track` adds no constraint beyond severity.
DECISION_SLA_DAYS: dict[str, int] = {
    "act": 1,
    "attend": 7,
    "track*": 30,
}


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def effective_sla_deadline(
    *,
    discovered_at: datetime,
    severity_days: int,
    ssvc_decision: str | None,
    ssvc_decided_at: datetime | None,
) -> date:
    """Pure rule: earliest of the severity deadline and the verdict deadline."""
    deadline = (_as_utc(discovered_at) + timedelta(days=severity_days)).date()

    decision_days = DECISION_SLA_DAYS.get(ssvc_decision or "")
    if decision_days is not None and ssvc_decided_at is not None:
        verdict_deadline = (_as_utc(ssvc_decided_at) + timedelta(days=decision_days)).date()
        deadline = min(deadline, verdict_deadline)

    return deadline
