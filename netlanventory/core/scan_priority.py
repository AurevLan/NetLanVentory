"""Smart Re-scan priority engine (innovation #5).

Maintains a per-(asset, module) priority score so the scheduler can pop
the most urgent scans first instead of sweeping every asset on a fixed
interval. Score updates are pushed by event hooks (EPSS refresh, KEV
import, scan completion, asset tag change), not pulled by a polling
loop.

Design rules:
  - **Pure scoring** (`compute_score`) is a free function — easy to
    unit-test and to expose for explainability.
  - **Famine guard** via `max_age_hours` — even a low-priority row gets
    forced into the queue once stale.
  - **Cooldown** via `next_eligible_at` — a freshly scanned (asset, module)
    cannot be re-popped before a configurable floor.
  - **No scheduler refactor in this commit** — the engine and DB helpers
    are wired, but the existing scheduler loops still run. Migrating the
    actual loops to `pop_due_priorities()` is a follow-up PR so we can
    observe the queue before flipping behaviour.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve
from netlanventory.models.scan_priority import ScanPriority

logger = get_logger(__name__)


# ── Tunables ──────────────────────────────────────────────────────────────────
# Kept as module constants (not env vars) for V1: easy to unit-test, easy to
# tune in one place. Promote to settings once the formula is stable.

WEIGHT_EPSS_DELTA = 5.0          # +5 per unit of (max EPSS delta over 24 h)
WEIGHT_NEW_KEV = 10.0            # +10 if any new KEV match since last scan
WEIGHT_AGE_PER_HOUR = 0.05       # +0.05 per hour since last scan
WEIGHT_UNACK_CRITICAL = 8.0      # +8 if any unacknowledged critical CVE
COOLDOWN_PENALTY = -5.0          # -5 if scanned within the last hour
COOLDOWN_WINDOW_HOURS = 1

CRITICALITY_WEIGHT: dict[str, float] = {
    "critical": 5.0,
    "high": 3.0,
    "medium": 1.0,
    "low": 0.0,
}

DEFAULT_RATELIMIT_MINUTES = 15   # min interval between two scans of the same (asset, module)
DEFAULT_MAX_AGE_HOURS = 72       # famine guard ceiling


# ── Pure scoring ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PriorityInputs:
    """Snapshot of facts feeding the score formula. Easy to mock in tests."""

    asset_criticality: str
    max_epss_delta_24h: float            # 0.0 if unknown
    new_kev_matches: int                  # since last_scan_at
    hours_since_last_scan: float          # 0.0 if never scanned, then huge bonus
    has_unack_critical_cve: bool
    scanned_within_cooldown: bool


def compute_score(inputs: PriorityInputs) -> float:
    """Return the priority score (no DB access).

    Higher = more urgent. Always >= 0 to keep the priority queue stable.
    """
    score = 1.0
    score += WEIGHT_EPSS_DELTA * max(0.0, inputs.max_epss_delta_24h)
    if inputs.new_kev_matches > 0:
        score += WEIGHT_NEW_KEV * min(inputs.new_kev_matches, 5)
    score += WEIGHT_AGE_PER_HOUR * max(0.0, inputs.hours_since_last_scan)
    score += CRITICALITY_WEIGHT.get((inputs.asset_criticality or "").lower(), 1.0)
    if inputs.has_unack_critical_cve:
        score += WEIGHT_UNACK_CRITICAL
    if inputs.scanned_within_cooldown:
        score += COOLDOWN_PENALTY
    return max(0.0, score)


# ── DB helpers ────────────────────────────────────────────────────────────────


async def upsert_priority(
    session: AsyncSession,
    asset_id: uuid.UUID,
    module: str,
    score: float,
    *,
    ratelimit_minutes: int = DEFAULT_RATELIMIT_MINUTES,
    max_age_hours: int = DEFAULT_MAX_AGE_HOURS,
) -> None:
    """Insert or update a priority row.

    Postgres-only (uses ON CONFLICT). The tests use SQLite via the existing
    conftest, so any unit test that touches DB persistence must mock this.
    Pure scoring is tested separately and does NOT exercise this helper.
    """
    now = datetime.now(timezone.utc)
    stmt = pg_insert(ScanPriority).values(
        asset_id=asset_id,
        module=module,
        score=score,
        last_score_update=now,
        next_eligible_at=now + timedelta(minutes=ratelimit_minutes),
        max_age_hours=max_age_hours,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["asset_id", "module"],
        set_={
            "score": stmt.excluded.score,
            "last_score_update": stmt.excluded.last_score_update,
            "next_eligible_at": stmt.excluded.next_eligible_at,
        },
    )
    await session.execute(stmt)


async def mark_scanned(
    session: AsyncSession,
    asset_id: uuid.UUID,
    module: str,
    *,
    cooldown_minutes: int = DEFAULT_RATELIMIT_MINUTES,
) -> None:
    """Reset the priority for a (asset, module) after a successful scan.

    Score drops back to 1.0; the row stays in the table so the next event
    can bump it again.
    """
    now = datetime.now(timezone.utc)
    await session.execute(
        update(ScanPriority)
        .where(
            ScanPriority.asset_id == asset_id,
            ScanPriority.module == module,
        )
        .values(
            score=1.0,
            last_score_update=now,
            last_scan_at=now,
            next_eligible_at=now + timedelta(minutes=cooldown_minutes),
        )
    )


async def pop_due_priorities(
    session: AsyncSession,
    *,
    budget: int = 20,
) -> list[ScanPriority]:
    """Return the top-N priorities whose next_eligible_at is past, score desc.

    Caller is responsible for triggering the corresponding scan and then
    calling `mark_scanned()`. We do not lock rows here — V1 expects a single
    scheduler instance. For multi-instance deployments, wrap in a SELECT FOR
    UPDATE SKIP LOCKED.
    """
    now = datetime.now(timezone.utc)
    rows = (
        await session.execute(
            select(ScanPriority)
            .where(ScanPriority.next_eligible_at <= now)
            .order_by(ScanPriority.score.desc())
            .limit(budget)
        )
    ).scalars().all()
    return list(rows)


async def force_stale_into_queue(session: AsyncSession) -> int:
    """Famine guard: bump score on rows older than max_age_hours.

    Returns the number of rows promoted. Intended to run nightly.
    """
    now = datetime.now(timezone.utc)
    bumped = 0
    rows = (
        await session.execute(select(ScanPriority).where(ScanPriority.last_scan_at.isnot(None)))
    ).scalars().all()
    for row in rows:
        age_hours = (now - row.last_scan_at).total_seconds() / 3600 if row.last_scan_at else 999
        if age_hours > row.max_age_hours and row.score < 50.0:
            row.score = 50.0  # high but not max — let real signals stay above
            row.next_eligible_at = now
            row.last_score_update = now
            bumped += 1
    return bumped


# ── Event hooks (called from other modules) ───────────────────────────────────


async def recompute_for_asset(
    session: AsyncSession,
    asset_id: uuid.UUID,
    modules: list[str],
) -> None:
    """Recompute the score for every (asset, module) on a single asset.

    Cheap to call from an event handler: 1 asset query + 1 CVE query, and
    one row upsert per module.
    """
    asset = (
        await session.execute(select(Asset).where(Asset.id == asset_id))
    ).scalar_one_or_none()
    if not asset:
        return

    # Collect CVE-derived signals once
    cve_rows = (
        await session.execute(
            select(Cve.epss_score, Cve.kev_date_added, Cve.cvss_score, AssetCve.ack_status)
            .join(AssetCve, AssetCve.cve_id == Cve.id)
            .where(AssetCve.asset_id == asset_id)
        )
    ).all()

    max_epss = max((r.epss_score or 0.0 for r in cve_rows), default=0.0)
    new_kev = sum(1 for r in cve_rows if r.kev_date_added is not None)
    has_unack_critical = any(
        (r.cvss_score or 0) >= 9.0 and r.ack_status not in ("false_positive", "accepted")
        for r in cve_rows
    )

    # Per-module score (currently uniform — same inputs for every module).
    # V2 may diverge: SSH-only signals for ssh_scan, web signals for nuclei, …
    inputs = PriorityInputs(
        asset_criticality=asset.criticality or "medium",
        max_epss_delta_24h=max_epss,           # V1: use absolute, not delta
        new_kev_matches=new_kev,
        hours_since_last_scan=0.0,             # filled per-row below
        has_unack_critical_cve=has_unack_critical,
        scanned_within_cooldown=False,
    )

    for module in modules:
        # Look up existing row to compute hours_since_last_scan & cooldown
        existing = (
            await session.execute(
                select(ScanPriority).where(
                    ScanPriority.asset_id == asset_id,
                    ScanPriority.module == module,
                )
            )
        ).scalar_one_or_none()

        now = datetime.now(timezone.utc)
        if existing and existing.last_scan_at:
            age_h = (now - existing.last_scan_at).total_seconds() / 3600
            in_cooldown = age_h < COOLDOWN_WINDOW_HOURS
        else:
            age_h = 24.0  # never scanned — generous starting bonus
            in_cooldown = False

        per_module_inputs = PriorityInputs(
            asset_criticality=inputs.asset_criticality,
            max_epss_delta_24h=inputs.max_epss_delta_24h,
            new_kev_matches=inputs.new_kev_matches,
            hours_since_last_scan=age_h,
            has_unack_critical_cve=inputs.has_unack_critical_cve,
            scanned_within_cooldown=in_cooldown,
        )
        score = compute_score(per_module_inputs)
        await upsert_priority(session, asset_id, module, score)


async def boost(
    session: AsyncSession, asset_id: uuid.UUID, module: str, amount: float = 20.0
) -> None:
    """Manual boost: add `amount` to the score for a (asset, module)."""
    existing = (
        await session.execute(
            select(ScanPriority).where(
                ScanPriority.asset_id == asset_id, ScanPriority.module == module
            )
        )
    ).scalar_one_or_none()
    if existing:
        existing.score += amount
        existing.last_score_update = datetime.now(timezone.utc)
        existing.next_eligible_at = datetime.now(timezone.utc)  # eligible now
    else:
        await upsert_priority(session, asset_id, module, amount, ratelimit_minutes=0)
