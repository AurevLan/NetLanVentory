"""Smart Re-scan priorities — visibility and manual boost (innovation #5).

⚠️  V1 OBSERVATIONAL: these scores are computed for visibility only. They do
NOT drive auto-scans yet — scanning is still done by the fixed-interval loops
in `core.scheduler`. Queue popping (`core.scan_priority.pop_due_priorities`)
is reserved behind the `smart_scheduler_queue_enabled` setting (no effect
today) and will be wired into `core.scheduler` in a future release.

Read-only endpoints to inspect the priority queue plus an admin-only POST
to manually boost a (asset, module) ahead of the next cycle.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_current_active_user, get_db, require_admin
from netlanventory.core.logging import get_logger
from netlanventory.core.scan_priority import boost
from netlanventory.models.scan_priority import ScanPriority

logger = get_logger(__name__)

router = APIRouter(prefix="/scheduler", tags=["scheduler"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]
AdminDep = Annotated[object, Depends(require_admin)]


class PriorityRowOut(BaseModel):
    asset_id: uuid.UUID
    module: str
    score: float
    last_score_update: datetime
    last_scan_at: datetime | None
    next_eligible_at: datetime
    max_age_hours: int


class BudgetOut(BaseModel):
    total_rows: int
    due_now: int
    in_cooldown: int
    avg_score: float | None


@router.get("/priorities", response_model=list[PriorityRowOut])
async def list_priorities(
    db: DbDep,
    _user: UserDep,
    limit: int = 50,
) -> list[PriorityRowOut]:
    """Top N priority rows by score, descending. Default 50.

    Note: these scores are observational — they do not trigger scans yet.
    """
    rows = (
        await db.execute(
            select(ScanPriority).order_by(ScanPriority.score.desc()).limit(min(limit, 500))
        )
    ).scalars().all()
    return [PriorityRowOut.model_validate(r, from_attributes=True) for r in rows]


@router.get("/budget", response_model=BudgetOut)
async def get_budget(db: DbDep, _user: UserDep) -> BudgetOut:
    """Aggregate stats: total rows, how many are due, average score."""
    now = func.now()
    total = (await db.execute(select(func.count()).select_from(ScanPriority))).scalar_one()
    due = (
        await db.execute(
            select(func.count()).select_from(ScanPriority).where(ScanPriority.next_eligible_at <= now)
        )
    ).scalar_one()
    avg = (await db.execute(select(func.avg(ScanPriority.score)))).scalar_one()
    return BudgetOut(
        total_rows=total or 0,
        due_now=due or 0,
        in_cooldown=(total or 0) - (due or 0),
        avg_score=float(avg) if avg is not None else None,
    )


@router.post(
    "/priorities/{asset_id}/{module}/boost",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def boost_priority(
    asset_id: uuid.UUID,
    module: str,
    db: DbDep,
    _admin: AdminDep,
    amount: float = 20.0,
) -> None:
    """Admin-only: bump the score of a (asset, module) and make it eligible now."""
    if amount <= 0 or amount > 100:
        raise HTTPException(status_code=400, detail="amount must be in (0, 100]")
    await boost(db, asset_id, module, amount=amount)
    await db.commit()
    logger.info("priority_boosted", asset_id=str(asset_id), module=module, amount=amount)
