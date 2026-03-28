"""Admin router — scan quota usage statistics."""

from __future__ import annotations

import uuid
from datetime import date, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db, require_admin
from netlanventory.models.scan_quota import ScanQuotaLog
from netlanventory.models.user import User

router = APIRouter(prefix="/admin/quota-usage", tags=["admin"])

DbDep = Annotated[AsyncSession, Depends(get_db)]


class QuotaDay(BaseModel):
    date: str
    count: int


class QuotaUser(BaseModel):
    user_id: str
    username: str
    email: str
    days: list[QuotaDay]
    total: int


class QuotaUsageResponse(BaseModel):
    users: list[QuotaUser]
    dates: list[str]


@router.get("", response_model=QuotaUsageResponse,
            dependencies=[Depends(require_admin)])
async def get_quota_usage(db: DbDep) -> QuotaUsageResponse:
    """Return per-user daily scan counts for the last 30 days."""
    today = date.today()
    cutoff = today - timedelta(days=29)

    # Generate 30-day date range
    dates = [str(cutoff + timedelta(days=i)) for i in range(30)]

    # Fetch all quota logs in range
    logs = (
        await db.execute(
            select(ScanQuotaLog).where(ScanQuotaLog.scan_date >= cutoff)
        )
    ).scalars().all()

    if not logs:
        return QuotaUsageResponse(users=[], dates=dates)

    # Group by user_id
    by_user: dict[str, dict[str, int]] = {}
    for log in logs:
        uid = str(log.user_id)
        d = str(log.scan_date)
        if uid not in by_user:
            by_user[uid] = {}
        by_user[uid][d] = log.count

    # Fetch user info
    user_ids_list = list(by_user.keys())
    users_result = await db.execute(
        select(User).where(User.id.in_([uuid.UUID(u) for u in user_ids_list]))
    )
    users_map = {str(u.id): u for u in users_result.scalars().all()}

    result_users: list[QuotaUser] = []
    for uid, day_counts in by_user.items():
        user = users_map.get(uid)
        days = [QuotaDay(date=d, count=day_counts.get(d, 0)) for d in dates]
        total = sum(day_counts.values())
        result_users.append(QuotaUser(
            user_id=uid,
            username=user.username if user else uid[:8],
            email=user.email if user else "",
            days=days,
            total=total,
        ))

    result_users.sort(key=lambda u: u.total, reverse=True)
    return QuotaUsageResponse(users=result_users, dates=dates)
