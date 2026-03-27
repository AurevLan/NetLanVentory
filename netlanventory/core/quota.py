"""Scan quota helper — check and increment per-user daily scan counts."""

from __future__ import annotations

import uuid
from datetime import date

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.models.scan_quota import ScanQuotaLog


async def check_and_increment_quota(
    session: AsyncSession,
    user_id: uuid.UUID,
    quota_limit: int | None,
) -> bool:
    """Check whether the user has quota remaining; if so, increment and return True.

    Returns False (quota exceeded) without modifying the DB if the limit is reached.
    If quota_limit is None the check is skipped and True is always returned.
    """
    if quota_limit is None:
        # Unlimited quota — still track usage but never block
        await _increment(session, user_id)
        return True

    today = date.today()
    result = await session.execute(
        select(ScanQuotaLog).where(
            ScanQuotaLog.user_id == user_id,
            ScanQuotaLog.scan_date == today,
        )
    )
    log = result.scalar_one_or_none()

    if log is not None and log.count >= quota_limit:
        return False

    await _increment(session, user_id, existing=log, today=today)
    return True


async def _increment(
    session: AsyncSession,
    user_id: uuid.UUID,
    existing: ScanQuotaLog | None = None,
    today: date | None = None,
) -> None:
    if today is None:
        today = date.today()
    if existing is not None:
        existing.count += 1
        await session.flush()
    else:
        # Try to find again (handles concurrent requests)
        result = await session.execute(
            select(ScanQuotaLog).where(
                ScanQuotaLog.user_id == user_id,
                ScanQuotaLog.scan_date == today,
            )
        )
        log = result.scalar_one_or_none()
        if log is not None:
            log.count += 1
        else:
            log = ScanQuotaLog(user_id=user_id, scan_date=today, count=1)
            session.add(log)
        await session.flush()
