"""Audit log helper — write a structured audit entry to the database."""

from __future__ import annotations

import json

from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.models.audit_log import AuditLog


async def log_action(
    session: AsyncSession,
    user: str,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    detail: dict | str | None = None,
) -> None:
    """Persist an audit log entry.

    Args:
        session:       The current async DB session (will be flushed, not committed).
        user:          Username or email of the actor.
        action:        Dot-namespaced action string, e.g. "asset.update", "cve.ack".
        resource_type: High-level resource type, e.g. "asset", "cve", "user".
        resource_id:   Optional UUID (as string) of the affected resource.
        detail:        Optional dict or string with extra context (stored as JSON string).
    """
    detail_str: str | None = None
    if detail is not None:
        if isinstance(detail, dict):
            detail_str = json.dumps(detail, default=str)
        else:
            detail_str = str(detail)

    entry = AuditLog(
        user=user,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        detail=detail_str,
    )
    session.add(entry)
    await session.flush()
