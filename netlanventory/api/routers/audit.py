"""Audit log router — admin access to the audit trail."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db, require_admin
from netlanventory.models.audit_log import AuditLog

router = APIRouter(prefix="/admin/audit-logs", tags=["audit"])

DbDep = Annotated[AsyncSession, Depends(get_db)]


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    timestamp: datetime
    user: str
    action: str
    resource_type: str
    resource_id: str | None
    detail: str | None


class AuditLogList(BaseModel):
    total: int
    items: list[AuditLogOut]


@router.get("", response_model=AuditLogList, dependencies=[Depends(require_admin)])
async def list_audit_logs(
    db: DbDep,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    user: str = Query("", description="Filter by username"),
    action: str = Query("", description="Filter by action"),
    resource_type: str = Query("", description="Filter by resource type"),
) -> AuditLogList:
    """Return paginated audit log entries (admin only)."""
    query = select(AuditLog)
    count_query = select(func.count()).select_from(AuditLog)

    if user:
        query = query.where(AuditLog.user.ilike(f"%{user}%"))
        count_query = count_query.where(AuditLog.user.ilike(f"%{user}%"))
    if action:
        query = query.where(AuditLog.action.ilike(f"%{action}%"))
        count_query = count_query.where(AuditLog.action.ilike(f"%{action}%"))
    if resource_type:
        query = query.where(AuditLog.resource_type.ilike(f"%{resource_type}%"))
        count_query = count_query.where(AuditLog.resource_type.ilike(f"%{resource_type}%"))

    total = (await db.execute(count_query)).scalar_one()
    result = await db.execute(
        query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit)
    )
    items = list(result.scalars().all())
    return AuditLogList(total=total, items=items)
