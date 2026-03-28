"""Session management router — list and revoke JWT sessions."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_current_active_user, get_db, require_admin
from netlanventory.models.user import User
from netlanventory.models.user_session import UserSession

router = APIRouter(tags=["sessions"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
CurrentUserDep = Annotated[User, Depends(get_current_active_user)]
AdminDep = Annotated[User, Depends(require_admin)]


class SessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    created_at: datetime
    last_seen_at: datetime
    ip_address: str | None
    user_agent: str | None
    revoked: bool


# ── Current user session endpoints ────────────────────────────────────────────

@router.get("/users/me/sessions", response_model=list[SessionOut])
async def list_my_sessions(db: DbDep, current_user: CurrentUserDep) -> list[UserSession]:
    """List all active (non-revoked) sessions for the current user."""
    result = await db.execute(
        select(UserSession)
        .where(UserSession.user_id == current_user.id, UserSession.revoked.is_(False))
        .order_by(UserSession.last_seen_at.desc())
    )
    return list(result.scalars().all())


@router.delete(
    "/users/me/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT
)
async def revoke_my_session(
    session_id: uuid.UUID, db: DbDep, current_user: CurrentUserDep
) -> None:
    """Revoke a specific session belonging to the current user."""
    result = await db.execute(
        select(UserSession).where(
            UserSession.id == session_id,
            UserSession.user_id == current_user.id,
        )
    )
    session_record = result.scalar_one_or_none()
    if not session_record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    session_record.revoked = True
    await db.flush()


@router.delete("/users/me/sessions", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_all_other_sessions(db: DbDep, current_user: CurrentUserDep) -> None:
    """Revoke all sessions for the current user (keeps the current one if jti is tracked)."""
    result = await db.execute(
        select(UserSession).where(
            UserSession.user_id == current_user.id,
            UserSession.revoked.is_(False),
        )
    )
    sessions = result.scalars().all()
    for s in sessions:
        s.revoked = True
    await db.flush()


# ── Admin session endpoints ────────────────────────────────────────────────────

@router.get(
    "/admin/users/{user_id}/sessions",
    response_model=list[SessionOut],
    dependencies=[Depends(require_admin)],
)
async def admin_list_user_sessions(
    user_id: uuid.UUID, db: DbDep
) -> list[UserSession]:
    """List all sessions for a specific user (admin only)."""
    result = await db.execute(
        select(UserSession)
        .where(UserSession.user_id == user_id)
        .order_by(UserSession.last_seen_at.desc())
    )
    return list(result.scalars().all())


@router.delete(
    "/admin/users/{user_id}/sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_admin)],
)
async def admin_revoke_user_session(
    user_id: uuid.UUID, session_id: uuid.UUID, db: DbDep
) -> None:
    """Revoke a specific session for any user (admin only)."""
    result = await db.execute(
        select(UserSession).where(
            UserSession.id == session_id,
            UserSession.user_id == user_id,
        )
    )
    session_record = result.scalar_one_or_none()
    if not session_record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    session_record.revoked = True
    await db.flush()
