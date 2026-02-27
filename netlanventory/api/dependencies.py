"""FastAPI dependency providers."""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.core.auth import decode_access_token
from netlanventory.core.database import get_session_factory
from netlanventory.core.registry import ModuleRegistry, get_registry

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield a database session for the duration of a request."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def get_module_registry() -> ModuleRegistry:
    """Return the global module registry (already discovered)."""
    return get_registry()


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: AsyncSession = Depends(get_db),
):
    """Decode the JWT and return the matching User row."""
    from netlanventory.models.user import User  # avoid circular import at module level

    payload = decode_access_token(token)
    user_id_str = payload.get("sub")
    try:
        user_id = uuid.UUID(user_id_str)
    except (TypeError, ValueError):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


async def get_current_active_user(
    current_user=Depends(get_current_user),
):
    """Raise 403 if the account is disabled."""
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")
    return current_user


async def require_admin(
    current_user=Depends(get_current_active_user),
):
    """Raise 403 if the user is not an admin."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required"
        )
    return current_user
