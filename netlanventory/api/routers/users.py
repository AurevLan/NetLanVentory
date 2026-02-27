"""Users router — CRUD for local user accounts (admin only except self-update)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_current_active_user, get_db, require_admin
from netlanventory.core.auth import hash_password
from netlanventory.core.logging import get_logger
from netlanventory.models.user import User
from netlanventory.schemas.user import UserCreate, UserList, UserOut, UserUpdate

router = APIRouter(prefix="/users", tags=["users"])
logger = get_logger(__name__)

DbDep = Annotated[AsyncSession, Depends(get_db)]
AdminDep = Annotated[User, Depends(require_admin)]
CurrentUserDep = Annotated[User, Depends(get_current_active_user)]


@router.get("", response_model=UserList, dependencies=[Depends(require_admin)])
async def list_users(db: DbDep) -> UserList:
    total = (await db.execute(select(func.count()).select_from(User))).scalar_one()
    result = await db.execute(select(User).order_by(User.created_at))
    return UserList(total=total, items=list(result.scalars().all()))


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(require_admin)])
async def create_user(payload: UserCreate, db: DbDep) -> User:
    # Check uniqueness
    existing = (await db.execute(
        select(User).where(
            (User.email == payload.email) | (User.username == payload.username)
        )
    )).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or username already taken",
        )

    user = User(
        email=payload.email,
        username=payload.username,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        is_active=True,
        auth_provider="local",
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    logger.info("User created", email=payload.email, role=payload.role)
    return user


@router.get("/{user_id}", response_model=UserOut)
async def get_user(user_id: uuid.UUID, db: DbDep, current_user: CurrentUserDep) -> User:
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.patch("/{user_id}", response_model=UserOut)
async def update_user(
    user_id: uuid.UUID, payload: UserUpdate, db: DbDep, current_user: CurrentUserDep
) -> User:
    is_self = current_user.id == user_id
    is_admin = current_user.role == "admin"

    if not is_admin and not is_self:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    data = payload.model_dump(exclude_unset=True)

    # Non-admins can only update their own name and password
    if not is_admin:
        data = {k: v for k, v in data.items() if k in ("full_name", "password")}

    if "password" in data:
        user.hashed_password = hash_password(data.pop("password"))

    for field, value in data.items():
        setattr(user, field, value)

    await db.flush()
    await db.refresh(user)
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(require_admin)])
async def delete_user(user_id: uuid.UUID, db: DbDep, current_user: AdminDep) -> None:
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    await db.delete(user)
    logger.info("User deleted", user_id=str(user_id))
