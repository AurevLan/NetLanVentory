"""Schemas for User and Auth resources."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=2, max_length=100)
    password: str = Field(..., min_length=8)
    full_name: str | None = None
    role: str = Field(default="user", pattern="^(admin|user)$")


class UserUpdate(BaseModel):
    full_name: str | None = None
    is_active: bool | None = None
    # Only admins may change roles; password changes use a dedicated field
    role: str | None = Field(default=None, pattern="^(admin|user)$")
    password: str | None = Field(default=None, min_length=8)


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    username: str
    full_name: str | None
    role: str
    is_active: bool
    auth_provider: str
    created_at: datetime
    updated_at: datetime


class UserList(BaseModel):
    total: int
    items: list[UserOut]


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut
