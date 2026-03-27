"""Schemas for SshProfile admin CRUD."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class SshProfileCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    ssh_user: str = Field(..., min_length=1, max_length=100)
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    # Write-only credentials — never echoed back
    ssh_password: str | None = Field(default=None, exclude=True)
    ssh_private_key: str | None = Field(default=None, exclude=True)


class SshProfileUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    ssh_user: str | None = Field(default=None, min_length=1, max_length=100)
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    # None = keep existing; non-empty string = overwrite; "" = clear
    ssh_password: str | None = Field(default=None, exclude=True)
    ssh_private_key: str | None = Field(default=None, exclude=True)


class SshProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    ssh_user: str
    ssh_port: int | None
    has_password: bool = False
    has_key: bool = False
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_orm_safe(cls, obj: object) -> SshProfileOut:
        instance = cls.model_validate(obj)
        instance.has_password = bool(getattr(obj, "ssh_password_enc", None))
        instance.has_key = bool(getattr(obj, "ssh_private_key_enc", None))
        return instance
