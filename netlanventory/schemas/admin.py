"""Schemas for the Admin panel — OIDC config and auth settings."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class OidcProviderOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    enabled: bool
    issuer_url: str | None
    client_id: str | None
    # Secret is masked in responses
    client_secret_set: bool = False
    scopes: str
    auto_create_users: bool
    default_role: str
    updated_at: datetime

    @classmethod
    def from_orm_masked(cls, obj) -> "OidcProviderOut":
        data = cls.model_validate(obj).model_dump()
        data["client_secret_set"] = bool(obj.client_secret)
        return cls(**data)


class OidcProviderUpdate(BaseModel):
    name: str = Field(default="SSO", min_length=1, max_length=100)
    enabled: bool = False
    issuer_url: str | None = None
    client_id: str | None = None
    # None = keep existing secret; empty string = clear it
    client_secret: str | None = None
    scopes: str = "openid email profile"
    auto_create_users: bool = True
    default_role: str = Field(default="user", pattern="^(admin|user)$")


class AuthSettingsOut(BaseModel):
    jwt_algorithm: str
    jwt_access_token_expire_minutes: int
    oidc_enabled_in_env: bool
    note: str = (
        "JWT settings are read from environment variables. "
        "Edit .env and restart the container to apply changes."
    )


class OidcTestResult(BaseModel):
    success: bool
    message: str
    discovery_url: str | None = None
    endpoints: dict | None = None


class GlobalSettingsOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    zap_auto_scan_enabled: bool
    zap_scan_interval_minutes: int


class GlobalSettingsUpdate(BaseModel):
    zap_auto_scan_enabled: bool = False
    zap_scan_interval_minutes: int = Field(default=60, ge=1, le=10080)
