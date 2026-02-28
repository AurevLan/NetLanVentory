"""Schemas for Asset, Port, and DNS resources."""

from __future__ import annotations

import ipaddress
import re as _re
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from netlanventory.schemas.zap import AssetCveOut, ZapReportOut  # noqa: F401 (re-exported)

# RFC-1123 hostname label: each label is 1-63 alnum chars, may contain hyphens (not at start/end)
_FQDN_RE = _re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)
_MAC_RE = _re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


class PortOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    port_number: int
    protocol: str
    state: str
    service_name: str | None
    version: str | None
    banner: str | None
    created_at: datetime
    updated_at: datetime


class AssetDnsOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    fqdn: str
    created_at: datetime


class AssetDnsCreate(BaseModel):
    fqdn: str = Field(..., min_length=1, max_length=255)

    @field_validator("fqdn")
    @classmethod
    def _validate_fqdn(cls, v: str) -> str:
        if not _FQDN_RE.match(v):
            raise ValueError(f"Invalid FQDN: {v!r}")
        return v


class AssetVocabularyOut(BaseModel):
    os_family: list[str] = []
    device_type: list[str] = []


class AssetBase(BaseModel):
    name: str | None = None
    mac: str | None = None
    ip: str | None = None
    hostname: str | None = None
    vendor: str | None = None
    device_type: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    ssh_user: str | None = None
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    notes: str | None = None
    # Write-only SSH credentials — accepted on create/update, never echoed back
    ssh_password: str | None = Field(default=None, exclude=True)
    ssh_private_key: str | None = Field(default=None, exclude=True)

    @field_validator("ip", mode="before")
    @classmethod
    def _validate_ip(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v!r}")
        return v

    @field_validator("mac", mode="before")
    @classmethod
    def _validate_mac(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not _MAC_RE.match(v):
            raise ValueError(f"Invalid MAC address (expected XX:XX:XX:XX:XX:XX): {v!r}")
        return v


class AssetCreate(AssetBase):
    pass


class AssetUpdate(AssetBase):
    is_active: bool | None = None
    zap_auto_scan_enabled: bool | None = None
    zap_scan_interval_minutes: int | None = None


class AssetOut(AssetBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    is_active: bool
    last_seen: datetime | None
    created_at: datetime
    updated_at: datetime

    # ZAP auto-scan settings
    zap_auto_scan_enabled: bool | None = None
    zap_scan_interval_minutes: int | None = None
    zap_last_auto_scan_at: datetime | None = None

    # SSH credential presence flags — never expose the ciphertext
    has_ssh_password: bool = False
    has_ssh_key: bool = False

    # Relationships
    ports: list[PortOut] = []
    cves: list[AssetCveOut] = []
    zap_reports: list[ZapReportOut] = []
    dns_entries: list[AssetDnsOut] = []

    @model_validator(mode="before")
    @classmethod
    def _prepare_orm(cls, data: Any) -> Any:
        """Flatten ORM AssetCve relations and compute SSH credential presence flags."""
        if hasattr(data, "cves"):
            data.__dict__["cves"] = [
                AssetCveOut.from_orm_with_cve(c) for c in (data.cves or [])
            ]
        if hasattr(data, "ssh_password_enc"):
            data.__dict__["has_ssh_password"] = bool(data.ssh_password_enc)
        if hasattr(data, "ssh_private_key_enc"):
            data.__dict__["has_ssh_key"] = bool(data.ssh_private_key_enc)
        return data


class AssetList(BaseModel):
    total: int
    items: list[AssetOut]
