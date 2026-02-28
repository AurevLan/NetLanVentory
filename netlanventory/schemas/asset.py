"""Schemas for Asset, Port, and DNS resources."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from netlanventory.schemas.zap import AssetCveOut, ZapReportOut  # noqa: F401 (re-exported)


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
    ssh_port: int | None = None
    notes: str | None = None


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

    # Relationships
    ports: list[PortOut] = []
    cves: list[AssetCveOut] = []
    zap_reports: list[ZapReportOut] = []
    dns_entries: list[AssetDnsOut] = []

    @model_validator(mode="before")
    @classmethod
    def _flatten_cves(cls, data: Any) -> Any:
        """Convert ORM AssetCve instances to AssetCveOut (flattening the .cve relation)."""
        if hasattr(data, "cves"):
            data.__dict__["cves"] = [
                AssetCveOut.from_orm_with_cve(c) for c in (data.cves or [])
            ]
        return data


class AssetList(BaseModel):
    total: int
    items: list[AssetOut]
