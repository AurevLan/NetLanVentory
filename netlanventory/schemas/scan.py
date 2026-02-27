"""Schemas for Scan resources."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ScanCreate(BaseModel):
    target: str = Field(..., description="Target CIDR or IP (e.g. 192.168.1.0/24)")
    modules: list[str] = Field(
        default=["arp_sweep"],
        description="List of module slugs to run",
    )
    options: dict[str, Any] = Field(
        default_factory=dict,
        description="Per-module option overrides keyed by module name",
    )


class ScanResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    module_name: str
    status: str
    raw_output: dict[str, Any] | None
    error_msg: str | None
    asset_id: uuid.UUID | None
    created_at: datetime


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    target: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    modules_run: list[str] | None
    summary: dict[str, Any] | None
    error_msg: str | None
    created_at: datetime
    updated_at: datetime
    results: list[ScanResultOut] = []


class ScanList(BaseModel):
    total: int
    items: list[ScanOut]
