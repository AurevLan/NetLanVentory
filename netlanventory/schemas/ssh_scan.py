"""Schemas for SSH CVE scan reports."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SshScanReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    status: str          # "pending" | "running" | "completed" | "failed"
    os_type: str | None = None
    packages_found: int | None = None
    cves_found: int | None = None
    error_msg: str | None = None
    created_at: datetime
    updated_at: datetime


class SshScanCveItem(BaseModel):
    cve_id: str
    severity: str | None = None
    cvss_score: float | None = None
    package_name: str | None = None
    package_version: str | None = None


class SshScanDiffOut(BaseModel):
    new_cves: list[SshScanCveItem] = []
    resolved_cves: list[SshScanCveItem] = []
    common_cves: list[SshScanCveItem] = []
