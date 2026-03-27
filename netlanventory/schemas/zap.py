"""Schemas for ZAP scan requests and responses."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, model_validator


# ── Request ───────────────────────────────────────────────────────────────────

class ZapScanRequest(BaseModel):
    target_url: AnyHttpUrl = Field(..., description="URL to scan (e.g. http://192.168.1.1)")
    spider: bool = Field(True, description="Run ZAP spider before passive scan")
    active_scan: bool = Field(False, description="Run ZAP active scan after passive scan (slower, more thorough)")


# ── Alert (one ZAP finding) ───────────────────────────────────────────────────

class ZapAlertOut(BaseModel):
    alert: str
    risk: str                     # High / Medium / Low / Informational
    confidence: str
    description: str | None = None
    solution: str | None = None
    reference: str | None = None
    evidence: str | None = None
    cwe_id: str | None = None
    cve_ids: list[str] = []       # CVE-XXXX-XXXXX extracted from reference
    package_name: str | None = None
    package_version: str | None = None
    url: str | None = None


# ── Detected technology ───────────────────────────────────────────────────────

class TechDetectedOut(BaseModel):
    name: str
    version: str | None = None
    category: str = "library"    # server / javascript / language / framework / library
    alert_name: str | None = None


# ── Report ────────────────────────────────────────────────────────────────────

class ZapReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: str
    target_url: str | None
    risk_summary: dict | None = None    # {high, medium, low, informational}
    alerts_count: int | None = None
    cve_count: int = 0
    technologies: list[TechDetectedOut] = []
    error_msg: str | None = None
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="before")
    @classmethod
    def _compute_fields(cls, data: Any) -> Any:
        """Derive computed fields from the stored report JSON when loading from ORM."""
        if hasattr(data, "report") and data.report:
            report = data.report or {}
            alerts = report.get("alerts", [])
            data.__dict__["alerts_count"] = len(alerts)
            data.__dict__["technologies"] = report.get("technologies", [])
        return data


class ZapReportDetail(ZapReportOut):
    alerts: list[ZapAlertOut] = []


# ── CVE as seen from an asset ─────────────────────────────────────────────────

class AssetCveOut(BaseModel):
    """Serialises an AssetCve ORM row (which has a .cve relationship)."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source: str | None = None       # "zap" | "ssh" | "nuclei" | "trivy"
    package_name: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None
    discovered_at: datetime

    # Acknowledgment fields
    ack_status: str = "none"        # none | accepted | false_positive | in_progress
    ack_note: str | None = None
    ack_by: str | None = None
    ack_at: datetime | None = None

    # Flattened from the related Cve row
    cve_id_str: str = ""
    description: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    remediation: str | None = None

    # Exploit verification
    exploit_verified: bool | None = None
    exploit_verified_at: datetime | None = None

    @classmethod
    def from_orm_with_cve(cls, obj: object) -> "AssetCveOut":
        """Build from an AssetCve ORM instance that has .cve loaded."""
        cve = getattr(obj, "cve", None)
        return cls(
            id=obj.id,  # type: ignore[attr-defined]
            source=obj.source,  # type: ignore[attr-defined]
            package_name=obj.package_name,  # type: ignore[attr-defined]
            package_version=obj.package_version,  # type: ignore[attr-defined]
            fixed_version=obj.fixed_version,  # type: ignore[attr-defined]
            discovered_at=obj.discovered_at,  # type: ignore[attr-defined]
            ack_status=getattr(obj, "ack_status", "none") or "none",
            ack_note=getattr(obj, "ack_note", None),
            ack_by=getattr(obj, "ack_by", None),
            ack_at=getattr(obj, "ack_at", None),
            cve_id_str=cve.cve_id if cve else "",
            description=cve.description if cve else None,
            severity=cve.severity if cve else None,
            cvss_score=cve.cvss_score if cve else None,
            remediation=getattr(cve, "remediation", None) if cve else None,
            exploit_verified=getattr(obj, "exploit_verified", None),
            exploit_verified_at=getattr(obj, "exploit_verified_at", None),
        )
