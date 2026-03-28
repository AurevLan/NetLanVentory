"""Schemas for the global CVE library endpoint."""

from __future__ import annotations

import uuid
from datetime import date, datetime

from pydantic import BaseModel, ConfigDict


class CveOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    cve_id: str
    severity: str | None = None
    cvss_score: float | None = None
    description: str | None = None
    published_at: datetime | None = None
    remediation: str | None = None
    asset_count: int = 0
    epss_score: float | None = None
    epss_percentile: float | None = None
    epss_updated_at: datetime | None = None
    # Threat intel
    kev_date_added: date | None = None
    kev_ransomware_use: bool = False
    exploit_db_id: int | None = None
    poc_available: bool = False
    poc_count: int = 0
    exploit_maturity: str = "none"
    threat_intel_updated_at: datetime | None = None

    @classmethod
    def from_orm_row(cls, cve: object, asset_count: int = 0) -> "CveOut":
        return cls(
            id=cve.id,              # type: ignore[attr-defined]
            cve_id=cve.cve_id,     # type: ignore[attr-defined]
            severity=cve.severity, # type: ignore[attr-defined]
            cvss_score=cve.cvss_score,  # type: ignore[attr-defined]
            description=cve.description,  # type: ignore[attr-defined]
            published_at=cve.published_at,  # type: ignore[attr-defined]
            remediation=getattr(cve, "remediation", None),  # type: ignore[attr-defined]
            asset_count=asset_count,
            epss_score=getattr(cve, "epss_score", None),
            epss_percentile=getattr(cve, "epss_percentile", None),
            epss_updated_at=getattr(cve, "epss_updated_at", None),
            kev_date_added=getattr(cve, "kev_date_added", None),
            kev_ransomware_use=getattr(cve, "kev_ransomware_use", False),
            exploit_db_id=getattr(cve, "exploit_db_id", None),
            poc_available=getattr(cve, "poc_available", False),
            poc_count=getattr(cve, "poc_count", 0),
            exploit_maturity=getattr(cve, "exploit_maturity", "none") or "none",
            threat_intel_updated_at=getattr(cve, "threat_intel_updated_at", None),
        )


class CveList(BaseModel):
    total: int
    items: list[CveOut]


class CveAssetLink(BaseModel):
    asset_id: uuid.UUID
    source: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None


class CveDetail(CveOut):
    affected_assets: list[CveAssetLink] = []

    @classmethod
    def from_orm_row(cls, cve: object, links: list) -> "CveDetail":
        return cls(
            id=cve.id,              # type: ignore[attr-defined]
            cve_id=cve.cve_id,     # type: ignore[attr-defined]
            severity=cve.severity, # type: ignore[attr-defined]
            cvss_score=cve.cvss_score,  # type: ignore[attr-defined]
            description=cve.description,  # type: ignore[attr-defined]
            published_at=cve.published_at,  # type: ignore[attr-defined]
            remediation=getattr(cve, "remediation", None),  # type: ignore[attr-defined]
            asset_count=len(links),
            affected_assets=[
                CveAssetLink(
                    asset_id=lnk.asset_id,          # type: ignore[attr-defined]
                    source=lnk.source,               # type: ignore[attr-defined]
                    package_name=lnk.package_name,  # type: ignore[attr-defined]
                    package_version=lnk.package_version,  # type: ignore[attr-defined]
                    fixed_version=lnk.fixed_version,      # type: ignore[attr-defined]
                )
                for lnk in links
            ],
        )
