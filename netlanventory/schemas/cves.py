"""Schemas for the global CVE library endpoint."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class CveOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    cve_id: str
    severity: str | None = None
    cvss_score: float | None = None
    description: str | None = None
    published_at: datetime | None = None
    asset_count: int = 0

    @classmethod
    def from_orm_row(cls, cve: object, asset_count: int = 0) -> "CveOut":
        return cls(
            id=cve.id,              # type: ignore[attr-defined]
            cve_id=cve.cve_id,     # type: ignore[attr-defined]
            severity=cve.severity, # type: ignore[attr-defined]
            cvss_score=cve.cvss_score,  # type: ignore[attr-defined]
            description=cve.description,  # type: ignore[attr-defined]
            published_at=cve.published_at,  # type: ignore[attr-defined]
            asset_count=asset_count,
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
