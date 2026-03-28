"""Schemas for the remediation plan endpoint."""

from __future__ import annotations

from pydantic import BaseModel


class RemediationGroup(BaseModel):
    rank: int
    action: str
    package_name: str | None
    fixed_version: str | None
    cve_ids: list[str]
    affected_assets: int
    asset_ids: list[str]
    severity_breakdown: dict[str, int]
    in_kev: bool
    epss_max: float
    exploit_verified: bool
    sla_breached_count: int
    risk_score: float
    sources: list[str]
    criticality_max: str


class RemediationPlanResponse(BaseModel):
    total_groups: int
    filters_applied: dict
    groups: list[RemediationGroup]
