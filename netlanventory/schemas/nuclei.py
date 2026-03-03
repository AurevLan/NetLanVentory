"""Schemas for Nuclei scan requests and responses."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, model_validator

# ── Finding (one Nuclei template match) ──────────────────────────────────────

class NucleiFindingOut(BaseModel):
    template_id: str                # e.g. "CVE-2021-41773" or "apache-detect"
    name: str                       # info.name
    severity: str                   # critical / high / medium / low / info
    type: str                       # http / dns / tcp / ssl …
    host: str
    matched_at: str | None = None   # Specific URL / endpoint / port matched
    description: str | None = None
    tags: list[str] = []            # info.tags
    cve_ids: list[str] = []         # info.classification.cve-id (canonical CVE IDs)
    cvss_score: float | None = None # info.classification.cvss-score


# ── Report (list view) ────────────────────────────────────────────────────────

class NucleiReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    status: str
    targets: list[str] | None = None   # Targets that were scanned
    tags: list[str] | None = None      # Nuclei tags used
    findings_count: int = 0
    cve_count: int = 0
    risk_summary: dict | None = None   # {critical, high, medium, low, info}
    error_msg: str | None = None
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="before")
    @classmethod
    def _compute_fields(cls, data: Any) -> Any:
        """Derive findings_count from stored report JSON when loading from ORM."""
        if hasattr(data, "report") and data.report:
            report = data.report or {}
            findings = report.get("findings", [])
            if not getattr(data, "findings_count", None):
                data.__dict__["findings_count"] = len(findings)
        return data


# ── Report (detail view) ──────────────────────────────────────────────────────

class NucleiReportDetail(NucleiReportOut):
    findings: list[NucleiFindingOut] = []

    @model_validator(mode="before")
    @classmethod
    def _compute_fields(cls, data: Any) -> Any:
        """Extract findings list from stored report JSON when loading from ORM."""
        # Call parent validator first
        if hasattr(data, "report") and data.report:
            report = data.report or {}
            raw_findings = report.get("findings", [])
            data.__dict__["findings_count"] = len(raw_findings)
            data.__dict__["findings"] = [
                _parse_nuclei_finding(f) for f in raw_findings
            ]
        return data


def _parse_nuclei_finding(raw: dict) -> NucleiFindingOut:
    """Convert a raw Nuclei JSONL finding dict to NucleiFindingOut."""
    info = raw.get("info", {})
    classification = info.get("classification", {})

    # Collect CVE IDs from classification (most reliable) and template-id
    cve_ids: list[str] = []
    raw_cve_ids = classification.get("cve-id") or []
    if isinstance(raw_cve_ids, str):
        raw_cve_ids = [raw_cve_ids]
    cve_ids.extend(raw_cve_ids)

    template_id = raw.get("template-id", "")
    tid_upper = template_id.upper()
    if tid_upper.startswith("CVE-") and tid_upper not in [c.upper() for c in cve_ids]:
        cve_ids.append(tid_upper)

    # Normalise severity
    severity = info.get("severity", "info").lower()

    # CVSS score
    cvss_score: float | None = None
    raw_score = classification.get("cvss-score")
    if raw_score is not None:
        try:
            cvss_score = float(raw_score)
        except (TypeError, ValueError):
            pass

    # Tags
    raw_tags = info.get("tags") or []
    if isinstance(raw_tags, str):
        raw_tags = [t.strip() for t in raw_tags.split(",")]

    return NucleiFindingOut(
        template_id=template_id,
        name=info.get("name", template_id),
        severity=severity,
        type=raw.get("type", "unknown"),
        host=raw.get("host", ""),
        matched_at=raw.get("matched-at"),
        description=info.get("description"),
        tags=raw_tags,
        cve_ids=[c.upper() for c in cve_ids],
        cvss_score=cvss_score,
    )
