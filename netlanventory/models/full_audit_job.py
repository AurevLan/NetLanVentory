"""FullAuditJob model — tracks a full security audit orchestration run on a single asset."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class FullAuditJob(Base):
    __tablename__ = "full_audit_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # pending / running / completed / completed_with_errors / failed
    status: Mapped[str] = mapped_column(String(30), nullable=False, server_default="pending")

    # Per-step tracking:
    # {
    #   "port_scan":           {"status": "completed", "detail": "12 ports", ...},
    #   "testssl":             {"status": "skipped",   "reason":  "no HTTPS"},
    #   "ssh_audit":           {"status": "completed", "detail": "critical: 1"},
    #   "default_creds":       {"status": "completed", "detail": "1 vulnerable"},
    #   "ssh_scan":            {"status": "skipped",   "reason":  "no creds"},
    #   "nuclei":              {"status": "completed", "detail": "5 findings"},
    #   "exploit_validation":  {"status": "completed", "detail": "1/3 confirmed"},
    #   "risk_score":          {"status": "completed", "detail": "score: 82.5"},
    # }
    steps: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # IDs of sub-reports created by this job (nullable — skipped steps leave these null)
    testssl_report_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("testssl_reports.id", ondelete="SET NULL"),
        nullable=True,
    )
    ssh_audit_report_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("ssh_audit_reports.id", ondelete="SET NULL"),
        nullable=True,
    )
    default_creds_report_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("default_creds_reports.id", ondelete="SET NULL"),
        nullable=True,
    )
    ssh_scan_report_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("ssh_scan_reports.id", ondelete="SET NULL"),
        nullable=True,
    )
    nuclei_report_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("nuclei_reports.id", ondelete="SET NULL"),
        nullable=True,
    )

    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    asset: Mapped["Asset"] = relationship("Asset", back_populates="full_audit_jobs")  # noqa: F821

    def __repr__(self) -> str:
        return f"<FullAuditJob asset={self.asset_id} status={self.status!r}>"
