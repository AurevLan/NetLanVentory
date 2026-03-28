"""HardeningReport model — system hardening audit results (Lynis + CIS checks via SSH)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class HardeningReport(Base):
    __tablename__ = "hardening_reports"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # pending / running / completed / failed / skipped
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")

    # "full" = Lynis + CIS checks  |  "lynis" = Lynis only
    scan_type: Mapped[str] = mapped_column(String(20), nullable=False, server_default="full")

    # Lynis hardening index (0–100), None if Lynis not available
    lynis_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    warnings_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    suggestions_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    # CIS Benchmark mapping (added in 0041)
    cis_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cis_level: Mapped[str | None] = mapped_column(String(5), nullable=True)
    cis_findings: Mapped[list | None] = mapped_column(JSONB, nullable=True, server_default="[]")

    # JSON structure:
    # {
    #   "lynis_available": bool,
    #   "warnings": [str, ...],
    #   "suggestions": [str, ...],
    #   "cis_checks": {
    #     "world_writable_files": [str, ...],
    #     "suid_binaries": [str, ...],
    #     "ssh_config": {"PermitRootLogin": "yes", "PasswordAuthentication": "yes"},
    #     "password_policy": {"PASS_MAX_DAYS": "99999", ...},
    #     "cron_entries": str,
    #   }
    # }
    findings: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    asset: Mapped["Asset"] = relationship("Asset", back_populates="hardening_reports")  # noqa: F821

    def __repr__(self) -> str:
        return f"<HardeningReport asset={self.asset_id} status={self.status!r} lynis_index={self.lynis_index}>"
