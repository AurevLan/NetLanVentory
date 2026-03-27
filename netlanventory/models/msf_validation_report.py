"""MsfValidationReport model — Metasploit-based exploit validation results."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class MsfValidationReport(Base):
    __tablename__ = "msf_validation_reports"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # pending / running / completed / failed
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")

    cves_tested: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    cves_confirmed: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    cves_not_confirmed: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    cves_no_module: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    # JSON list of per-CVE results:
    # [
    #   {
    #     "cve_id": "CVE-2021-44228",
    #     "module": "exploit/multi/http/log4shell_header_injection",
    #     "result": "vulnerable" | "not_vulnerable" | "no_module" | "check_unsupported" | "error",
    #     "output": "The target is vulnerable.",
    #   },
    #   ...
    # ]
    results: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    asset: Mapped["Asset"] = relationship("Asset", back_populates="msf_validation_reports")  # noqa: F821

    def __repr__(self) -> str:
        return (
            f"<MsfValidationReport asset={self.asset_id} status={self.status!r} "
            f"confirmed={self.cves_confirmed}/{self.cves_tested}>"
        )
