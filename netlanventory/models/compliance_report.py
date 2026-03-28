"""ComplianceReport model — framework compliance evaluation results."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from netlanventory.models.base import Base


class ComplianceReport(Base):
    __tablename__ = "compliance_reports"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # iso27001 | nis2 | anssi
    framework: Mapped[str] = mapped_column(String(30), nullable=False, index=True)

    # "global" or an asset group / scope description
    scope: Mapped[str] = mapped_column(String(100), nullable=False, server_default="global")

    # Overall score 0-100
    score: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    # compliant | partial | non-compliant
    status: Mapped[str] = mapped_column(String(30), nullable=False, server_default="partial")

    # Full evaluation data as JSONB
    findings: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<ComplianceReport framework={self.framework!r} score={self.score} status={self.status!r}>"
