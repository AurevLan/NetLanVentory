"""ScheduledReport model — recurring email report configuration."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from netlanventory.models.base import Base


class ScheduledReport(Base):
    __tablename__ = "scheduled_reports"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    name: Mapped[str] = mapped_column(String(100), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")

    # executive | full | cve_summary
    report_type: Mapped[str] = mapped_column(String(30), nullable=False, server_default="executive")

    # daily | weekly | monthly
    schedule: Mapped[str] = mapped_column(String(20), nullable=False, server_default="weekly")

    # List of email addresses
    recipients: Mapped[list | None] = mapped_column(JSONB, nullable=True, server_default="[]")

    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<ScheduledReport name={self.name!r} schedule={self.schedule!r}>"
