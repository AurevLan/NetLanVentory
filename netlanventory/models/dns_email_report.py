"""DnsEmailReport model — DNS/email security audit results (SPF/DKIM/DMARC)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class DnsEmailReport(Base):
    __tablename__ = "dns_email_reports"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # {spf: {record, valid, issues}, dkim: {selectors_found, records}, dmarc: {record, policy, issues}}
    findings: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    asset: Mapped["Asset"] = relationship("Asset", back_populates="dns_email_reports")  # noqa: F821

    def __repr__(self) -> str:
        return f"<DnsEmailReport asset={self.asset_id} domain={self.domain!r} status={self.status!r}>"
