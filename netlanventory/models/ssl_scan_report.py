"""SSL scan report model — stores TLS/SSL certificate inspection results."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class SslScanReport(Base):
    __tablename__ = "ssl_scan_reports"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False, server_default="443")

    # valid / expiring / expired / invalid / error
    status: Mapped[str | None] = mapped_column(String(20), nullable=True)

    subject: Mapped[str | None] = mapped_column(String(500), nullable=True)
    issuer: Mapped[str | None] = mapped_column(String(500), nullable=True)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    days_remaining: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # TLS 1.2, TLS 1.3, etc.
    protocol_version: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cipher_suite: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # List of issues detected (JSON array of strings)
    issues: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    # Raw certificate data
    raw_data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationship
    asset: Mapped["Asset"] = relationship("Asset", back_populates="ssl_scan_reports")  # noqa: F821

    def __repr__(self) -> str:
        return f"<SslScanReport asset={self.asset_id} host={self.host!r} status={self.status!r}>"
