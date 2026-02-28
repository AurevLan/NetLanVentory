"""ZapReport model — stores OWASP ZAP scan results linked to an asset."""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Integer, JSON, String, Text
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ZapReport(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "zap_reports"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Optional: the scan that triggered this ZAP run
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
    )

    # pending / running / completed / failed
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="pending"
    )

    # The URL or IP that was scanned
    target_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Full ZAP JSON report
    report: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # e.g. {"high": 2, "medium": 5, "low": 12, "informational": 8}
    risk_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Count of CVEs found during this scan (populated by _persist_cves)
    cve_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False, server_default="0")

    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    asset: Mapped["Asset"] = relationship("Asset", back_populates="zap_reports")  # noqa: F821

    def __repr__(self) -> str:
        return f"<ZapReport asset={self.asset_id} status={self.status!r}>"
