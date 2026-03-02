"""NucleiReport model — stores Nuclei scan results linked to an asset."""

from __future__ import annotations

import uuid

from sqlalchemy import JSON, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class NucleiReport(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "nuclei_reports"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # pending / running / completed / failed
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="pending"
    )

    # Auto-determined scan targets (IPs, URLs, FQDNs) derived from discovered ports/services
    targets: Mapped[list | None] = mapped_column(JSON, nullable=True)

    # Nuclei template tags used (e.g. ["cve", "http", "smb"])
    tags: Mapped[list | None] = mapped_column(JSON, nullable=True)

    # Full parsed findings list: {"findings": [...]}
    report: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # e.g. {"critical": 1, "high": 2, "medium": 5, "low": 3, "info": 8}
    risk_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    # Count of unique CVEs persisted from this scan
    cve_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False, server_default="0")

    # Total findings (including non-CVE findings)
    findings_count: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False, server_default="0"
    )

    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    asset: Mapped[Asset] = relationship("Asset", back_populates="nuclei_reports")  # noqa: F821

    def __repr__(self) -> str:
        return f"<NucleiReport asset={self.asset_id} status={self.status!r}>"
