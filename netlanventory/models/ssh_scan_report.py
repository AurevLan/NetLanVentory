"""SshScanReport model — records each SSH-based CVE scan run against an asset."""

import uuid

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class SshScanReport(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "ssh_scan_reports"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # "pending" | "running" | "completed" | "failed"
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")

    # OS detection result
    os_type: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Scan summary
    packages_found: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cves_found: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Error detail (populated when status == "failed")
    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    asset: Mapped["Asset"] = relationship(  # noqa: F821
        "Asset", back_populates="ssh_scan_reports"
    )

    def __repr__(self) -> str:
        return f"<SshScanReport asset_id={self.asset_id!r} status={self.status!r}>"
