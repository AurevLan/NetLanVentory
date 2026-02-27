"""ScanResult model — per-module result for a specific asset during a scan."""

import uuid
from typing import Any

from sqlalchemy import JSON, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ScanResult(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "scan_results"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    module_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="success")
    raw_output: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="results")  # noqa: F821
    asset: Mapped["Asset | None"] = relationship("Asset", back_populates="scan_results")  # noqa: F821

    def __repr__(self) -> str:
        return (
            f"<ScanResult module={self.module_name!r} status={self.status!r}>"
        )
