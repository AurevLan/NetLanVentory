"""testssl.sh report model — stores deep TLS/SSL audit results."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class TestsslReport(Base):
    __tablename__ = "testssl_reports"

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

    # pending / running / completed / failed
    status: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Overall grade assigned by testssl (A+, A, B, C, F …)
    grade: Mapped[str | None] = mapped_column(String(10), nullable=True)

    # Aggregated issue counts by severity
    critical_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    high_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    medium_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    low_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    info_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    # Full testssl JSON output (array of finding objects)
    findings: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    asset: Mapped["Asset"] = relationship("Asset", back_populates="testssl_reports")  # noqa: F821

    def __repr__(self) -> str:
        return f"<TestsslReport asset={self.asset_id} host={self.host!r} grade={self.grade!r}>"
