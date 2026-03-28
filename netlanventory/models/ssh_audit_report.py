"""ssh-audit report model — stores SSH configuration audit results."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class SshAuditReport(Base):
    __tablename__ = "ssh_audit_reports"

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
    port: Mapped[int] = mapped_column(Integer, nullable=False, server_default="22")

    # pending / running / completed / failed
    status: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # SSH server banner / version
    banner: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Aggregated issue counts
    critical_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    high_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    medium_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    low_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    # Parsed algorithm lists (for quick display)
    kex_algorithms: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    encryption_algorithms: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    mac_algorithms: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    host_key_algorithms: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    # Full ssh-audit JSON output
    raw_output: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Recommendations list
    recommendations: Mapped[list | None] = mapped_column(JSONB, nullable=True)

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

    asset: Mapped["Asset"] = relationship("Asset", back_populates="ssh_audit_reports")  # noqa: F821

    def __repr__(self) -> str:
        return f"<SshAuditReport asset={self.asset_id} host={self.host!r} status={self.status!r}>"
