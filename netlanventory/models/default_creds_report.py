"""Default credentials scan report model."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class DefaultCredsReport(Base):
    __tablename__ = "default_creds_reports"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # pending / running / completed / failed
    status: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Number of services where default creds were found
    vulnerable_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    # Number of services tested
    tested_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    # List of findings: [{service, port, credential, result}]
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

    asset: Mapped["Asset"] = relationship("Asset", back_populates="default_creds_reports")  # noqa: F821

    def __repr__(self) -> str:
        return (
            f"<DefaultCredsReport asset={self.asset_id} "
            f"vulnerable={self.vulnerable_count}/{self.tested_count}>"
        )
