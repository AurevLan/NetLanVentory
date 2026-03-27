"""AssetBaseline model — point-in-time snapshot for drift detection."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class AssetBaseline(Base):
    __tablename__ = "asset_baselines"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Snapshots stored as JSON
    ports_snapshot: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    packages_snapshot: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    cves_snapshot: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationship
    asset: Mapped["Asset"] = relationship("Asset", back_populates="baselines")  # noqa: F821

    def __repr__(self) -> str:
        return f"<AssetBaseline asset={self.asset_id} created_at={self.created_at}>"
