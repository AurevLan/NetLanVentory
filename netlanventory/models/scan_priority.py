"""ScanPriority model — priority queue for the smart re-scan scheduler.

One row per (asset, module). The scheduler pops the top-N by score whose
`next_eligible_at` is past, runs the scan, then resets the row. A nightly
sweep forces re-scan on rows older than `max_age_hours` regardless of score
to prevent starvation.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from netlanventory.models.base import Base


class ScanPriority(Base):
    __tablename__ = "scan_priorities"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    module: Mapped[str] = mapped_column(String(50), primary_key=True, nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False, server_default="1.0")
    last_score_update: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_scan_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_eligible_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    max_age_hours: Mapped[int] = mapped_column(Integer, nullable=False, server_default="72")

    __table_args__ = (
        Index("ix_scan_priorities_eligible_score", "next_eligible_at", "score"),
    )

    def __repr__(self) -> str:
        return f"<ScanPriority {self.asset_id} {self.module} score={self.score:.1f}>"
