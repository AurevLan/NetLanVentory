"""SavedFilter model — user-saved search/filter presets."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class SavedFilter(Base):
    __tablename__ = "saved_filters"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Display name for this filter preset
    name: Mapped[str] = mapped_column(String(100), nullable=False)

    # Which view this filter applies to: assets | cves | expositions
    view: Mapped[str] = mapped_column(String(30), nullable=False, index=True)

    # Serialized filter state as JSONB
    filters: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    user: Mapped["User"] = relationship("User")  # noqa: F821

    def __repr__(self) -> str:
        return f"<SavedFilter name={self.name!r} view={self.view!r}>"
