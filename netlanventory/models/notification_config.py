"""NotificationConfig model — webhook / alerting configuration."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from netlanventory.models.base import Base


class NotificationConfig(Base):
    __tablename__ = "notification_configs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False
    )

    name: Mapped[str] = mapped_column(String(255), nullable=False)

    # webhook / email (email reserved for future)
    type: Mapped[str] = mapped_column(String(20), nullable=False, server_default="webhook")

    # Destination URL (webhook endpoint)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")

    # List of subscribed event names (JSON array)
    events: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    # HMAC-SHA256 secret for webhook signature
    secret: Mapped[str | None] = mapped_column(String(255), nullable=True)

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

    def __repr__(self) -> str:
        return f"<NotificationConfig name={self.name!r} type={self.type!r} enabled={self.enabled}>"
