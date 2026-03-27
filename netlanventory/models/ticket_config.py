"""TicketConfig model — Jira / ServiceNow integration configuration."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, Text, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from netlanventory.models.base import Base


class TicketConfig(Base):
    __tablename__ = "ticket_configs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    name: Mapped[str] = mapped_column(String(100), nullable=False)

    # jira | servicenow
    type: Mapped[str] = mapped_column(String(20), nullable=False)

    # Base URL of the Jira/ServiceNow instance
    base_url: Mapped[str] = mapped_column(Text, nullable=False)

    # Fernet-encrypted API token
    api_token_enc: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Jira project key or ServiceNow table name
    project_key: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Username for Basic auth (Jira Cloud uses email + API token)
    username: Mapped[str | None] = mapped_column(String(255), nullable=True)

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<TicketConfig name={self.name!r} type={self.type!r}>"
