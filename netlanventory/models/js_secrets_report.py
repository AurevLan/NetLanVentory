"""JsSecretsReport model — JavaScript bundle secret/API key leak detection."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class JsSecretsReport(Base):
    __tablename__ = "js_secrets_reports"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")
    scripts_scanned: Mapped[int | None] = mapped_column(Integer, nullable=True)
    secrets_found: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # {secrets: [{type, pattern_name, match, script_url, context}], scripts_scanned: [...]}
    findings: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    asset: Mapped["Asset"] = relationship("Asset", back_populates="js_secrets_reports")  # noqa: F821

    def __repr__(self) -> str:
        return f"<JsSecretsReport asset={self.asset_id} secrets={self.secrets_found} status={self.status!r}>"
