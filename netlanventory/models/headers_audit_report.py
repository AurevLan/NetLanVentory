"""HeadersAuditReport model — HTTP security headers audit results."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class HeadersAuditReport(Base):
    __tablename__ = "headers_audit_reports"

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

    # pending / running / completed / failed
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")

    # 0–100: percentage of required security headers present and correctly configured
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # JSON structure:
    # {
    #   "present": ["Strict-Transport-Security", ...],
    #   "missing": ["Content-Security-Policy", ...],
    #   "misconfigured": [{"header": "Access-Control-Allow-Origin", "value": "*", "reason": "wildcard"}],
    #   "details": {"Strict-Transport-Security": "max-age=31536000; includeSubDomains", ...},
    #   "active_scan": bool,
    #   "active_scan_alerts": [...],   # ZAP active scan alerts if triggered
    # }
    findings: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    asset: Mapped["Asset"] = relationship("Asset", back_populates="headers_audit_reports")  # noqa: F821

    def __repr__(self) -> str:
        return f"<HeadersAuditReport asset={self.asset_id} status={self.status!r} score={self.score}>"
