"""AssetCve junction — links a CVE to an asset with discovery context."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, String, Text, func
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class AssetCve(Base):
    __tablename__ = "asset_cves"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cve_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cves.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # 'ssh' = found via package audit, 'zap' = found via OWASP ZAP
    source: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Package that carries the vulnerability (SSH source)
    package_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    package_version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(100), nullable=True)

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Acknowledgment — none | accepted | false_positive | in_progress
    ack_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="none"
    )
    ack_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    ack_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ack_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # SLA remediation tracking
    sla_deadline: Mapped[datetime | None] = mapped_column(Date(), nullable=True)
    sla_breached: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")

    # Exploit verification — did Nuclei confirm the CVE is actually exploitable?
    # None = never tested, True = confirmed exploitable, False = tested / not confirmed
    exploit_verified: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    exploit_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exploit_verified_method: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Ticket tracking (Jira / ServiceNow)
    ticket_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    ticket_url: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ── Remediation workflow ─────────────────────────────────────────────
    # Status: open → planned → in_progress → resolved | blocked
    remediation_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="open"
    )
    assigned_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    remediation_due_date: Mapped[datetime | None] = mapped_column(Date(), nullable=True)
    remediation_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    remediation_resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    remediation_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    asset: Mapped["Asset"] = relationship("Asset", back_populates="cves")  # noqa: F821
    cve: Mapped["Cve"] = relationship("Cve", back_populates="asset_cves")  # noqa: F821

    def __repr__(self) -> str:
        return f"<AssetCve asset={self.asset_id} cve={self.cve_id} source={self.source!r}>"
