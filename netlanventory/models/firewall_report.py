"""FirewallReport model — host firewall rules audit results."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class FirewallReport(Base):
    __tablename__ = "firewall_reports"

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
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")

    # Detected firewall backend: iptables | nftables | ufw | firewalld | none
    backend: Mapped[str | None] = mapped_column(String(30), nullable=True)

    # Is the firewall active?
    firewall_active: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    # Counters
    rules_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    open_input_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    risk_findings_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    # Detailed findings as JSONB
    # {
    #   "backend": "iptables",
    #   "default_policies": {"INPUT": "ACCEPT", "FORWARD": "DROP", "OUTPUT": "ACCEPT"},
    #   "rules": [
    #     {"chain": "INPUT", "target": "ACCEPT", "proto": "tcp", "dport": "22", "source": "0.0.0.0/0"},
    #     ...
    #   ],
    #   "ufw_status": "active",
    #   "ufw_rules": ["22/tcp ALLOW Anywhere", ...],
    #   "nft_tables": ["inet filter", ...],
    #   "risk_findings": [
    #     {"severity": "critical", "finding": "Default INPUT policy is ACCEPT", "detail": "..."},
    #     {"severity": "high", "finding": "Port 3306 open to 0.0.0.0/0", "detail": "MySQL exposed"},
    #   ],
    #   "zones": {"public": ["ssh", "http"], "internal": ["all"]},
    # }
    findings: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    asset: Mapped["Asset"] = relationship("Asset", back_populates="firewall_reports")  # noqa: F821

    def __repr__(self) -> str:
        return f"<FirewallReport asset={self.asset_id} backend={self.backend!r} active={self.firewall_active}>"
