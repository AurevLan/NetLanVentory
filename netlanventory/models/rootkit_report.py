"""RootkitReport model — rootkit detection scan results."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class RootkitReport(Base):
    __tablename__ = "rootkit_reports"

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

    # Which tool was used: chkrootkit | rkhunter | both
    tool_used: Mapped[str | None] = mapped_column(String(30), nullable=True)

    # Counters
    suspects_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    warnings_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    infected_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    # Detailed findings as JSONB
    # {
    #   "chkrootkit": {
    #     "available": true,
    #     "infected": ["Suckit rootkit... INFECTED"],
    #     "suspects": ["Checking `bindshell'... INFECTED"],
    #     "not_infected": ["Checking `amd'... not infected"],
    #     "not_tested": [...],
    #   },
    #   "rkhunter": {
    #     "available": true,
    #     "warnings": [
    #       {"test": "filesystem", "detail": "/usr/bin/lwp-request [ Warning ]"},
    #     ],
    #     "infected": [],
    #     "system_checks": {
    #       "rootkits_checked": 478,
    #       "possible_rootkits": 0,
    #       "trojans_checked": 25,
    #     },
    #   },
    #   "suspicious_files": ["/dev/.hdd", "/tmp/.ice-unix/..."],
    #   "hidden_processes": [],
    #   "hidden_ports": [],
    # }
    findings: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    asset: Mapped["Asset"] = relationship("Asset", back_populates="rootkit_reports")  # noqa: F821

    def __repr__(self) -> str:
        return f"<RootkitReport asset={self.asset_id} suspects={self.suspects_count} infected={self.infected_count}>"
