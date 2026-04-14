"""AuthLogReport model — authentication log analysis results."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class AuthLogReport(Base):
    __tablename__ = "auth_log_reports"

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

    # Counters
    failed_logins_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    successful_logins_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    unique_source_ips: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    brute_force_sources: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    risk_findings_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    # Detailed findings as JSONB
    # {
    #   "log_source": "journalctl" | "auth.log" | "secure",
    #   "analysis_period": {"from": "2026-03-20T00:00:00Z", "to": "2026-03-28T12:00:00Z"},
    #   "failed_logins": {
    #     "total": 1523,
    #     "by_user": {"root": 890, "admin": 210, "test": 150, ...},
    #     "by_source_ip": {"45.33.32.156": 500, "103.21.45.2": 320, ...},
    #     "by_service": {"sshd": 1200, "su": 50, "sudo": 10, ...},
    #   },
    #   "successful_logins": {
    #     "total": 42,
    #     "by_user": {"deploy": 20, "admin": 15, ...},
    #     "recent": [
    #       {"user": "admin", "source": "192.168.1.10", "time": "2026-03-28T10:15:00Z", "service": "sshd"},
    #     ],
    #   },
    #   "brute_force_suspects": [
    #     {"ip": "45.33.32.156", "attempts": 500, "period_minutes": 60, "targeted_users": ["root"]},
    #   ],
    #   "last_logins": [
    #     {"user": "root", "tty": "pts/0", "source": "192.168.1.1", "time": "2026-03-28T09:00:00Z"},
    #   ],
    #   "risk_findings": [
    #     {"severity": "critical", "finding": "Active brute-force from 45.33.32.156", "detail": "500 attempts in 60min"},
    #     {"severity": "high", "finding": "Successful root login from external IP", "detail": "..."},
    #   ],
    # }
    findings: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    asset: Mapped["Asset"] = relationship("Asset", back_populates="auth_log_reports")  # noqa: F821

    def __repr__(self) -> str:
        return f"<AuthLogReport asset={self.asset_id} failed={self.failed_logins_count} brute_force={self.brute_force_sources}>"
