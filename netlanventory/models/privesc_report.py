"""PrivescReport model — privileged access and escalation audit results."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class PrivescReport(Base):
    __tablename__ = "privesc_reports"

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
    users_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    sudoers_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    suid_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    sgid_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    capabilities_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    authorized_keys_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    writable_paths_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    risk_findings_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    # Detailed findings as JSONB
    # {
    #   "users": [{"name": "root", "uid": 0, "gid": 0, "shell": "/bin/bash", "home": "/root"}, ...],
    #   "sudoers": [{"user": "admin", "rule": "ALL=(ALL) NOPASSWD: ALL", "risky": true}, ...],
    #   "suid_binaries": ["/usr/bin/sudo", "/usr/bin/passwd", ...],
    #   "sgid_binaries": ["/usr/bin/wall", ...],
    #   "capabilities": [{"path": "/usr/bin/ping", "caps": "cap_net_raw=ep"}, ...],
    #   "authorized_keys": [{"user": "root", "keys_count": 2, "keys": ["ssh-rsa AAAA..."]}, ...],
    #   "writable_paths": ["/tmp/script.sh", "/var/www/upload/..."],
    #   "risk_findings": [
    #     {"severity": "critical", "finding": "NOPASSWD sudo for user admin", "detail": "..."},
    #     {"severity": "high", "finding": "SUID on /usr/bin/python3", "detail": "GTFOBins privesc"},
    #   ],
    #   "passwd_hash_exposure": true,
    #   "empty_password_users": ["nobody"],
    #   "nologin_shell_users": 25,
    #   "root_login_allowed": true,
    # }
    findings: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    asset: Mapped["Asset"] = relationship("Asset", back_populates="privesc_reports")  # noqa: F821

    def __repr__(self) -> str:
        return f"<PrivescReport asset={self.asset_id} status={self.status!r} risks={self.risk_findings_count}>"
