"""ScanQuotaLog model — tracks daily scan counts per user."""

from __future__ import annotations

import uuid
from datetime import date

from sqlalchemy import Date, ForeignKey, Integer, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from netlanventory.models.base import Base, UUIDPrimaryKeyMixin


class ScanQuotaLog(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "scan_quota_logs"

    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_date: Mapped[date] = mapped_column(Date, nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        UniqueConstraint("user_id", "scan_date", name="uq_scan_quota_user_date"),
    )

    def __repr__(self) -> str:
        return f"<ScanQuotaLog user_id={self.user_id} date={self.scan_date} count={self.count}>"
