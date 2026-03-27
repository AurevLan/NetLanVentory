"""Scheduled network scan — recurring automatic rescans of target ranges."""

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from netlanventory.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ScheduledScan(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "scheduled_scans"

    # Human-readable label
    name: Mapped[str] = mapped_column(String(100), nullable=False)

    # Target CIDR or range (e.g. "192.168.1.0/24", "10.0.0.0/8")
    target: Mapped[str] = mapped_column(String(100), nullable=False)

    # Modules to run (comma-separated: "arp_sweep,port_scanner,service_detector,os_fingerprint")
    modules: Mapped[str] = mapped_column(
        String(500),
        nullable=False,
        default="arp_sweep,port_scanner,service_detector,os_fingerprint",
    )

    # Schedule
    interval_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Execution state
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    # Stats
    run_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
