"""GlobalSettings model — singleton row for app-wide configuration."""

from __future__ import annotations

from sqlalchemy import Boolean, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from netlanventory.models.base import Base, TimestampMixin


class GlobalSettings(TimestampMixin, Base):
    __tablename__ = "global_settings"

    # Always 1 — singleton pattern
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1, nullable=False)

    # ZAP auto-scan global settings
    zap_auto_scan_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    zap_scan_interval_minutes: Mapped[int] = mapped_column(
        Integer, default=60, nullable=False
    )

    # Passive discovery settings
    passive_discovery_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, server_default="false"
    )
    passive_interface: Mapped[str | None] = mapped_column(
        String(50), nullable=True, server_default="eth0"
    )

    def __repr__(self) -> str:
        return (
            f"<GlobalSettings zap_auto_scan={self.zap_auto_scan_enabled}"
            f" interval={self.zap_scan_interval_minutes}min>"
        )
