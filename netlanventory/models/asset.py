"""Asset model — represents a discovered network device."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Asset(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "assets"

    # Custom label (user-defined)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Network identifiers
    mac: Mapped[str | None] = mapped_column(String(17), unique=True, nullable=True, index=True)
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Hardware / vendor info
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    device_type: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # OS fingerprint
    os_family: Mapped[str | None] = mapped_column(String(100), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # SSH access
    ssh_user: Mapped[str | None] = mapped_column(String(100), nullable=True)
    ssh_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Encrypted credentials — never returned in plain text via API
    ssh_password_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    ssh_private_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Free-text notes
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # ZAP auto-scan (None = inherit global setting)
    zap_auto_scan_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    zap_scan_interval_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    zap_last_auto_scan_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    ports: Mapped[list["Port"]] = relationship(  # noqa: F821
        "Port", back_populates="asset", cascade="all, delete-orphan"
    )
    scan_results: Mapped[list["ScanResult"]] = relationship(  # noqa: F821
        "ScanResult", back_populates="asset", cascade="all, delete-orphan"
    )
    cves: Mapped[list["AssetCve"]] = relationship(  # noqa: F821
        "AssetCve", back_populates="asset", cascade="all, delete-orphan"
    )
    zap_reports: Mapped[list["ZapReport"]] = relationship(  # noqa: F821
        "ZapReport", back_populates="asset", cascade="all, delete-orphan"
    )
    dns_entries: Mapped[list["AssetDns"]] = relationship(  # noqa: F821
        "AssetDns", back_populates="asset", cascade="all, delete-orphan"
    )
    ssh_scan_reports: Mapped[list["SshScanReport"]] = relationship(  # noqa: F821
        "SshScanReport", back_populates="asset", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Asset ip={self.ip!r} mac={self.mac!r}>"
