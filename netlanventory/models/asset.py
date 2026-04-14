"""Asset model — represents a discovered network device."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, Uuid, func
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

    # SSH profile (optional — profile credentials used as fallback when no per-asset creds)
    ssh_profile_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("ssh_profiles.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Asset criticality and computed risk score
    criticality: Mapped[str] = mapped_column(String(20), nullable=False, server_default="medium")
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Free-text notes
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # How this asset was discovered: manual | arp_sweep | passive | ldap | aws | azure | gcp
    discovery_source: Mapped[str | None] = mapped_column(String(30), nullable=True, server_default="manual")

    # ZAP auto-scan (None = inherit global setting)
    zap_auto_scan_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    zap_scan_interval_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    zap_last_auto_scan_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # SSH auto-scan (per-asset recurring SSH CVE scans)
    ssh_auto_scan_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ssh_scan_interval_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ssh_last_auto_scan_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Trivy auto-scan (per-asset recurring Trivy Docker scans)
    trivy_auto_scan_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    trivy_scan_interval_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    trivy_last_auto_scan_at: Mapped[datetime | None] = mapped_column(
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
    nuclei_reports: Mapped[list["NucleiReport"]] = relationship(  # noqa: F821
        "NucleiReport", back_populates="asset", cascade="all, delete-orphan"
    )
    ssh_profile: Mapped["SshProfile | None"] = relationship(  # noqa: F821
        "SshProfile", back_populates="assets"
    )
    trivy_docker_reports: Mapped[list["TrivyDockerReport"]] = relationship(  # noqa: F821
        "TrivyDockerReport", back_populates="asset", cascade="all, delete-orphan"
    )
    tags: Mapped[list["AssetTag"]] = relationship(  # noqa: F821
        "AssetTag", back_populates="asset", cascade="all, delete-orphan"
    )
    ssl_scan_reports: Mapped[list["SslScanReport"]] = relationship(  # noqa: F821
        "SslScanReport", back_populates="asset", cascade="all, delete-orphan"
    )
    testssl_reports: Mapped[list["TestsslReport"]] = relationship(  # noqa: F821
        "TestsslReport", back_populates="asset", cascade="all, delete-orphan"
    )
    ssh_audit_reports: Mapped[list["SshAuditReport"]] = relationship(  # noqa: F821
        "SshAuditReport", back_populates="asset", cascade="all, delete-orphan"
    )
    default_creds_reports: Mapped[list["DefaultCredsReport"]] = relationship(  # noqa: F821
        "DefaultCredsReport", back_populates="asset", cascade="all, delete-orphan"
    )
    baselines: Mapped[list["AssetBaseline"]] = relationship(  # noqa: F821
        "AssetBaseline", back_populates="asset", cascade="all, delete-orphan"
    )
    full_audit_jobs: Mapped[list["FullAuditJob"]] = relationship(  # noqa: F821
        "FullAuditJob", back_populates="asset", cascade="all, delete-orphan"
    )
    hardening_reports: Mapped[list["HardeningReport"]] = relationship(  # noqa: F821
        "HardeningReport", back_populates="asset", cascade="all, delete-orphan"
    )
    headers_audit_reports: Mapped[list["HeadersAuditReport"]] = relationship(  # noqa: F821
        "HeadersAuditReport", back_populates="asset", cascade="all, delete-orphan"
    )
    msf_validation_reports: Mapped[list["MsfValidationReport"]] = relationship(  # noqa: F821
        "MsfValidationReport", back_populates="asset", cascade="all, delete-orphan"
    )
    privesc_reports: Mapped[list["PrivescReport"]] = relationship(  # noqa: F821
        "PrivescReport", back_populates="asset", cascade="all, delete-orphan",
        lazy="raise",
    )
    firewall_reports: Mapped[list["FirewallReport"]] = relationship(  # noqa: F821
        "FirewallReport", back_populates="asset", cascade="all, delete-orphan",
        lazy="raise",
    )
    rootkit_reports: Mapped[list["RootkitReport"]] = relationship(  # noqa: F821
        "RootkitReport", back_populates="asset", cascade="all, delete-orphan",
        lazy="raise",
    )
    docker_bench_reports: Mapped[list["DockerBenchReport"]] = relationship(  # noqa: F821
        "DockerBenchReport", back_populates="asset", cascade="all, delete-orphan",
        lazy="raise",
    )
    auth_log_reports: Mapped[list["AuthLogReport"]] = relationship(  # noqa: F821
        "AuthLogReport", back_populates="asset", cascade="all, delete-orphan",
        lazy="raise",
    )
    dns_email_reports: Mapped[list["DnsEmailReport"]] = relationship(  # noqa: F821
        "DnsEmailReport", back_populates="asset", cascade="all, delete-orphan",
        lazy="raise",
    )
    tech_fingerprint_reports: Mapped[list["TechFingerprintReport"]] = relationship(  # noqa: F821
        "TechFingerprintReport", back_populates="asset", cascade="all, delete-orphan",
        lazy="raise",
    )
    js_secrets_reports: Mapped[list["JsSecretsReport"]] = relationship(  # noqa: F821
        "JsSecretsReport", back_populates="asset", cascade="all, delete-orphan",
        lazy="raise",
    )
    dangling_cname_reports: Mapped[list["DanglingCnameReport"]] = relationship(  # noqa: F821
        "DanglingCnameReport", back_populates="asset", cascade="all, delete-orphan",
        lazy="raise",
    )

    @property
    def has_ssh_credentials(self) -> bool:
        """Return True if SSH credentials are available (direct or via profile).

        Checks instance dict for ssh_profile to avoid triggering a lazy load in
        async context — callers must have loaded the relationship via selectinload.
        """
        if self.ssh_password_enc or self.ssh_private_key_enc:
            return True
        profile = self.__dict__.get("ssh_profile")
        return bool(profile and (profile.ssh_password_enc or profile.ssh_private_key_enc))

    def __repr__(self) -> str:
        return f"<Asset ip={self.ip!r} mac={self.mac!r}>"
