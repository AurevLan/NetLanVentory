"""CVE model — a known vulnerability that can be linked to assets."""

from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Cve(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "cves"

    # Official CVE identifier (e.g. "CVE-2024-12345" or "UBUNTU-CVE-2022-23491")
    cve_id: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)

    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # LOW / MEDIUM / HIGH / CRITICAL
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # CVSS v3 base score (0.0 – 10.0)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Full CVSS base vector string (e.g. "CVSS:3.1/AV:N/AC:L/.../C:H/I:H/A:H").
    # Feeds the SSVC engine (Automatable / Technical Impact) far more faithfully
    # than the collapsed base score. See core/cvss_vector.py.
    cvss_vector: Mapped[str | None] = mapped_column(String(120), nullable=True)

    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Free-text remediation / action plan (admin-editable)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)

    # EPSS (Exploit Prediction Scoring System) — enriched via FIRST.org bulk CSV
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # CISA KEV (Known Exploited Vulnerabilities)
    kev_date_added: Mapped[date | None] = mapped_column(Date, nullable=True)
    kev_ransomware_use: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")

    # ExploitDB
    exploit_db_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # PoC on GitHub (nomi-sec/PoC-in-GitHub)
    poc_available: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    poc_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    # Composite maturity: none | poc | exploit | weaponized
    exploit_maturity: Mapped[str] = mapped_column(String(20), default="none", server_default="none")

    # Last threat-intel sync timestamp
    threat_intel_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # MITRE ATT&CK techniques associated with this CVE
    # [{technique_id, technique_name, tactics: [str]}]
    mitre_techniques: Mapped[list | None] = mapped_column(JSONB, nullable=True, server_default="[]")
    mitre_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    asset_cves: Mapped[list["AssetCve"]] = relationship(  # noqa: F821
        "AssetCve", back_populates="cve", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Cve {self.cve_id!r} severity={self.severity!r}>"
