"""CVE model — a known vulnerability that can be linked to assets."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Cve(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "cves"

    # Official CVE identifier (e.g. "CVE-2024-12345")
    cve_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False, index=True)

    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # LOW / MEDIUM / HIGH / CRITICAL
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # CVSS v3 base score (0.0 – 10.0)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    asset_cves: Mapped[list["AssetCve"]] = relationship(  # noqa: F821
        "AssetCve", back_populates="cve", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Cve {self.cve_id!r} severity={self.severity!r}>"
