"""ThreatIoc model — indicator of compromise from threat intel feeds."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, Text, Uuid, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from netlanventory.models.base import Base


class ThreatIoc(Base):
    __tablename__ = "threat_iocs"
    __table_args__ = (
        UniqueConstraint("indicator", "ioc_type", name="uq_threat_ioc_indicator_type"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # The indicator value (IP, domain, URL, hash)
    indicator: Mapped[str] = mapped_column(String(500), nullable=False, index=True)

    # ip | domain | url | hash_md5 | hash_sha1 | hash_sha256
    ioc_type: Mapped[str] = mapped_column(String(20), nullable=False, index=True)

    # Source feed: otx | abusech_urlhaus | manual
    source: Mapped[str] = mapped_column(String(50), nullable=False)

    # critical | high | medium | low
    severity: Mapped[str] = mapped_column(String(20), nullable=False, server_default="medium")

    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    first_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    def __repr__(self) -> str:
        return f"<ThreatIoc {self.ioc_type}:{self.indicator!r} source={self.source!r}>"
