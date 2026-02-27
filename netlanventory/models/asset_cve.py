"""AssetCve junction — links a CVE to an asset with discovery context."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class AssetCve(Base):
    __tablename__ = "asset_cves"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cve_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cves.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # 'ssh' = found via package audit, 'zap' = found via OWASP ZAP
    source: Mapped[str | None] = mapped_column(String(20), nullable=True)

    # Package that carries the vulnerability (SSH source)
    package_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    package_version: Mapped[str | None] = mapped_column(String(100), nullable=True)

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    # Relationships
    asset: Mapped["Asset"] = relationship("Asset", back_populates="cves")  # noqa: F821
    cve: Mapped["Cve"] = relationship("Cve", back_populates="asset_cves")  # noqa: F821

    def __repr__(self) -> str:
        return f"<AssetCve asset={self.asset_id} cve={self.cve_id} source={self.source!r}>"
