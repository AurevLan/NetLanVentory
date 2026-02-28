"""AssetDns model — DNS names associated with an asset."""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AssetDns(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "asset_dns"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    fqdn: Mapped[str] = mapped_column(String(255), nullable=False)

    # Relationships
    asset: Mapped["Asset"] = relationship("Asset", back_populates="dns_entries")  # noqa: F821

    def __repr__(self) -> str:
        return f"<AssetDns fqdn={self.fqdn!r} asset={self.asset_id}>"
