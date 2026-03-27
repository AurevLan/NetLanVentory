"""AssetTag — free-form labels attached to an asset for organisation."""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class AssetTag(Base):
    __tablename__ = "asset_tags"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        primary_key=True,
    )
    name: Mapped[str] = mapped_column(String(64), primary_key=True)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="tags")  # noqa: F821

    def __repr__(self) -> str:
        return f"<AssetTag asset={self.asset_id} name={self.name!r}>"
