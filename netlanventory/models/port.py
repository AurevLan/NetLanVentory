"""Port model — open/closed ports discovered on an asset."""

import uuid

from sqlalchemy import ForeignKey, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class Port(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "ports"
    __table_args__ = (
        UniqueConstraint("asset_id", "port_number", "protocol", name="uq_port_asset_proto"),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    port_number: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="tcp")

    # Port state: open | closed | filtered | open|filtered
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="open")

    service_name: Mapped[str | None] = mapped_column(String(100), nullable=True)
    version: Mapped[str | None] = mapped_column(String(255), nullable=True)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationship
    asset: Mapped["Asset"] = relationship("Asset", back_populates="ports")  # noqa: F821

    def __repr__(self) -> str:
        return f"<Port {self.protocol}/{self.port_number} state={self.state!r}>"
