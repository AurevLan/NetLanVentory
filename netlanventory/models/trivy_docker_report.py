"""TrivyDockerReport — stores Trivy container scan results linked to an asset."""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class TrivyDockerReport(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "trivy_docker_reports"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # pending / running / completed / failed
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="pending"
    )

    # Number of running containers found on the remote host
    containers_found: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False, server_default="0"
    )

    # Number of unique images actually scanned by Trivy
    images_scanned: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False, server_default="0"
    )

    # Total unique CVEs persisted from this scan
    cves_found: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False, server_default="0"
    )

    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    asset: Mapped[Asset] = relationship(  # noqa: F821
        "Asset", back_populates="trivy_docker_reports"
    )

    def __repr__(self) -> str:
        return f"<TrivyDockerReport asset={self.asset_id} status={self.status!r}>"
