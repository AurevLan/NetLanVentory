"""AttackPath model — directed graph of multi-hop attack paths between assets.

Each row represents one computed path: a starting asset, a target ("crown jewel"),
and the chain of hops with edge types (cve_exploit, ssh_pivot, network_reachable,
credential_leak, ioc_pivot, firewall_gap) and per-hop weights.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from netlanventory.models.base import Base


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False
    )
    source_asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # [{"asset_id": "...", "edge_type": "cve_exploit", "cve_id": "CVE-...", "weight": 7.5}]
    hops: Mapped[list[dict]] = mapped_column(JSONB, nullable=False)
    total_weight: Mapped[float] = mapped_column(Float, nullable=False)
    hop_count: Mapped[int] = mapped_column(Integer, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("ix_attack_paths_target_weight", "target_asset_id", "total_weight"),
    )

    def __repr__(self) -> str:
        return (
            f"<AttackPath {self.source_asset_id}→{self.target_asset_id} "
            f"hops={self.hop_count} weight={self.total_weight:.1f}>"
        )
