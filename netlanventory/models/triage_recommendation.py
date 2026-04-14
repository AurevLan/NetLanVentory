"""TriageRecommendation model — cached LLM triage suggestion per (cve, asset).

Cache key = sha256(prompt_version + cve_id + cve.last_modified + asset_id +
effective_severity + sorted(asset.tags)). Stored in `input_hash`. Bumping
`prompt_version` invalidates all entries automatically.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, Uuid, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ENUM as PgEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from netlanventory.models.base import Base


class TriageUrgency(str, enum.Enum):
    NOW = "now"
    H24 = "24h"
    D7 = "7d"
    D30 = "30d"
    NONE = "none"


class TriageRecommendation(Base):
    __tablename__ = "triage_recommendations"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False
    )
    cve_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    urgency: Mapped[TriageUrgency] = mapped_column(
        PgEnum(
            TriageUrgency,
            name="triage_urgency",
            create_type=False,
            values_callable=lambda enum_cls: [e.value for e in enum_cls],
        ),
        nullable=False,
    )
    one_liner: Mapped[str] = mapped_column(String(300), nullable=False)
    top_factors: Mapped[list] = mapped_column(JSONB, nullable=False, server_default="[]")

    model_id: Mapped[str] = mapped_column(String(100), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(20), nullable=False)
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    cached_until: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    tokens_in: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tokens_out: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            "cve_id", "asset_id", "prompt_version",
            name="uq_triage_cve_asset_promptv",
        ),
    )

    def __repr__(self) -> str:
        return f"<TriageRecommendation {self.cve_id} {self.asset_id} {self.urgency.value}>"
