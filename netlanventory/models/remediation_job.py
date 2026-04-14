"""RemediationJob model — Ansible playbook execution with dry-run, 4-eyes and rollback.

Machine d'état :
DRAFT → DRY_RUN_PENDING → DRY_RUN_DONE → AWAITING_APPROVAL → APPROVED → RUNNING
                                                                          ↓
                              ROLLED_BACK ← HEALTHCHECK_FAILED ← SUCCEEDED|FAILED
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import ENUM as PgEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from netlanventory.models.base import Base


class RemediationStatus(str, enum.Enum):
    DRAFT = "draft"
    DRY_RUN_PENDING = "dry_run_pending"
    DRY_RUN_DONE = "dry_run_done"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    HEALTHCHECK_FAILED = "healthcheck_failed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class RemediationJob(Base):
    __tablename__ = "remediation_jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    cve_id: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)

    playbook_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    rollback_yaml: Mapped[str | None] = mapped_column(Text, nullable=True)
    healthcheck_cmd: Mapped[str | None] = mapped_column(Text, nullable=True)
    playbook_signature: Mapped[str | None] = mapped_column(String(128), nullable=True)

    status: Mapped[RemediationStatus] = mapped_column(
        PgEnum(RemediationStatus, name="remediation_status", create_type=True),
        nullable=False,
        server_default=RemediationStatus.DRAFT.value,
        index=True,
    )
    dry_run_diff: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    execution_log: Mapped[str | None] = mapped_column(Text, nullable=True)
    requires_four_eyes: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )

    created_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    executed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    rolled_back_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<RemediationJob {self.id} asset={self.asset_id} status={self.status.value}>"
