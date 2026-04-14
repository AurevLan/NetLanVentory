"""Create remediation_jobs table for the patch workflow with dry-run, 4-eyes and rollback.

Revision ID: 0055
Revises: 0054
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ENUM, JSONB

revision = "0055"
down_revision = "0054"
branch_labels = None
depends_on = None

REMEDIATION_STATUS_VALUES = (
    "draft",
    "dry_run_pending",
    "dry_run_done",
    "awaiting_approval",
    "approved",
    "running",
    "succeeded",
    "healthcheck_failed",
    "rolled_back",
    "failed",
)


def upgrade() -> None:
    remediation_status = ENUM(
        *REMEDIATION_STATUS_VALUES,
        name="remediation_status",
        create_type=True,
    )
    remediation_status.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "remediation_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "asset_id",
            sa.Uuid(),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("cve_id", sa.String(50), nullable=True),
        sa.Column("playbook_yaml", sa.Text(), nullable=False),
        sa.Column("rollback_yaml", sa.Text(), nullable=True),
        sa.Column("healthcheck_cmd", sa.Text(), nullable=True),
        sa.Column("playbook_signature", sa.String(128), nullable=True),
        sa.Column(
            "status",
            sa.Enum(*REMEDIATION_STATUS_VALUES, name="remediation_status", create_type=False),
            nullable=False,
            server_default="draft",
        ),
        sa.Column("dry_run_diff", JSONB, nullable=True),
        sa.Column("execution_log", sa.Text(), nullable=True),
        sa.Column(
            "requires_four_eyes",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column(
            "created_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "approved_by",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rolled_back_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_remediation_jobs_asset_id", "remediation_jobs", ["asset_id"])
    op.create_index("ix_remediation_jobs_cve_id", "remediation_jobs", ["cve_id"])
    op.create_index("ix_remediation_jobs_status", "remediation_jobs", ["status"])


def downgrade() -> None:
    op.drop_index("ix_remediation_jobs_status", table_name="remediation_jobs")
    op.drop_index("ix_remediation_jobs_cve_id", table_name="remediation_jobs")
    op.drop_index("ix_remediation_jobs_asset_id", table_name="remediation_jobs")
    op.drop_table("remediation_jobs")
    ENUM(name="remediation_status").drop(op.get_bind(), checkfirst=True)
