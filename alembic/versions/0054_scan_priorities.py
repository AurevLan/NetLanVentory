"""Create scan_priorities table for the smart re-scan scheduler.

Revision ID: 0054
Revises: 0053
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0054"
down_revision = "0053"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_priorities",
        sa.Column(
            "asset_id",
            sa.Uuid(),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("module", sa.String(50), nullable=False),
        sa.Column("score", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column(
            "last_score_update",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "next_eligible_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("max_age_hours", sa.Integer(), nullable=False, server_default="72"),
        sa.PrimaryKeyConstraint("asset_id", "module"),
    )
    op.create_index(
        "ix_scan_priorities_eligible_score",
        "scan_priorities",
        ["next_eligible_at", "score"],
    )


def downgrade() -> None:
    op.drop_index("ix_scan_priorities_eligible_score", table_name="scan_priorities")
    op.drop_table("scan_priorities")
