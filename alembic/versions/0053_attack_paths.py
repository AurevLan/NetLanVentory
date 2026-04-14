"""Create attack_paths table for the Attack Path Graph engine.

Revision ID: 0053
Revises: 0052
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0053"
down_revision = "0052"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "attack_paths",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column(
            "source_asset_id",
            sa.Uuid(),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "target_asset_id",
            sa.Uuid(),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("hops", JSONB, nullable=False),
        sa.Column("total_weight", sa.Float(), nullable=False),
        sa.Column("hop_count", sa.Integer(), nullable=False),
        sa.Column(
            "computed_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_attack_paths_source_asset_id", "attack_paths", ["source_asset_id"])
    op.create_index("ix_attack_paths_target_asset_id", "attack_paths", ["target_asset_id"])
    op.create_index(
        "ix_attack_paths_target_weight",
        "attack_paths",
        ["target_asset_id", "total_weight"],
    )


def downgrade() -> None:
    op.drop_index("ix_attack_paths_target_weight", table_name="attack_paths")
    op.drop_index("ix_attack_paths_target_asset_id", table_name="attack_paths")
    op.drop_index("ix_attack_paths_source_asset_id", table_name="attack_paths")
    op.drop_table("attack_paths")
