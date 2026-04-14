"""Create triage_recommendations table — cached LLM triage suggestions per (cve, asset).

Revision ID: 0056
Revises: 0055
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ENUM, JSONB

revision = "0056"
down_revision = "0055"
branch_labels = None
depends_on = None

TRIAGE_URGENCY_VALUES = ("now", "24h", "7d", "30d", "none")


def upgrade() -> None:
    triage_urgency = ENUM(
        *TRIAGE_URGENCY_VALUES, name="triage_urgency", create_type=True
    )
    triage_urgency.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "triage_recommendations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("cve_id", sa.String(50), nullable=False),
        sa.Column(
            "asset_id",
            sa.Uuid(),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "urgency",
            sa.Enum(*TRIAGE_URGENCY_VALUES, name="triage_urgency", create_type=False),
            nullable=False,
        ),
        sa.Column("one_liner", sa.String(300), nullable=False),
        sa.Column("top_factors", JSONB, nullable=False, server_default="[]"),
        sa.Column("model_id", sa.String(100), nullable=False),
        sa.Column("prompt_version", sa.String(20), nullable=False),
        sa.Column("input_hash", sa.String(64), nullable=False),
        sa.Column("cached_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tokens_in", sa.Integer(), nullable=True),
        sa.Column("tokens_out", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "cve_id", "asset_id", "prompt_version",
            name="uq_triage_cve_asset_promptv",
        ),
    )
    op.create_index("ix_triage_recommendations_cve_id", "triage_recommendations", ["cve_id"])
    op.create_index(
        "ix_triage_recommendations_asset_id", "triage_recommendations", ["asset_id"]
    )
    op.create_index(
        "ix_triage_recommendations_input_hash", "triage_recommendations", ["input_hash"]
    )


def downgrade() -> None:
    op.drop_index("ix_triage_recommendations_input_hash", table_name="triage_recommendations")
    op.drop_index("ix_triage_recommendations_asset_id", table_name="triage_recommendations")
    op.drop_index("ix_triage_recommendations_cve_id", table_name="triage_recommendations")
    op.drop_table("triage_recommendations")
    ENUM(name="triage_urgency").drop(op.get_bind(), checkfirst=True)
