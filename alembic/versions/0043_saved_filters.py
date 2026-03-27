"""Create saved_filters table.

Revision ID: 0043
Revises: 0042
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0043"
down_revision = "0042"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "saved_filters",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("view", sa.String(30), nullable=False),
        sa.Column("filters", JSONB, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_saved_filters_user_id", "saved_filters", ["user_id"])
    op.create_index("ix_saved_filters_view", "saved_filters", ["view"])


def downgrade() -> None:
    op.drop_index("ix_saved_filters_view", table_name="saved_filters")
    op.drop_index("ix_saved_filters_user_id", table_name="saved_filters")
    op.drop_table("saved_filters")
