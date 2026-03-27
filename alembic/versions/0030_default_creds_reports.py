"""Add default_creds_reports table for default credentials scan.

Revision ID: 0030
Revises: 0029
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "default_creds_reports",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "asset_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(20), nullable=True),
        sa.Column("vulnerable_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tested_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings", postgresql.JSONB(), nullable=True),
        sa.Column("error_msg", sa.Text(), nullable=True),
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
    )
    op.create_index(
        "ix_default_creds_reports_asset_id", "default_creds_reports", ["asset_id"]
    )


def downgrade() -> None:
    op.drop_index(
        "ix_default_creds_reports_asset_id", table_name="default_creds_reports"
    )
    op.drop_table("default_creds_reports")
