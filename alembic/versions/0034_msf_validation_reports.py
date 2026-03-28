"""Add msf_validation_reports table for Metasploit exploit validation.

Revision ID: 0034
Revises: 0033
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "msf_validation_reports",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "asset_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("cves_tested", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cves_confirmed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cves_not_confirmed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cves_no_module", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("results", postgresql.JSONB(), nullable=True),
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
    op.create_index("ix_msf_validation_reports_asset_id", "msf_validation_reports", ["asset_id"])


def downgrade() -> None:
    op.drop_index("ix_msf_validation_reports_asset_id", table_name="msf_validation_reports")
    op.drop_table("msf_validation_reports")
