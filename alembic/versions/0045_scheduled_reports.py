"""Create scheduled_reports table.

Revision ID: 0045
Revises: 0044
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0045"
down_revision = "0044"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scheduled_reports",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("report_type", sa.String(30), nullable=False, server_default="executive"),
        sa.Column("schedule", sa.String(20), nullable=False, server_default="weekly"),
        sa.Column("recipients", JSONB, nullable=True, server_default="[]"),
        sa.Column("last_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_scheduled_reports_next_run", "scheduled_reports", ["next_run_at"])


def downgrade() -> None:
    op.drop_index("ix_scheduled_reports_next_run", table_name="scheduled_reports")
    op.drop_table("scheduled_reports")
