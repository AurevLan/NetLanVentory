"""Add recurring scan columns to scans table.

Revision ID: 0048
Revises: 0047
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0048"
down_revision = "0047"


def upgrade() -> None:
    op.add_column("scans", sa.Column("recurring", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("scans", sa.Column("recurring_interval_hours", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("recurring_last_triggered_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("recurring_run_count", sa.Integer(), nullable=False, server_default="0"))


def downgrade() -> None:
    op.drop_column("scans", "recurring_run_count")
    op.drop_column("scans", "recurring_last_triggered_at")
    op.drop_column("scans", "recurring_interval_hours")
    op.drop_column("scans", "recurring")
