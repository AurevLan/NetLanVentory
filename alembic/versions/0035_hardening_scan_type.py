"""Add scan_type column to hardening_reports.

Revision ID: 0035
Revises: 0034
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "hardening_reports",
        sa.Column(
            "scan_type",
            sa.String(20),
            nullable=False,
            server_default="full",
        ),
    )
    op.create_index(
        "ix_hardening_reports_scan_type",
        "hardening_reports",
        ["asset_id", "scan_type"],
    )


def downgrade() -> None:
    op.drop_index("ix_hardening_reports_scan_type", table_name="hardening_reports")
    op.drop_column("hardening_reports", "scan_type")
