"""Add CIS benchmark columns to hardening_reports.

Revision ID: 0041
Revises: 0040
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0041"
down_revision = "0040"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "hardening_reports",
        sa.Column("cis_score", sa.Integer, nullable=True),
    )
    op.add_column(
        "hardening_reports",
        sa.Column("cis_level", sa.String(5), nullable=True),
    )
    op.add_column(
        "hardening_reports",
        sa.Column("cis_findings", JSONB, nullable=True, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("hardening_reports", "cis_findings")
    op.drop_column("hardening_reports", "cis_level")
    op.drop_column("hardening_reports", "cis_score")
