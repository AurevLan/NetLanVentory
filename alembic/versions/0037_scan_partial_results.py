"""Add partial_results column to scans.

Revision ID: 0037
Revises: 0036
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column(
            "partial_results",
            JSONB,
            nullable=True,
            server_default="{}",
        ),
    )


def downgrade() -> None:
    op.drop_column("scans", "partial_results")
