"""Add EPSS score fields to cves table.

Revision ID: 0021
Revises: 0020
Create Date: 2026-03-18 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: Union[str, None] = "0020"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("cves", sa.Column("epss_score", sa.Float(), nullable=True))
    op.add_column("cves", sa.Column("epss_percentile", sa.Float(), nullable=True))
    op.add_column(
        "cves",
        sa.Column("epss_updated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("cves", "epss_updated_at")
    op.drop_column("cves", "epss_percentile")
    op.drop_column("cves", "epss_score")
