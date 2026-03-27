"""Add SLA deadline and breach fields to asset_cves table.

Revision ID: 0022
Revises: 0021
Create Date: 2026-03-18 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0022"
down_revision: Union[str, None] = "0021"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("asset_cves", sa.Column("sla_deadline", sa.Date(), nullable=True))
    op.add_column(
        "asset_cves",
        sa.Column("sla_breached", sa.Boolean(), nullable=False, server_default="false"),
    )


def downgrade() -> None:
    op.drop_column("asset_cves", "sla_breached")
    op.drop_column("asset_cves", "sla_deadline")
