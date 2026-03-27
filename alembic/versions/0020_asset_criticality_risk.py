"""Add criticality and risk_score to assets table.

Revision ID: 0020
Revises: 0019
Create Date: 2026-03-18 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0020"
down_revision: Union[str, None] = "0019"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("criticality", sa.String(20), nullable=False, server_default="medium"),
    )
    op.add_column(
        "assets",
        sa.Column("risk_score", sa.Float(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("assets", "risk_score")
    op.drop_column("assets", "criticality")
