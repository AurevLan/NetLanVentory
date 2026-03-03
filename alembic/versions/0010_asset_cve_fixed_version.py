"""Add fixed_version column to asset_cves.

Stores the package version that fixes the vulnerability, as returned by OSV.dev
in affected[].ranges[].events[fixed].

Revision ID: 0010
Revises: 0009
Create Date: 2026-03-03 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "asset_cves",
        sa.Column("fixed_version", sa.String(100), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("asset_cves", "fixed_version")
