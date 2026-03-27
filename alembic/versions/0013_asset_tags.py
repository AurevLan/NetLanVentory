"""Add asset_tags table.

Revision ID: 0013
Revises: 0012
Create Date: 2026-03-16 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "asset_tags",
        sa.Column("asset_id", sa.Uuid(as_uuid=True),
                  sa.ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("name", sa.String(64), primary_key=True),
    )


def downgrade() -> None:
    op.drop_table("asset_tags")
