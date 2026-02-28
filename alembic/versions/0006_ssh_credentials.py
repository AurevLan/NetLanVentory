"""Add encrypted SSH credential columns to assets.

Revision ID: 0006
Revises: 0005
Create Date: 2026-02-28 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("ssh_password_enc", sa.Text(), nullable=True))
    op.add_column("assets", sa.Column("ssh_private_key_enc", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("assets", "ssh_private_key_enc")
    op.drop_column("assets", "ssh_password_enc")
