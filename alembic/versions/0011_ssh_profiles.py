"""Add ssh_profiles table and ssh_profile_id FK on assets.

Revision ID: 0011
Revises: 0010
Create Date: 2026-03-16 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ssh_profiles",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("ssh_user", sa.String(100), nullable=False),
        sa.Column("ssh_port", sa.Integer(), nullable=True),
        sa.Column("ssh_password_enc", sa.Text(), nullable=True),
        sa.Column("ssh_private_key_enc", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.add_column(
        "assets",
        sa.Column(
            "ssh_profile_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("ssh_profiles.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_assets_ssh_profile_id", "assets", ["ssh_profile_id"])


def downgrade() -> None:
    op.drop_index("ix_assets_ssh_profile_id", table_name="assets")
    op.drop_column("assets", "ssh_profile_id")
    op.drop_table("ssh_profiles")
