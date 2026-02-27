"""Create oidc_providers table.

Revision ID: 0004
Revises: 0003
Create Date: 2024-01-04 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "oidc_providers",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("name", sa.String(100), nullable=False, server_default="SSO"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("issuer_url", sa.String(500), nullable=True),
        sa.Column("client_id", sa.String(255), nullable=True),
        sa.Column("client_secret", sa.Text(), nullable=True),
        sa.Column(
            "scopes",
            sa.String(255),
            nullable=False,
            server_default="openid email profile",
        ),
        sa.Column(
            "auto_create_users",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "default_role",
            sa.String(20),
            nullable=False,
            server_default="user",
        ),
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


def downgrade() -> None:
    op.drop_table("oidc_providers")
