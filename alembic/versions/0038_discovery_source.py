"""Add discovery_source column to assets.

Revision ID: 0038
Revises: 0037
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column(
            "discovery_source",
            sa.String(30),
            nullable=True,
            server_default="manual",
        ),
    )
    op.create_index(
        "ix_assets_discovery_source",
        "assets",
        ["discovery_source"],
    )

    # Also add passive_discovery fields to global_settings
    op.add_column(
        "global_settings",
        sa.Column("passive_discovery_enabled", sa.Boolean, nullable=False, server_default="false"),
    )
    op.add_column(
        "global_settings",
        sa.Column("passive_interface", sa.String(50), nullable=True, server_default="eth0"),
    )


def downgrade() -> None:
    op.drop_column("global_settings", "passive_interface")
    op.drop_column("global_settings", "passive_discovery_enabled")
    op.drop_index("ix_assets_discovery_source", table_name="assets")
    op.drop_column("assets", "discovery_source")
