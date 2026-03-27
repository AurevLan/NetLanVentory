"""Add cursor-pagination and ACK indexes.

Revision ID: 0036
Revises: 0035
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0036"
down_revision = "0035"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Composite index for cursor-based pagination on assets (sorted by created_at DESC)
    op.create_index(
        "ix_assets_active_created",
        "assets",
        ["is_active", "created_at"],
    )
    # Index for fast CVE ack-status filtering
    op.create_index(
        "ix_asset_cves_asset_ack",
        "asset_cves",
        ["asset_id", "ack_status"],
    )


def downgrade() -> None:
    op.drop_index("ix_asset_cves_asset_ack", table_name="asset_cves")
    op.drop_index("ix_assets_active_created", table_name="assets")
