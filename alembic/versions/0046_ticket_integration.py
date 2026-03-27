"""Add ticket integration — asset_cve columns + ticket_configs table.

Revision ID: 0046
Revises: 0045
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0046"
down_revision = "0045"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add ticket tracking to asset_cves
    op.add_column(
        "asset_cves",
        sa.Column("ticket_id", sa.String(100), nullable=True),
    )
    op.add_column(
        "asset_cves",
        sa.Column("ticket_url", sa.Text, nullable=True),
    )

    # Ticket integration configurations
    op.create_table(
        "ticket_configs",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("type", sa.String(20), nullable=False),
        sa.Column("base_url", sa.Text, nullable=False),
        sa.Column("api_token_enc", sa.Text, nullable=True),
        sa.Column("project_key", sa.String(50), nullable=True),
        sa.Column("username", sa.String(255), nullable=True),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("ticket_configs")
    op.drop_column("asset_cves", "ticket_url")
    op.drop_column("asset_cves", "ticket_id")
