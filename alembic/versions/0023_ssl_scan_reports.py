"""Create ssl_scan_reports table.

Revision ID: 0023
Revises: 0022
Create Date: 2026-03-18 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "0023"
down_revision: Union[str, None] = "0022"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ssl_scan_reports",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "asset_id",
            UUID(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("host", sa.String(255), nullable=True),
        sa.Column("port", sa.Integer(), nullable=False, server_default="443"),
        sa.Column("status", sa.String(20), nullable=True),
        sa.Column("subject", sa.String(500), nullable=True),
        sa.Column("issuer", sa.String(500), nullable=True),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("days_remaining", sa.Integer(), nullable=True),
        sa.Column("protocol_version", sa.String(20), nullable=True),
        sa.Column("cipher_suite", sa.String(255), nullable=True),
        sa.Column("issues", JSONB, nullable=True),
        sa.Column("raw_data", JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("ssl_scan_reports")
