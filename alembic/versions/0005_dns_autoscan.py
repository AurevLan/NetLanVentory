"""Add asset_dns, global_settings tables; add ZAP auto-scan and cve_count columns.

Revision ID: 0005
Revises: 0004
Create Date: 2026-02-28 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── New table: asset_dns ───────────────────────────────────────────────────
    op.create_table(
        "asset_dns",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "asset_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("fqdn", sa.String(255), nullable=False),
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

    # ── New table: global_settings ────────────────────────────────────────────
    op.create_table(
        "global_settings",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column(
            "zap_auto_scan_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "zap_scan_interval_minutes",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("60"),
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

    # ── Add ZAP auto-scan columns to assets ───────────────────────────────────
    op.add_column("assets", sa.Column("zap_auto_scan_enabled", sa.Boolean(), nullable=True))
    op.add_column("assets", sa.Column("zap_scan_interval_minutes", sa.Integer(), nullable=True))
    op.add_column(
        "assets",
        sa.Column("zap_last_auto_scan_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ── Add cve_count column to zap_reports ───────────────────────────────────
    op.add_column(
        "zap_reports",
        sa.Column(
            "cve_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )


def downgrade() -> None:
    op.drop_column("zap_reports", "cve_count")
    op.drop_column("assets", "zap_last_auto_scan_at")
    op.drop_column("assets", "zap_scan_interval_minutes")
    op.drop_column("assets", "zap_auto_scan_enabled")
    op.drop_table("global_settings")
    op.drop_table("asset_dns")
