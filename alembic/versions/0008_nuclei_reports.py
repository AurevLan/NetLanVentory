"""Create nuclei_reports table and widen asset_cves.source for multi-source tracking.

Revision ID: 0008
Revises: 0007
Create Date: 2026-03-02 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── nuclei_reports table ──────────────────────────────────────────────────
    op.create_table(
        "nuclei_reports",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "asset_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("targets", sa.JSON(), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=True),
        sa.Column("report", sa.JSON(), nullable=True),
        sa.Column("risk_summary", sa.JSON(), nullable=True),
        sa.Column(
            "cve_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "findings_count",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("error_msg", sa.Text(), nullable=True),
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

    # ── Widen asset_cves.source to support comma-separated multi-source values ─
    # e.g. "zap", "ssh", "nuclei", "zap,nuclei", "zap,nuclei,ssh"
    # Going from VARCHAR(20) to VARCHAR(50) is a metadata-only change in PostgreSQL
    # (no full table rewrite required), so this is safe on large tables.
    op.alter_column(
        "asset_cves",
        "source",
        type_=sa.String(50),
        existing_type=sa.String(20),
        existing_nullable=True,
    )


def downgrade() -> None:
    op.drop_table("nuclei_reports")
    op.alter_column(
        "asset_cves",
        "source",
        type_=sa.String(20),
        existing_type=sa.String(50),
        existing_nullable=True,
    )
