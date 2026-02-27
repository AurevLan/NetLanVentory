"""Asset extensions: name/SSH fields + CVE and ZAP report tables.

Revision ID: 0002
Revises: 0001
Create Date: 2024-01-02 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── assets: add user-facing fields ──────────────────────────────────────
    op.add_column("assets", sa.Column("name", sa.String(255), nullable=True))
    op.add_column("assets", sa.Column("ssh_user", sa.String(100), nullable=True))
    op.add_column("assets", sa.Column("ssh_port", sa.Integer(), nullable=True))

    # ── cves ─────────────────────────────────────────────────────────────────
    op.create_table(
        "cves",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("cve_id", sa.String(20), unique=True, nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
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
    op.create_index("ix_cves_cve_id", "cves", ["cve_id"])

    # ── asset_cves (junction) ────────────────────────────────────────────────
    op.create_table(
        "asset_cves",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "asset_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "cve_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("cves.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source", sa.String(20), nullable=True),
        sa.Column("package_name", sa.String(255), nullable=True),
        sa.Column("package_version", sa.String(100), nullable=True),
        sa.Column(
            "discovered_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_asset_cves_asset_id", "asset_cves", ["asset_id"])
    op.create_index("ix_asset_cves_cve_id", "asset_cves", ["cve_id"])

    # ── zap_reports ──────────────────────────────────────────────────────────
    op.create_table(
        "zap_reports",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "asset_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("target_url", sa.String(500), nullable=True),
        sa.Column("report", sa.JSON(), nullable=True),
        sa.Column("risk_summary", sa.JSON(), nullable=True),
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
    op.create_index("ix_zap_reports_asset_id", "zap_reports", ["asset_id"])


def downgrade() -> None:
    op.drop_table("zap_reports")
    op.drop_table("asset_cves")
    op.drop_table("cves")
    op.drop_column("assets", "ssh_port")
    op.drop_column("assets", "ssh_user")
    op.drop_column("assets", "name")
