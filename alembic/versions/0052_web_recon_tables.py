"""Create web recon tables: dns_email, tech_fingerprint, js_secrets, dangling_cname reports.

Revision ID: 0052
Revises: 0051
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0052"
down_revision = "0051"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── dns_email_reports ────────────────────────────────────────────────
    op.create_table(
        "dns_email_reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("domain", sa.String(255), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("score", sa.Integer(), nullable=True),
        sa.Column("findings", JSONB, nullable=True),
        sa.Column("error_msg", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_dns_email_reports_asset_id", "dns_email_reports", ["asset_id"])

    # ── tech_fingerprint_reports ─────────────────────────────────────────
    op.create_table(
        "tech_fingerprint_reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_url", sa.String(500), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("technologies_count", sa.Integer(), nullable=True),
        sa.Column("findings", JSONB, nullable=True),
        sa.Column("error_msg", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_tech_fingerprint_reports_asset_id", "tech_fingerprint_reports", ["asset_id"])

    # ── js_secrets_reports ───────────────────────────────────────────────
    op.create_table(
        "js_secrets_reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_url", sa.String(500), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("scripts_scanned", sa.Integer(), nullable=True),
        sa.Column("secrets_found", sa.Integer(), nullable=True),
        sa.Column("findings", JSONB, nullable=True),
        sa.Column("error_msg", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_js_secrets_reports_asset_id", "js_secrets_reports", ["asset_id"])

    # ── dangling_cname_reports ───────────────────────────────────────────
    op.create_table(
        "dangling_cname_reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("domain", sa.String(255), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("subdomains_checked", sa.Integer(), nullable=True),
        sa.Column("dangling_count", sa.Integer(), nullable=True),
        sa.Column("findings", JSONB, nullable=True),
        sa.Column("error_msg", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_dangling_cname_reports_asset_id", "dangling_cname_reports", ["asset_id"])


def downgrade() -> None:
    op.drop_index("ix_dangling_cname_reports_asset_id", table_name="dangling_cname_reports")
    op.drop_table("dangling_cname_reports")
    op.drop_index("ix_js_secrets_reports_asset_id", table_name="js_secrets_reports")
    op.drop_table("js_secrets_reports")
    op.drop_index("ix_tech_fingerprint_reports_asset_id", table_name="tech_fingerprint_reports")
    op.drop_table("tech_fingerprint_reports")
    op.drop_index("ix_dns_email_reports_asset_id", table_name="dns_email_reports")
    op.drop_table("dns_email_reports")
