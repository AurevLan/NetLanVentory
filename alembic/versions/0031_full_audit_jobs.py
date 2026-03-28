"""Add full_audit_jobs table for full audit orchestration.

Revision ID: 0031
Revises: 0030
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0031"
down_revision = "0030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "full_audit_jobs",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column(
            "asset_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("assets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(30), nullable=False, server_default="pending"),
        sa.Column("steps", postgresql.JSONB(), nullable=True),
        sa.Column(
            "testssl_report_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("testssl_reports.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "ssh_audit_report_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("ssh_audit_reports.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "default_creds_report_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("default_creds_reports.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "ssh_scan_report_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("ssh_scan_reports.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "nuclei_report_id",
            sa.Uuid(as_uuid=True),
            sa.ForeignKey("nuclei_reports.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("error_msg", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_full_audit_jobs_asset_id", "full_audit_jobs", ["asset_id"])


def downgrade() -> None:
    op.drop_index("ix_full_audit_jobs_asset_id", table_name="full_audit_jobs")
    op.drop_table("full_audit_jobs")
