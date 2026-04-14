"""Create internal audit tables: privesc, firewall, rootkit, docker_bench, auth_log reports.

Also adds new sub-report ID columns to full_audit_jobs for orchestration.

Revision ID: 0051
Revises: 0050
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0051"
down_revision = "0050"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── privesc_reports ───────────────────────────────────────────────────
    op.create_table(
        "privesc_reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("users_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sudoers_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("suid_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sgid_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("capabilities_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("authorized_keys_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("writable_paths_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risk_findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings", JSONB, nullable=True),
        sa.Column("error_msg", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── firewall_reports ──────────────────────────────────────────────────
    op.create_table(
        "firewall_reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("backend", sa.String(30), nullable=True),
        sa.Column("firewall_active", sa.Boolean(), nullable=True),
        sa.Column("rules_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_input_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risk_findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings", JSONB, nullable=True),
        sa.Column("error_msg", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── rootkit_reports ───────────────────────────────────────────────────
    op.create_table(
        "rootkit_reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("tool_used", sa.String(30), nullable=True),
        sa.Column("suspects_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("warnings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("infected_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings", JSONB, nullable=True),
        sa.Column("error_msg", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── docker_bench_reports ──────────────────────────────────────────────
    op.create_table(
        "docker_bench_reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("docker_version", sa.String(50), nullable=True),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("pass_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("warn_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("info_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("note_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings", JSONB, nullable=True),
        sa.Column("error_msg", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── auth_log_reports ──────────────────────────────────────────────────
    op.create_table(
        "auth_log_reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("failed_logins_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("successful_logins_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unique_source_ips", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("brute_force_sources", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risk_findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings", JSONB, nullable=True),
        sa.Column("error_msg", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── Add sub-report IDs to full_audit_jobs ─────────────────────────────
    op.add_column(
        "full_audit_jobs",
        sa.Column("privesc_report_id", sa.Uuid(), sa.ForeignKey("privesc_reports.id", ondelete="SET NULL"), nullable=True),
    )
    op.add_column(
        "full_audit_jobs",
        sa.Column("firewall_report_id", sa.Uuid(), sa.ForeignKey("firewall_reports.id", ondelete="SET NULL"), nullable=True),
    )
    op.add_column(
        "full_audit_jobs",
        sa.Column("rootkit_report_id", sa.Uuid(), sa.ForeignKey("rootkit_reports.id", ondelete="SET NULL"), nullable=True),
    )
    op.add_column(
        "full_audit_jobs",
        sa.Column("docker_bench_report_id", sa.Uuid(), sa.ForeignKey("docker_bench_reports.id", ondelete="SET NULL"), nullable=True),
    )
    op.add_column(
        "full_audit_jobs",
        sa.Column("auth_log_report_id", sa.Uuid(), sa.ForeignKey("auth_log_reports.id", ondelete="SET NULL"), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("full_audit_jobs", "auth_log_report_id")
    op.drop_column("full_audit_jobs", "docker_bench_report_id")
    op.drop_column("full_audit_jobs", "rootkit_report_id")
    op.drop_column("full_audit_jobs", "firewall_report_id")
    op.drop_column("full_audit_jobs", "privesc_report_id")
    op.drop_table("auth_log_reports")
    op.drop_table("docker_bench_reports")
    op.drop_table("rootkit_reports")
    op.drop_table("firewall_reports")
    op.drop_table("privesc_reports")
