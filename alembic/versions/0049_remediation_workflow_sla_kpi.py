"""Add remediation workflow, persistent SLA config, and KPI snapshots.

Revision ID: 0049
Revises: 0048
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0049"
down_revision = "0048"


def upgrade() -> None:
    # ── Remediation workflow on asset_cves ────────────────────────────────
    op.add_column("asset_cves", sa.Column(
        "remediation_status", sa.String(20), nullable=False, server_default="open"))
    op.add_column("asset_cves", sa.Column(
        "assigned_to", sa.String(255), nullable=True))
    op.add_column("asset_cves", sa.Column(
        "remediation_due_date", sa.Date(), nullable=True))
    op.add_column("asset_cves", sa.Column(
        "remediation_started_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("asset_cves", sa.Column(
        "remediation_resolved_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("asset_cves", sa.Column(
        "remediation_note", sa.Text(), nullable=True))

    # ── Persistent SLA configuration ─────────────────────────────────────
    op.create_table(
        "sla_configs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("severity", sa.String(20), nullable=False, unique=True),
        sa.Column("days", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    # Seed defaults
    op.execute("""
        INSERT INTO sla_configs (severity, days) VALUES
        ('critical', 3), ('high', 7), ('medium', 30), ('low', 90)
    """)

    # ── KPI daily snapshots ──────────────────────────────────────────────
    op.create_table(
        "kpi_snapshots",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("date", sa.Date(), nullable=False, unique=True),
        sa.Column("total_assets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("active_assets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_cves", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical_cves", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("high_cves", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_cves", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("resolved_cves", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("mttr_hours", sa.Float(), nullable=True),
        sa.Column("sla_breach_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("risk_score_avg", sa.Float(), nullable=True),
        sa.Column("scan_coverage_pct", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("kpi_snapshots")
    op.drop_table("sla_configs")
    op.drop_column("asset_cves", "remediation_note")
    op.drop_column("asset_cves", "remediation_resolved_at")
    op.drop_column("asset_cves", "remediation_started_at")
    op.drop_column("asset_cves", "remediation_due_date")
    op.drop_column("asset_cves", "assigned_to")
    op.drop_column("asset_cves", "remediation_status")
