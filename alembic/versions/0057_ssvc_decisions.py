"""Add SSVC decision columns to asset_cves (innovation #6).

Stores the per-(cve, asset) CISA SSVC Coordinator decision as the primary
patch-prioritisation signal, plus the full input provenance for audit.

Revision ID: 0057
Revises: 0056
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0057"
down_revision = "0056"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "asset_cves",
        sa.Column("ssvc_decision", sa.String(10), nullable=True),
    )
    op.add_column(
        "asset_cves",
        sa.Column("ssvc_inputs", JSONB, nullable=True),
    )
    op.add_column(
        "asset_cves",
        sa.Column("ssvc_evaluated_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Partial index: the smart scheduler & dashboards filter on actionable
    # decisions (attend / act), which are the minority of rows.
    op.create_index(
        "ix_asset_cves_ssvc_decision",
        "asset_cves",
        ["ssvc_decision"],
        postgresql_where=sa.text("ssvc_decision IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_asset_cves_ssvc_decision", table_name="asset_cves")
    op.drop_column("asset_cves", "ssvc_evaluated_at")
    op.drop_column("asset_cves", "ssvc_inputs")
    op.drop_column("asset_cves", "ssvc_decision")
