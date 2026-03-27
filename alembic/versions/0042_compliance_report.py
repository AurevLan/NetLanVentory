"""Create compliance_reports table.

Revision ID: 0042
Revises: 0041
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0042"
down_revision = "0041"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "compliance_reports",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("framework", sa.String(30), nullable=False),
        sa.Column("scope", sa.String(100), nullable=False, server_default="global"),
        sa.Column("score", sa.Integer, nullable=False, server_default="0"),
        sa.Column("status", sa.String(30), nullable=False, server_default="partial"),
        sa.Column("findings", JSONB, nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_compliance_reports_framework", "compliance_reports", ["framework"])
    op.create_index("ix_compliance_reports_generated_at", "compliance_reports", ["generated_at"])


def downgrade() -> None:
    op.drop_index("ix_compliance_reports_generated_at", table_name="compliance_reports")
    op.drop_index("ix_compliance_reports_framework", table_name="compliance_reports")
    op.drop_table("compliance_reports")
