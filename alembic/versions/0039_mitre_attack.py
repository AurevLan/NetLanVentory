"""Add MITRE ATT&CK columns to cves.

Revision ID: 0039
Revises: 0038
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0039"
down_revision = "0038"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "cves",
        sa.Column("mitre_techniques", JSONB, nullable=True, server_default="[]"),
    )
    op.add_column(
        "cves",
        sa.Column("mitre_updated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("cves", "mitre_updated_at")
    op.drop_column("cves", "mitre_techniques")
