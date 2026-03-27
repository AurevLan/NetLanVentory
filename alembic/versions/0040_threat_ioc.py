"""Create threat_iocs table.

Revision ID: 0040
Revises: 0039
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0040"
down_revision = "0039"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "threat_iocs",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("indicator", sa.String(500), nullable=False),
        sa.Column("ioc_type", sa.String(20), nullable=False),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_threat_iocs_indicator", "threat_iocs", ["indicator"])
    op.create_index("ix_threat_iocs_ioc_type", "threat_iocs", ["ioc_type"])
    op.create_unique_constraint(
        "uq_threat_ioc_indicator_type",
        "threat_iocs",
        ["indicator", "ioc_type"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_threat_ioc_indicator_type", "threat_iocs", type_="unique")
    op.drop_index("ix_threat_iocs_ioc_type", table_name="threat_iocs")
    op.drop_index("ix_threat_iocs_indicator", table_name="threat_iocs")
    op.drop_table("threat_iocs")
