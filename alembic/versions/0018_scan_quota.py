"""Add scan_quota_per_day to users; create scan_quota_logs table.

Revision ID: 0018
Revises: 0017
Create Date: 2026-03-16 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: Union[str, None] = "0017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add quota field to users
    op.add_column(
        "users",
        sa.Column(
            "scan_quota_per_day",
            sa.Integer(),
            nullable=True,
            server_default="50",
        ),
    )

    # Create scan_quota_logs table
    op.create_table(
        "scan_quota_logs",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("scan_date", sa.Date(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="1"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("user_id", "scan_date", name="uq_scan_quota_user_date"),
    )
    op.create_index("ix_scan_quota_logs_user_id", "scan_quota_logs", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_scan_quota_logs_user_id", "scan_quota_logs")
    op.drop_table("scan_quota_logs")
    op.drop_column("users", "scan_quota_per_day")
