"""Add SSH and Trivy auto-scan fields to assets.

ssh_auto_scan_enabled, ssh_scan_interval_minutes, ssh_last_auto_scan_at
trivy_auto_scan_enabled, trivy_scan_interval_minutes, trivy_last_auto_scan_at

Revision ID: 0015
Revises: 0014
Create Date: 2026-03-16 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: Union[str, None] = "0014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("ssh_auto_scan_enabled", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "assets",
        sa.Column("ssh_scan_interval_minutes", sa.Integer(), nullable=True),
    )
    op.add_column(
        "assets",
        sa.Column("ssh_last_auto_scan_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "assets",
        sa.Column("trivy_auto_scan_enabled", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "assets",
        sa.Column("trivy_scan_interval_minutes", sa.Integer(), nullable=True),
    )
    op.add_column(
        "assets",
        sa.Column("trivy_last_auto_scan_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("assets", "trivy_last_auto_scan_at")
    op.drop_column("assets", "trivy_scan_interval_minutes")
    op.drop_column("assets", "trivy_auto_scan_enabled")
    op.drop_column("assets", "ssh_last_auto_scan_at")
    op.drop_column("assets", "ssh_scan_interval_minutes")
    op.drop_column("assets", "ssh_auto_scan_enabled")
