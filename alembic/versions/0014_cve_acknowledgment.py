"""Add acknowledgment fields to asset_cves.

ack_status: none | accepted | false_positive | in_progress
ack_note:   free-text note from the acknowledging user
ack_by:     username of the acknowledger
ack_at:     timestamp of acknowledgment

Revision ID: 0014
Revises: 0013
Create Date: 2026-03-16 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("asset_cves", sa.Column("ack_status", sa.String(20),
                                          nullable=False, server_default="none"))
    op.add_column("asset_cves", sa.Column("ack_note", sa.Text(), nullable=True))
    op.add_column("asset_cves", sa.Column("ack_by", sa.String(255), nullable=True))
    op.add_column("asset_cves", sa.Column("ack_at",
                                          sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("asset_cves", "ack_at")
    op.drop_column("asset_cves", "ack_by")
    op.drop_column("asset_cves", "ack_note")
    op.drop_column("asset_cves", "ack_status")
