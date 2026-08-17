"""Add cvss_vector to cves (innovation #6, V2).

Stores the full CVSS base vector string so the SSVC engine can derive
Automatable (AV/AC/PR/UI/AT) and Technical Impact (C/I/A) from the real
sub-metrics instead of the EPSS / base-score proxies.

Revision ID: 0058
Revises: 0057
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0058"
down_revision = "0057"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "cves",
        sa.Column("cvss_vector", sa.String(120), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("cves", "cvss_vector")
