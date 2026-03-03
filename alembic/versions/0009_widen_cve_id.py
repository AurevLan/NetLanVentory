"""Widen cves.cve_id from VARCHAR(20) to VARCHAR(50).

OSV.dev returns non-standard identifiers such as UBUNTU-CVE-2022-23491
(22 chars) which exceed the previous limit of 20.

Revision ID: 0009
Revises: 0008
Create Date: 2026-03-03 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "cves",
        "cve_id",
        type_=sa.String(50),
        existing_type=sa.String(20),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        "cves",
        "cve_id",
        type_=sa.String(20),
        existing_type=sa.String(50),
        existing_nullable=False,
    )
