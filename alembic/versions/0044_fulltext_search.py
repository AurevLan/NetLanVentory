"""Add full-text search vectors to assets and cves.

Revision ID: 0044
Revises: 0043
"""

from __future__ import annotations

from alembic import op

revision = "0044"
down_revision = "0043"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Generated tsvector columns using STORED (computed automatically by PostgreSQL)
    op.execute("""
        ALTER TABLE assets
        ADD COLUMN IF NOT EXISTS search_vector tsvector
        GENERATED ALWAYS AS (
            to_tsvector('simple',
                coalesce(name, '') || ' ' ||
                coalesce(hostname, '') || ' ' ||
                coalesce(ip, '') || ' ' ||
                coalesce(os_family, '') || ' ' ||
                coalesce(device_type, '')
            )
        ) STORED
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_assets_fts
        ON assets USING GIN(search_vector)
    """)

    op.execute("""
        ALTER TABLE cves
        ADD COLUMN IF NOT EXISTS search_vector tsvector
        GENERATED ALWAYS AS (
            to_tsvector('english',
                coalesce(cve_id, '') || ' ' ||
                coalesce(description, '')
            )
        ) STORED
    """)
    op.execute("""
        CREATE INDEX IF NOT EXISTS ix_cves_fts
        ON cves USING GIN(search_vector)
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_cves_fts")
    op.execute("ALTER TABLE cves DROP COLUMN IF EXISTS search_vector")
    op.execute("DROP INDEX IF EXISTS ix_assets_fts")
    op.execute("ALTER TABLE assets DROP COLUMN IF EXISTS search_vector")
