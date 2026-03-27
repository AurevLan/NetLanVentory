"""Apply migration 0049: remediation workflow + SLA + KPI snapshots."""
import os
import sqlalchemy as sa

url = os.environ.get("DATABASE_URL", "postgresql://netlv:pass@db:5432/netlanventory")
# Strip async driver if present
url = url.replace("+asyncpg", "")
engine = sa.create_engine(url)

with engine.begin() as conn:
    # Remediation workflow on asset_cves
    for col, typ in [
        ("remediation_status", "VARCHAR(20) NOT NULL DEFAULT 'open'"),
        ("assigned_to", "VARCHAR(255)"),
        ("remediation_due_date", "DATE"),
        ("remediation_started_at", "TIMESTAMPTZ"),
        ("remediation_resolved_at", "TIMESTAMPTZ"),
        ("remediation_note", "TEXT"),
    ]:
        try:
            conn.execute(sa.text(f"ALTER TABLE asset_cves ADD COLUMN IF NOT EXISTS {col} {typ}"))
        except Exception as e:
            print(f"  skip {col}: {e}")

    # SLA config table
    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS sla_configs (
            id SERIAL PRIMARY KEY,
            severity VARCHAR(20) NOT NULL UNIQUE,
            days INTEGER NOT NULL,
            updated_at TIMESTAMPTZ DEFAULT now()
        )
    """))
    conn.execute(sa.text("""
        INSERT INTO sla_configs (severity, days) VALUES
        ('critical', 3), ('high', 7), ('medium', 30), ('low', 90)
        ON CONFLICT (severity) DO NOTHING
    """))

    # KPI snapshots table
    conn.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS kpi_snapshots (
            id SERIAL PRIMARY KEY,
            date DATE NOT NULL UNIQUE,
            total_assets INTEGER DEFAULT 0,
            active_assets INTEGER DEFAULT 0,
            total_cves INTEGER DEFAULT 0,
            critical_cves INTEGER DEFAULT 0,
            high_cves INTEGER DEFAULT 0,
            open_cves INTEGER DEFAULT 0,
            resolved_cves INTEGER DEFAULT 0,
            mttr_hours FLOAT,
            sla_breach_count INTEGER DEFAULT 0,
            risk_score_avg FLOAT,
            scan_coverage_pct FLOAT,
            created_at TIMESTAMPTZ DEFAULT now()
        )
    """))

print("Migration 0049 applied successfully")
