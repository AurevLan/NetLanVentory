"""Daily KPI snapshot for historical trend tracking."""

from datetime import date, datetime

from sqlalchemy import Date, DateTime, Float, Integer, func
from sqlalchemy.orm import Mapped, mapped_column

from netlanventory.models.base import Base


class KpiSnapshot(Base):
    __tablename__ = "kpi_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    date: Mapped[date] = mapped_column(Date, nullable=False, unique=True)

    # Asset metrics
    total_assets: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    active_assets: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    # CVE metrics
    total_cves: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    critical_cves: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    high_cves: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    open_cves: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    resolved_cves: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    # Performance metrics
    mttr_hours: Mapped[float | None] = mapped_column(Float, nullable=True)
    sla_breach_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    risk_score_avg: Mapped[float | None] = mapped_column(Float, nullable=True)
    scan_coverage_pct: Mapped[float | None] = mapped_column(Float, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
