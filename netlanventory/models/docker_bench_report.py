"""DockerBenchReport model — Docker daemon security audit results (docker-bench-security)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netlanventory.models.base import Base


class DockerBenchReport(Base):
    __tablename__ = "docker_bench_reports"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # pending / running / completed / failed
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="pending")

    # Docker version detected
    docker_version: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # Score (percentage of passing checks)
    score: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Counters
    pass_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    warn_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    info_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    note_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    # Detailed findings as JSONB
    # {
    #   "docker_available": true,
    #   "docker_version": "24.0.7",
    #   "sections": {
    #     "host_configuration": {
    #       "pass": ["1.1.1 - Ensure a separate partition for containers has been created"],
    #       "warn": ["1.1.2 - Ensure only trusted users are allowed to control Docker daemon"],
    #     },
    #     "docker_daemon_configuration": {
    #       "warn": ["2.1 - Run the Docker daemon as a non-root user"],
    #       "pass": [],
    #     },
    #     "container_images": {...},
    #     "container_runtime": {...},
    #     "docker_security_operations": {...},
    #   },
    #   "risk_findings": [
    #     {"severity": "critical", "finding": "Docker socket exposed to network", "cis": "2.15"},
    #     {"severity": "high", "finding": "User namespace not enabled", "cis": "2.8"},
    #   ],
    #   "containers_running": 5,
    #   "images_count": 12,
    # }
    findings: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    asset: Mapped["Asset"] = relationship("Asset", back_populates="docker_bench_reports")  # noqa: F821

    def __repr__(self) -> str:
        return f"<DockerBenchReport asset={self.asset_id} score={self.score} warns={self.warn_count}>"
