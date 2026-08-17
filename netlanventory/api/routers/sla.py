"""SLA remediation router — manage SLA deadlines and breach detection."""

from __future__ import annotations

import uuid
from datetime import date, datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import get_current_active_user, get_db, require_admin
from netlanventory.core.logging import get_logger
from netlanventory.core.sla_policy import effective_sla_deadline
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.sla_config import SlaConfig

logger = get_logger(__name__)

router = APIRouter(tags=["sla"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
AuthDep = Annotated[object, Depends(get_current_active_user)]
AdminDep = Annotated[object, Depends(require_admin)]

# Default SLA configuration (days from discovery to remediation deadline)
_DEFAULT_SLA_DAYS: dict[str, int] = {
    "Critical": 3,
    "High": 7,
    "Medium": 30,
    "Low": 90,
}


class SlaConfigOut(BaseModel):
    critical_days: int
    high_days: int
    medium_days: int
    low_days: int


class SlaConfigIn(BaseModel):
    critical_days: int = 3
    high_days: int = 7
    medium_days: int = 30
    low_days: int = 90


class SlaBreachItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    asset_cve_id: uuid.UUID
    asset_id: uuid.UUID
    cve_id: str
    severity: str | None
    sla_deadline: date | None
    discovered_at: datetime
    ack_status: str


class SlaComputeResult(BaseModel):
    updated: int


async def _load_sla_config(db: AsyncSession) -> dict[str, int]:
    """Load SLA configuration from the database, falling back to defaults."""
    result = await db.execute(select(SlaConfig))
    rows = result.scalars().all()
    config = dict(_DEFAULT_SLA_DAYS)
    for row in rows:
        config[row.severity] = row.days
    return config


@router.get("/sla/config", response_model=SlaConfigOut)
async def get_sla_config(db: DbDep, _auth: AuthDep) -> SlaConfigOut:
    """Return the current SLA configuration (days per severity)."""
    config = await _load_sla_config(db)
    return SlaConfigOut(
        critical_days=config.get("Critical", 3),
        high_days=config.get("High", 7),
        medium_days=config.get("Medium", 30),
        low_days=config.get("Low", 90),
    )


@router.put("/sla/config", response_model=SlaConfigOut)
async def update_sla_config(body: SlaConfigIn, db: DbDep, _admin: AdminDep) -> SlaConfigOut:
    """Update the SLA configuration (admin only). Upserts rows in sla_configs."""
    updates = {
        "Critical": body.critical_days,
        "High": body.high_days,
        "Medium": body.medium_days,
        "Low": body.low_days,
    }
    for severity, days in updates.items():
        result = await db.execute(
            select(SlaConfig).where(SlaConfig.severity == severity)
        )
        existing = result.scalar_one_or_none()
        if existing:
            existing.days = days
            existing.updated_at = datetime.now(timezone.utc)
        else:
            db.add(SlaConfig(severity=severity, days=days))
    await db.commit()
    return SlaConfigOut(
        critical_days=body.critical_days,
        high_days=body.high_days,
        medium_days=body.medium_days,
        low_days=body.low_days,
    )


@router.post("/sla/compute", response_model=SlaComputeResult)
async def compute_sla_deadlines(db: DbDep, _admin: AdminDep) -> SlaComputeResult:
    """Recalculate SLA deadlines for all asset CVE links and flag breaches.

    Deadline = discovered_at + days_for_severity.
    A breach is flagged when sla_deadline < today and ack_status != 'accepted'.
    """
    sla_config = await _load_sla_config(db)

    result = await db.execute(
        select(AssetCve).options(selectinload(AssetCve.cve))
    )
    links = result.scalars().all()

    today = date.today()
    updated = 0

    for link in links:
        cve = link.cve
        if not cve:
            continue
        severity = (cve.severity or "Medium").capitalize()
        days = sla_config.get(severity, 30)

        deadline = effective_sla_deadline(
            discovered_at=link.discovered_at,
            severity_days=days,
            ssvc_decision=link.ssvc_decision,
            ssvc_decided_at=link.ssvc_evaluated_at,
        )
        link.sla_deadline = deadline

        # Breach: deadline passed and not accepted
        if deadline < today and link.ack_status != "accepted":
            link.sla_breached = True
        else:
            link.sla_breached = False
        updated += 1

    await db.commit()
    logger.info("SLA deadlines recomputed", updated=updated)
    return SlaComputeResult(updated=updated)


@router.get("/sla/breaches", response_model=list[SlaBreachItem])
async def list_sla_breaches(db: DbDep, _auth: AuthDep) -> list[SlaBreachItem]:
    """List all CVE links that are currently in SLA breach."""
    result = await db.execute(
        select(AssetCve)
        .where(AssetCve.sla_breached.is_(True))
        .options(selectinload(AssetCve.cve))
        .order_by(AssetCve.sla_deadline)
    )
    links = result.scalars().all()

    items = []
    for link in links:
        items.append(
            SlaBreachItem(
                asset_cve_id=link.id,
                asset_id=link.asset_id,
                cve_id=link.cve.cve_id if link.cve else str(link.cve_id),
                severity=link.cve.severity if link.cve else None,
                sla_deadline=link.sla_deadline,
                discovered_at=link.discovered_at,
                ack_status=link.ack_status,
            )
        )
    return items
