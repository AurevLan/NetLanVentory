"""Scheduled reports router — manage and trigger automated email reports."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db
from netlanventory.core.logging import get_logger
from netlanventory.models.scheduled_report import ScheduledReport

logger = get_logger(__name__)
router = APIRouter(prefix="/scheduled-reports", tags=["scheduled-reports"])

DbDep = Annotated[AsyncSession, Depends(get_db)]

_VALID_SCHEDULES = {"daily", "weekly", "monthly"}
_VALID_REPORT_TYPES = {"executive", "full", "assets", "cves"}


class ScheduledReportCreate(BaseModel):
    name: str
    report_type: str  # executive | full | assets | cves
    schedule: str  # daily | weekly | monthly
    recipients: list[str]
    enabled: bool = True


class ScheduledReportResponse(BaseModel):
    id: str
    name: str
    report_type: str
    schedule: str
    recipients: list[str]
    enabled: bool
    last_sent_at: str | None
    next_run_at: str | None


def _compute_next_run(schedule: str) -> datetime:
    now = datetime.now(timezone.utc)
    if schedule == "daily":
        return now + timedelta(days=1)
    elif schedule == "weekly":
        return now + timedelta(weeks=1)
    else:  # monthly
        return now + timedelta(days=30)


@router.get("", response_model=list[ScheduledReportResponse])
async def list_scheduled_reports(db: DbDep) -> list[ScheduledReportResponse]:
    rows = (await db.execute(select(ScheduledReport).order_by(ScheduledReport.name))).scalars().all()
    return [
        ScheduledReportResponse(
            id=str(r.id),
            name=r.name,
            report_type=r.report_type,
            schedule=r.schedule,
            recipients=r.recipients or [],
            enabled=r.enabled,
            last_sent_at=r.last_sent_at.isoformat() if r.last_sent_at else None,
            next_run_at=r.next_run_at.isoformat() if r.next_run_at else None,
        )
        for r in rows
    ]


@router.post("", response_model=ScheduledReportResponse, status_code=201)
async def create_scheduled_report(body: ScheduledReportCreate, db: DbDep) -> ScheduledReportResponse:
    if body.schedule not in _VALID_SCHEDULES:
        raise HTTPException(status_code=400, detail=f"schedule must be one of: {', '.join(_VALID_SCHEDULES)}")
    if body.report_type not in _VALID_REPORT_TYPES:
        raise HTTPException(status_code=400, detail=f"report_type must be one of: {', '.join(_VALID_REPORT_TYPES)}")
    if not body.recipients:
        raise HTTPException(status_code=400, detail="recipients must not be empty")

    sr = ScheduledReport(
        name=body.name,
        report_type=body.report_type,
        schedule=body.schedule,
        recipients=body.recipients,
        enabled=body.enabled,
        next_run_at=_compute_next_run(body.schedule),
    )
    db.add(sr)
    await db.commit()
    await db.refresh(sr)

    return ScheduledReportResponse(
        id=str(sr.id),
        name=sr.name,
        report_type=sr.report_type,
        schedule=sr.schedule,
        recipients=sr.recipients or [],
        enabled=sr.enabled,
        last_sent_at=None,
        next_run_at=sr.next_run_at.isoformat() if sr.next_run_at else None,
    )


@router.put("/{report_id}", response_model=ScheduledReportResponse)
async def update_scheduled_report(report_id: str, body: ScheduledReportCreate, db: DbDep) -> ScheduledReportResponse:
    try:
        rid = uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report_id")

    sr = (await db.execute(select(ScheduledReport).where(ScheduledReport.id == rid))).scalar_one_or_none()
    if not sr:
        raise HTTPException(status_code=404, detail="Scheduled report not found")

    sr.name = body.name
    sr.report_type = body.report_type
    sr.schedule = body.schedule
    sr.recipients = body.recipients
    sr.enabled = body.enabled
    if sr.schedule != body.schedule:
        sr.next_run_at = _compute_next_run(body.schedule)

    await db.commit()
    await db.refresh(sr)

    return ScheduledReportResponse(
        id=str(sr.id),
        name=sr.name,
        report_type=sr.report_type,
        schedule=sr.schedule,
        recipients=sr.recipients or [],
        enabled=sr.enabled,
        last_sent_at=sr.last_sent_at.isoformat() if sr.last_sent_at else None,
        next_run_at=sr.next_run_at.isoformat() if sr.next_run_at else None,
    )


@router.delete("/{report_id}", status_code=204)
async def delete_scheduled_report(report_id: str, db: DbDep) -> None:
    try:
        rid = uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report_id")

    sr = (await db.execute(select(ScheduledReport).where(ScheduledReport.id == rid))).scalar_one_or_none()
    if not sr:
        raise HTTPException(status_code=404, detail="Scheduled report not found")

    await db.delete(sr)
    await db.commit()


@router.post("/{report_id}/send", status_code=202)
async def send_report_now(report_id: str, background_tasks: BackgroundTasks, db: DbDep) -> dict:
    """Trigger immediate send of a scheduled report."""
    try:
        rid = uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report_id")

    sr = (await db.execute(select(ScheduledReport).where(ScheduledReport.id == rid))).scalar_one_or_none()
    if not sr:
        raise HTTPException(status_code=404, detail="Scheduled report not found")

    async def _send() -> None:
        from netlanventory.core.database import get_session_factory
        from netlanventory.core.email_sender import send_report_email

        factory = get_session_factory()
        async with factory() as session:
            report = (await session.execute(
                select(ScheduledReport).where(ScheduledReport.id == rid)
            )).scalar_one_or_none()
            if not report:
                return

            subject = f"[NetLanVentory] {report.name} — {report.report_type} report"
            html_body = f"<h1>NetLanVentory Report: {report.name}</h1><p>Type: {report.report_type}</p>"

            try:
                await send_report_email(
                    recipients=report.recipients,
                    subject=subject,
                    html_body=html_body,
                    pdf_attachment=None,
                )
                report.last_sent_at = datetime.now(timezone.utc)
                report.next_run_at = _compute_next_run(report.schedule)
                await session.commit()
                logger.info("Scheduled report sent", report=report.name, recipients=report.recipients)
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to send scheduled report", error=str(exc))

    background_tasks.add_task(_send)
    return {"status": "queued", "report_id": report_id}
