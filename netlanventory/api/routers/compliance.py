"""Compliance framework evaluation router — ISO 27001, NIS2, ANSSI."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db
from netlanventory.core.logging import get_logger
from netlanventory.models.compliance_report import ComplianceReport

logger = get_logger(__name__)
router = APIRouter(prefix="/compliance", tags=["compliance"])

DbDep = Annotated[AsyncSession, Depends(get_db)]

_FRAMEWORKS = {
    "iso27001": {
        "name": "ISO 27001:2022",
        "description": "International standard for information security management systems",
        "controls_count": 93,
    },
    "nis2": {
        "name": "NIS2 Directive",
        "description": "EU directive on the security of network and information systems",
        "controls_count": 10,
    },
    "anssi": {
        "name": "ANSSI Guide d'Hygiène",
        "description": "42 measures for securing information systems (ANSSI France)",
        "controls_count": 42,
    },
}


class FrameworkInfo(BaseModel):
    id: str
    name: str
    description: str
    controls_count: int


class ComplianceReportResponse(BaseModel):
    id: str
    framework: str
    framework_name: str
    scope: str
    score: int | None
    status: str
    findings_count: int
    generated_at: str | None


class ComplianceReportDetail(ComplianceReportResponse):
    findings: list[dict]


@router.get("/frameworks", response_model=list[FrameworkInfo])
async def list_frameworks() -> list[FrameworkInfo]:
    """List available compliance frameworks."""
    return [FrameworkInfo(id=fid, **finfo) for fid, finfo in _FRAMEWORKS.items()]


@router.post("/evaluate/{framework}", response_model=ComplianceReportResponse)
async def evaluate_framework(
    framework: str,
    background_tasks: BackgroundTasks,
    db: DbDep,
    scope: str = Query("full", description="Evaluation scope"),
) -> ComplianceReportResponse:
    """Launch a compliance evaluation in the background."""
    if framework not in _FRAMEWORKS:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown framework. Available: {', '.join(_FRAMEWORKS)}",
        )

    # Create a pending report
    report = ComplianceReport(
        framework=framework,
        scope=scope,
        status="pending",
        findings=[],
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    report_id = report.id

    async def _run_evaluation() -> None:
        from netlanventory.core.database import get_session_factory

        factory = get_session_factory()
        async with factory() as session:
            db_report = (await session.execute(
                select(ComplianceReport).where(ComplianceReport.id == report_id)
            )).scalar_one_or_none()
            if not db_report:
                return

            try:
                db_report.status = "running"
                await session.commit()

                if framework == "iso27001":
                    from netlanventory.core.compliance.iso27001 import evaluate_iso27001
                    result = await evaluate_iso27001(session)
                elif framework == "nis2":
                    from netlanventory.core.compliance.nis2 import evaluate_nis2
                    result = await evaluate_nis2(session)
                elif framework == "anssi":
                    from netlanventory.core.compliance.anssi import evaluate_anssi
                    result = await evaluate_anssi(session)
                else:
                    raise ValueError(f"Unknown framework: {framework}")

                db_report.score = result["score"]
                db_report.findings = result["findings"]
                db_report.status = "completed"

            except Exception as exc:  # noqa: BLE001
                logger.error("Compliance evaluation failed", framework=framework, error=str(exc))
                db_report.status = "failed"
                db_report.findings = [{"error": str(exc)}]

            await session.commit()

    background_tasks.add_task(_run_evaluation)

    fw_info = _FRAMEWORKS[framework]
    return ComplianceReportResponse(
        id=str(report.id),
        framework=framework,
        framework_name=fw_info["name"],
        scope=scope,
        score=None,
        status="pending",
        findings_count=0,
        generated_at=report.generated_at.isoformat() if report.generated_at else None,
    )


@router.get("/reports", response_model=list[ComplianceReportResponse])
async def list_reports(
    db: DbDep,
    framework: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
) -> list[ComplianceReportResponse]:
    """List compliance reports."""
    q = select(ComplianceReport).order_by(ComplianceReport.generated_at.desc()).limit(limit)
    if framework:
        q = q.where(ComplianceReport.framework == framework)

    rows = (await db.execute(q)).scalars().all()
    return [
        ComplianceReportResponse(
            id=str(r.id),
            framework=r.framework,
            framework_name=_FRAMEWORKS.get(r.framework, {}).get("name", r.framework),
            scope=r.scope,
            score=r.score,
            status=r.status,
            findings_count=len(r.findings) if r.findings else 0,
            generated_at=r.generated_at.isoformat() if r.generated_at else None,
        )
        for r in rows
    ]


@router.get("/reports/{report_id}", response_model=ComplianceReportDetail)
async def get_report(report_id: str, db: DbDep) -> ComplianceReportDetail:
    """Get full compliance report with findings."""
    try:
        rid = uuid.UUID(report_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid report_id")

    report = (await db.execute(select(ComplianceReport).where(ComplianceReport.id == rid))).scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return ComplianceReportDetail(
        id=str(report.id),
        framework=report.framework,
        framework_name=_FRAMEWORKS.get(report.framework, {}).get("name", report.framework),
        scope=report.scope,
        score=report.score,
        status=report.status,
        findings_count=len(report.findings) if report.findings else 0,
        generated_at=report.generated_at.isoformat() if report.generated_at else None,
        findings=report.findings or [],
    )
