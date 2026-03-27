"""Global CVE library router.

Exposes the shared `cves` table so users can browse all known vulnerabilities
across all assets without repeating API calls — the data is cached once and
reused every time the same CVE appears on a new asset.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_current_active_user, get_db
from netlanventory.core.config import get_settings
from netlanventory.core.cve_enrichment import enrich_cves
from netlanventory.core.database import get_session_factory
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve
from netlanventory.schemas.cves import CveDetail, CveList, CveOut


class CvePatch(BaseModel):
    remediation: str | None = None

router = APIRouter(prefix="/cves", tags=["cves"])
DbDep = Annotated[AsyncSession, Depends(get_db)]

_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}


@router.get("", response_model=CveList)
async def list_cves(
    db: DbDep,
    _: Annotated[object, Depends(get_current_active_user)],
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    severity: str | None = Query(None, description="Filter: Critical|High|Medium|Low|Unknown"),
    search: str | None = Query(None, description="Filter by CVE ID substring"),
    epss_min: float | None = Query(None, ge=0.0, le=1.0, description="Minimum EPSS score (0–1)"),
    kev_only: bool = Query(False, description="Only CVEs in CISA KEV"),
    exploit_only: bool = Query(False, description="Only CVEs with exploit/PoC available"),
    maturity: str | None = Query(None, description="Filter by exploit_maturity: none|poc|exploit|weaponized"),
) -> CveList:
    """List all CVEs in the global cache, ordered by severity then CVE ID."""
    query = select(Cve)
    count_query = select(func.count()).select_from(Cve)

    if severity:
        query = query.where(Cve.severity == severity)
        count_query = count_query.where(Cve.severity == severity)
    if search:
        like = f"%{search.upper()}%"
        query = query.where(Cve.cve_id.ilike(like))
        count_query = count_query.where(Cve.cve_id.ilike(like))
    if epss_min is not None:
        query = query.where(Cve.epss_score >= epss_min)
        count_query = count_query.where(Cve.epss_score >= epss_min)
    if kev_only:
        query = query.where(Cve.kev_date_added.isnot(None))
        count_query = count_query.where(Cve.kev_date_added.isnot(None))
    if exploit_only:
        query = query.where(Cve.exploit_maturity.in_(["poc", "exploit", "weaponized"]))
        count_query = count_query.where(Cve.exploit_maturity.in_(["poc", "exploit", "weaponized"]))
    if maturity:
        query = query.where(Cve.exploit_maturity == maturity)
        count_query = count_query.where(Cve.exploit_maturity == maturity)

    total = (await db.execute(count_query)).scalar_one()
    rows = (await db.execute(query.offset(skip).limit(limit))).scalars().all()

    # Attach asset counts
    cve_ids = [r.id for r in rows]
    asset_counts: dict[uuid.UUID, int] = {}
    if cve_ids:
        cnt_result = await db.execute(
            select(AssetCve.cve_id, func.count(AssetCve.asset_id.distinct()))
            .where(AssetCve.cve_id.in_(cve_ids))
            .group_by(AssetCve.cve_id)
        )
        asset_counts = {row[0]: row[1] for row in cnt_result}

    items = sorted(
        [CveOut.from_orm_row(r, asset_counts.get(r.id, 0)) for r in rows],
        key=lambda c: (_SEVERITY_ORDER.get(c.severity or "Unknown", 4), c.cve_id),
    )
    return CveList(total=total, items=items)


@router.get("/{cve_id_str}", response_model=CveDetail)
async def get_cve(
    cve_id_str: str,
    db: DbDep,
    _: Annotated[object, Depends(get_current_active_user)],
) -> CveDetail:
    """Get a single CVE with the list of affected asset IDs."""
    from fastapi import HTTPException, status
    cve = (
        await db.execute(select(Cve).where(Cve.cve_id == cve_id_str.upper()))
    ).scalar_one_or_none()
    if not cve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE not found")

    links = (
        await db.execute(
            select(AssetCve).where(AssetCve.cve_id == cve.id)
        )
    ).scalars().all()
    return CveDetail.from_orm_row(cve, links)


@router.patch("/{cve_id_str}", response_model=CveOut)
async def update_cve(
    cve_id_str: str,
    body: CvePatch,
    db: DbDep,
    current_user: Annotated[object, Depends(get_current_active_user)],
) -> CveOut:
    """Update a CVE's remediation plan (admin only)."""
    if getattr(current_user, "role", None) != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")
    cve = (
        await db.execute(select(Cve).where(Cve.cve_id == cve_id_str.upper()))
    ).scalar_one_or_none()
    if not cve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="CVE not found")
    if body.remediation is not None:
        cve.remediation = body.remediation or None
    await db.commit()
    await db.refresh(cve)
    cnt = (
        await db.execute(
            select(func.count(AssetCve.asset_id.distinct())).where(AssetCve.cve_id == cve.id)
        )
    ).scalar_one()
    return CveOut.from_orm_row(cve, cnt)


@router.post("/enrich", status_code=202)
async def trigger_enrichment(
    background_tasks: BackgroundTasks,
    _: Annotated[object, Depends(get_current_active_user)],
) -> dict:
    """Trigger background enrichment of all CVEs with missing data."""
    background_tasks.add_task(_run_global_enrichment)
    return {"detail": "Enrichment started"}


async def _run_global_enrichment() -> None:
    """Fetch all CVE IDs missing data and enrich them from OSV/NVD."""
    from netlanventory.core.logging import get_logger
    log = get_logger(__name__)
    factory = get_session_factory()
    settings = get_settings()

    async with factory() as session:
        result = await session.execute(
            select(Cve.cve_id).where(
                (Cve.cvss_score.is_(None))
                | (Cve.severity.is_(None))
                | (Cve.severity == "Unknown")
            )
        )
        ids = [r for (r,) in result]
        log.info("Global CVE enrichment started", count=len(ids))
        await enrich_cves(session, ids, nvd_api_key=settings.nvd_api_key)
        await session.commit()
        log.info("Global CVE enrichment complete")
