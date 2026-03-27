"""EPSS enrichment router — enrich CVEs with FIRST.org EPSS data.

Uses the EPSS bulk CSV from epss.cyentia.com (updated daily) rather than
the per-CVE API which has proven unreliable.
"""

from __future__ import annotations

import csv
import gzip
import io
from datetime import datetime, timezone
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db, require_admin
from netlanventory.core.logging import get_logger
from netlanventory.models.cve import Cve

logger = get_logger(__name__)

router = APIRouter(prefix="/admin/epss", tags=["epss"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
AdminDep = Annotated[object, Depends(require_admin)]

# Bulk CSV updated daily — no rate limit, no auth required
_EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_COMMIT_EVERY = 500


class EpssStatsOut(BaseModel):
    total_cves: int
    enriched_cves: int
    not_enriched: int


class EpssEnrichResult(BaseModel):
    updated: int
    skipped: int
    errors: int


async def _download_epss_map() -> dict[str, tuple[float, float]]:
    """Download the EPSS bulk CSV and return a {cve_id: (epss, percentile)} map."""
    try:
        async with httpx.AsyncClient(timeout=120, follow_redirects=True) as client:
            resp = await client.get(_EPSS_CSV_URL)
            resp.raise_for_status()
            raw = resp.content
    except Exception as exc:  # noqa: BLE001
        logger.error("EPSS CSV download failed", error=str(exc))
        return {}

    epss_map: dict[str, tuple[float, float]] = {}
    try:
        with gzip.open(io.BytesIO(raw), "rt", encoding="utf-8") as f:
            # First line is a comment like: #model_version:...,score_date:...
            # Second line is the CSV header: cve,epss,percentile
            reader = csv.reader(f)
            for row in reader:
                if not row or row[0].startswith("#"):
                    continue
                if row[0] == "cve":  # header
                    continue
                if len(row) < 3:
                    continue
                cve_id = row[0]
                try:
                    epss_map[cve_id] = (float(row[1]), float(row[2]))
                except ValueError:
                    continue
    except Exception as exc:  # noqa: BLE001
        logger.error("EPSS CSV parse failed", error=str(exc))
        return {}

    logger.info("EPSS CSV loaded", total_entries=len(epss_map))
    return epss_map


@router.post("/enrich", response_model=EpssEnrichResult)
async def enrich_epss(
    db: DbDep,
    _admin: AdminDep,
) -> EpssEnrichResult:
    """Enrich all CVEs with EPSS exploitation probability scores.

    Downloads the daily EPSS bulk CSV from epss.cyentia.com and updates
    matching CVE records. Only standard CVE-YYYY-NNNNN identifiers are matched.
    """
    # Download full EPSS dataset once
    epss_map = await _download_epss_map()
    if not epss_map:
        return EpssEnrichResult(updated=0, skipped=0, errors=1)

    # Load all standard CVE IDs from DB
    result = await db.execute(select(Cve.id, Cve.cve_id))
    rows = result.all()
    standard_cves = [(row[0], row[1]) for row in rows if row[1].startswith("CVE-")]

    updated = 0
    skipped = 0
    now = datetime.now(timezone.utc)

    # Fetch all CVE rows in one shot and update in memory
    all_ids = [r[0] for r in standard_cves]
    cve_result = await db.execute(select(Cve).where(Cve.id.in_(all_ids)))
    cve_rows = {c.cve_id: c for c in cve_result.scalars().all()}

    for _uuid, cve_id_str in standard_cves:
        cve_row = cve_rows.get(cve_id_str)
        if not cve_row:
            skipped += 1
            continue
        entry = epss_map.get(cve_id_str)
        if entry is None:
            skipped += 1
            continue
        cve_row.epss_score = entry[0]
        cve_row.epss_percentile = entry[1]
        cve_row.epss_updated_at = now
        updated += 1

        if updated % _COMMIT_EVERY == 0:
            await db.flush()

    await db.commit()
    logger.info("EPSS enrichment complete", updated=updated, skipped=skipped)
    return EpssEnrichResult(updated=updated, skipped=skipped, errors=0)


@router.get("/stats", response_model=EpssStatsOut)
async def epss_stats(
    db: DbDep,
    _admin: AdminDep,
) -> EpssStatsOut:
    """Return statistics on EPSS enrichment coverage."""
    total = (await db.execute(select(func.count()).select_from(Cve))).scalar_one()
    enriched = (
        await db.execute(
            select(func.count()).select_from(Cve).where(Cve.epss_score.isnot(None))
        )
    ).scalar_one()
    return EpssStatsOut(
        total_cves=total,
        enriched_cves=enriched,
        not_enriched=total - enriched,
    )
