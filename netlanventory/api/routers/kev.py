"""CISA KEV (Known Exploited Vulnerabilities) sync router.

Downloads the CISA KEV catalog and marks matching CVEs as actively exploited.
Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (public, no auth)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db, require_admin
from netlanventory.core.logging import get_logger
from netlanventory.models.cve import Cve

logger = get_logger(__name__)

router = APIRouter(prefix="/admin/kev", tags=["threat-intel"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
AdminDep = Annotated[object, Depends(require_admin)]

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KevSyncResult(BaseModel):
    kev_total: int       # CVEs in KEV catalog
    matched: int         # matched against our CVE library
    unmatched: int       # in KEV but not in our DB


class KevStatsOut(BaseModel):
    kev_count: int
    ransomware_count: int
    last_sync: str | None


@router.post("/sync", response_model=KevSyncResult)
async def sync_kev(db: DbDep, _admin: AdminDep) -> KevSyncResult:
    """Download the CISA KEV catalog and update matching CVEs."""
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            resp = await client.get(_KEV_URL)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.error("KEV download failed", error=str(exc))
        from fastapi import HTTPException, status
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"KEV download failed: {exc}")

    vulnerabilities = data.get("vulnerabilities", [])
    kev_total = len(vulnerabilities)
    logger.info("KEV catalog downloaded", total=kev_total)

    # Build lookup: cve_id -> {date_added, ransomware}
    kev_map: dict[str, dict] = {}
    for v in vulnerabilities:
        cve_id = v.get("cveID", "")
        if cve_id:
            kev_map[cve_id] = {
                "date_added": v.get("dateAdded"),
                "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known",
            }

    # Load all CVEs from DB
    result = await db.execute(select(Cve))
    cves = result.scalars().all()

    now = datetime.now(timezone.utc)
    matched = 0
    changed = 0

    for cve in cves:
        entry = kev_map.get(cve.cve_id)
        if entry:
            matched += 1
            from datetime import date as _date
            date_str = entry["date_added"]
            kev_date = None
            if date_str:
                try:
                    kev_date = _date.fromisoformat(date_str)
                except ValueError:
                    pass
            cve.kev_date_added = kev_date
            cve.kev_ransomware_use = entry["ransomware"]
            cve.exploit_maturity = "weaponized"
            cve.threat_intel_updated_at = now
            changed += 1
        else:
            # Clear KEV fields if no longer in catalog
            if cve.kev_date_added is not None:
                cve.kev_date_added = None
                cve.kev_ransomware_use = False
                # Don't downgrade maturity — other sources may have set it

    await db.commit()
    logger.info("KEV sync complete", matched=matched, unmatched=kev_total - matched)
    return KevSyncResult(kev_total=kev_total, matched=matched, unmatched=kev_total - matched)


@router.get("/stats", response_model=KevStatsOut)
async def kev_stats(db: DbDep, _admin: AdminDep) -> KevStatsOut:
    """Return KEV coverage statistics."""
    from sqlalchemy import func
    kev_count = (
        await db.execute(
            select(func.count()).select_from(Cve).where(Cve.kev_date_added.isnot(None))
        )
    ).scalar_one()
    ransomware_count = (
        await db.execute(
            select(func.count()).select_from(Cve).where(Cve.kev_ransomware_use.is_(True))
        )
    ).scalar_one()
    last_sync_row = (
        await db.execute(
            select(func.max(Cve.threat_intel_updated_at)).select_from(Cve)
        )
    ).scalar_one()
    return KevStatsOut(
        kev_count=kev_count,
        ransomware_count=ransomware_count,
        last_sync=last_sync_row.isoformat() if last_sync_row else None,
    )
