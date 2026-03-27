"""Global full-text search router.

Searches across assets, CVEs using PostgreSQL full-text search (tsvector).
Falls back to ILIKE if tsvector columns are not available (e.g. SQLite in tests).
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db
from netlanventory.models.asset import Asset
from netlanventory.models.cve import Cve

router = APIRouter(prefix="/search", tags=["search"])

DbDep = Annotated[AsyncSession, Depends(get_db)]


class SearchResult(BaseModel):
    type: str           # "asset" | "cve"
    id: str
    title: str
    subtitle: str | None = None
    severity: str | None = None


class SearchResponse(BaseModel):
    results: list[SearchResult]
    total: int
    query: str


@router.get("", response_model=SearchResponse)
async def global_search(
    db: DbDep,
    q: str = Query(..., min_length=2, max_length=200),
    types: str = Query("assets,cves", description="Comma-separated list: assets,cves"),
    limit: int = Query(20, ge=1, le=100),
) -> SearchResponse:
    """Search across assets and CVEs using full-text search."""
    if not q.strip():
        return SearchResponse(results=[], total=0, query=q)

    search_types = {t.strip() for t in types.split(",")}
    results: list[SearchResult] = []
    q_clean = q.strip()

    # Try PostgreSQL full-text search first, fall back to ILIKE
    try:
        if "assets" in search_types:
            asset_results = await _search_assets_fts(db, q_clean, limit)
            results.extend(asset_results)

        if "cves" in search_types:
            cve_results = await _search_cves_fts(db, q_clean, limit)
            results.extend(cve_results)
    except Exception:
        # Fallback to simple ILIKE search
        if "assets" in search_types:
            results.extend(await _search_assets_ilike(db, q_clean, limit))
        if "cves" in search_types:
            results.extend(await _search_cves_ilike(db, q_clean, limit))

    # Deduplicate and limit
    seen: set[str] = set()
    unique_results = []
    for r in results:
        key = f"{r.type}:{r.id}"
        if key not in seen:
            seen.add(key)
            unique_results.append(r)

    unique_results = unique_results[:limit]
    return SearchResponse(results=unique_results, total=len(unique_results), query=q)


async def _search_assets_fts(db: AsyncSession, q: str, limit: int) -> list[SearchResult]:
    """Search assets using PostgreSQL tsvector."""
    rows = (
        await db.execute(
            select(Asset.id, Asset.ip, Asset.hostname, Asset.name, Asset.device_type)
            .where(
                text("search_vector @@ plainto_tsquery('simple', :q)").bindparams(q=q)
            )
            .order_by(
                text("ts_rank(search_vector, plainto_tsquery('simple', :q)) DESC").bindparams(q=q)
            )
            .limit(limit)
        )
    ).all()

    return [
        SearchResult(
            type="asset",
            id=str(row.id),
            title=row.ip or str(row.id)[:8],
            subtitle=row.hostname or row.name or row.device_type,
        )
        for row in rows
    ]


async def _search_cves_fts(db: AsyncSession, q: str, limit: int) -> list[SearchResult]:
    """Search CVEs using PostgreSQL tsvector."""
    rows = (
        await db.execute(
            select(Cve.id, Cve.cve_id, Cve.description, Cve.severity)
            .where(
                text("search_vector @@ plainto_tsquery('english', :q)").bindparams(q=q)
            )
            .order_by(
                text("ts_rank(search_vector, plainto_tsquery('english', :q)) DESC").bindparams(q=q)
            )
            .limit(limit)
        )
    ).all()

    return [
        SearchResult(
            type="cve",
            id=str(row.id),
            title=row.cve_id,
            subtitle=(row.description or "")[:100],
            severity=row.severity,
        )
        for row in rows
    ]


async def _search_assets_ilike(db: AsyncSession, q: str, limit: int) -> list[SearchResult]:
    """Fallback: search assets using ILIKE (no tsvector needed)."""
    pattern = f"%{q}%"
    rows = (
        await db.execute(
            select(Asset.id, Asset.ip, Asset.hostname, Asset.name, Asset.device_type)
            .where(
                Asset.ip.ilike(pattern)
                | Asset.hostname.ilike(pattern)
                | Asset.name.ilike(pattern)
            )
            .limit(limit)
        )
    ).all()

    return [
        SearchResult(
            type="asset",
            id=str(row.id),
            title=row.ip or str(row.id)[:8],
            subtitle=row.hostname or row.name or row.device_type,
        )
        for row in rows
    ]


async def _search_cves_ilike(db: AsyncSession, q: str, limit: int) -> list[SearchResult]:
    """Fallback: search CVEs using ILIKE."""
    pattern = f"%{q}%"
    rows = (
        await db.execute(
            select(Cve.id, Cve.cve_id, Cve.description, Cve.severity)
            .where(
                Cve.cve_id.ilike(pattern)
                | Cve.description.ilike(pattern)
            )
            .limit(limit)
        )
    ).all()

    return [
        SearchResult(
            type="cve",
            id=str(row.id),
            title=row.cve_id,
            subtitle=(row.description or "")[:100],
            severity=row.severity,
        )
        for row in rows
    ]
