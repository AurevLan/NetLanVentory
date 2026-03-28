"""Discovery timeline API — chronological event feed."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, union_all, literal, text
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve
from netlanventory.models.port import Port
from netlanventory.models.scan import Scan

router = APIRouter(prefix="/timeline", tags=["timeline"])

DbDep = Annotated[AsyncSession, Depends(get_db)]


class TimelineEvent(BaseModel):
    event_type: str       # asset_discovered | cve_found | port_opened | scan_completed
    timestamp: datetime
    asset_id: str | None
    asset_ip: str | None
    detail: str           # human-readable summary
    severity: str | None  # critical | high | medium | low | info


@router.get("", response_model=list[TimelineEvent])
async def get_timeline(
    db: DbDep,
    limit: int = Query(100, ge=1, le=500),
    asset_id: str | None = Query(None),
) -> list[TimelineEvent]:
    """Return a unified chronological event feed from all data sources."""
    events: list[TimelineEvent] = []

    # 1. Asset discoveries
    asset_q = select(Asset.id, Asset.ip, Asset.name, Asset.created_at, Asset.criticality)
    if asset_id:
        try:
            aid = uuid.UUID(asset_id)
            asset_q = asset_q.where(Asset.id == aid)
        except ValueError:
            pass
    asset_rows = (await db.execute(asset_q.order_by(Asset.created_at.desc()).limit(limit))).all()
    for row in asset_rows:
        if row.created_at:
            events.append(TimelineEvent(
                event_type="asset_discovered",
                timestamp=row.created_at,
                asset_id=str(row.id),
                asset_ip=row.ip,
                detail=f"Asset discovered: {row.ip or row.name or str(row.id)[:8]}",
                severity="info",
            ))

    # 2. CVE findings
    cve_q = (
        select(
            AssetCve.asset_id,
            AssetCve.discovered_at,
            Cve.cve_id,
            Cve.severity,
            Asset.ip,
        )
        .join(Cve, AssetCve.cve_id == Cve.id)
        .join(Asset, AssetCve.asset_id == Asset.id)
    )
    if asset_id:
        try:
            aid = uuid.UUID(asset_id)
            cve_q = cve_q.where(AssetCve.asset_id == aid)
        except ValueError:
            pass
    cve_rows = (
        await db.execute(
            cve_q.order_by(AssetCve.discovered_at.desc()).limit(limit)
        )
    ).all()
    for row in cve_rows:
        if row.discovered_at:
            events.append(TimelineEvent(
                event_type="cve_found",
                timestamp=row.discovered_at,
                asset_id=str(row.asset_id),
                asset_ip=row.ip,
                detail=f"CVE found: {row.cve_id} on {row.ip or str(row.asset_id)[:8]}",
                severity=row.severity,
            ))

    # 3. Port openings
    port_q = (
        select(Port.asset_id, Port.created_at, Port.port_number, Port.service_name, Asset.ip)
        .join(Asset, Port.asset_id == Asset.id)
        .where(Port.state == "open")
    )
    if asset_id:
        try:
            aid = uuid.UUID(asset_id)
            port_q = port_q.where(Port.asset_id == aid)
        except ValueError:
            pass
    port_rows = (
        await db.execute(
            port_q.order_by(Port.created_at.desc()).limit(limit)
        )
    ).all()
    for row in port_rows:
        if row.created_at:
            svc = f" ({row.service_name})" if row.service_name else ""
            events.append(TimelineEvent(
                event_type="port_opened",
                timestamp=row.created_at,
                asset_id=str(row.asset_id),
                asset_ip=row.ip,
                detail=f"Port {row.port_number}{svc} open on {row.ip or str(row.asset_id)[:8]}",
                severity="info",
            ))

    # 4. Completed scans
    if not asset_id:
        scan_rows = (
            await db.execute(
                select(Scan.id, Scan.target, Scan.finished_at, Scan.summary)
                .where(Scan.status == "completed", Scan.finished_at.isnot(None))
                .order_by(Scan.finished_at.desc())
                .limit(limit // 4)
            )
        ).all()
        for row in scan_rows:
            summary = row.summary or {}
            hosts_found = summary.get("hosts_found", 0)
            events.append(TimelineEvent(
                event_type="scan_completed",
                timestamp=row.finished_at,
                asset_id=None,
                asset_ip=None,
                detail=f"Scan completed: {row.target} ({hosts_found} hosts found)",
                severity="info",
            ))

    # Sort all events by timestamp descending and return top N
    events.sort(key=lambda e: e.timestamp, reverse=True)
    return events[:limit]
