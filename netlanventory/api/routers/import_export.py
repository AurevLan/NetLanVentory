"""Import/Export router — CSV bulk import and export of assets.

GET  /api/v1/assets/export/csv  — stream all assets as CSV
POST /api/v1/assets/import/csv  — multipart CSV upload; create or update by IP
"""

from __future__ import annotations

import csv
import io
import ipaddress
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import get_db
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve

logger = get_logger(__name__)

router = APIRouter(tags=["import-export"])

DbDep = Annotated[AsyncSession, Depends(get_db)]

# Columns included in the CSV export
_EXPORT_COLUMNS = [
    "id",
    "name",
    "ip",
    "mac",
    "hostname",
    "vendor",
    "device_type",
    "os_family",
    "os_version",
    "is_active",
    "tags",
    "ssh_profile_name",
    "open_ports",
    "cve_count",
    "created_at",
]

# Columns accepted in CSV import
_IMPORT_COLUMNS = {
    "name",
    "ip",
    "mac",
    "hostname",
    "vendor",
    "device_type",
    "os_family",
    "os_version",
    "notes",
}


@router.get("/assets/export/csv")
@limiter.limit("10/minute")
async def export_assets_csv(request: Request, db: DbDep) -> StreamingResponse:
    """Stream all assets as a CSV file."""
    result = await db.execute(
        select(Asset).options(
            selectinload(Asset.ports),
            selectinload(Asset.cves).selectinload(AssetCve.cve),
            selectinload(Asset.ssh_profile),
            selectinload(Asset.tags),
        )
    )
    assets = result.scalars().all()

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=_EXPORT_COLUMNS, lineterminator="\n")
    writer.writeheader()

    for asset in assets:
        open_ports = ",".join(
            str(p.port_number) for p in (asset.ports or []) if p.state == "open"
        )
        tags = ",".join(t.name for t in (asset.tags or []))
        ssh_profile_name = asset.ssh_profile.name if asset.ssh_profile else ""
        cve_count = len(asset.cves or [])
        writer.writerow({
            "id": str(asset.id),
            "name": asset.name or "",
            "ip": asset.ip or "",
            "mac": asset.mac or "",
            "hostname": asset.hostname or "",
            "vendor": asset.vendor or "",
            "device_type": asset.device_type or "",
            "os_family": asset.os_family or "",
            "os_version": asset.os_version or "",
            "is_active": str(asset.is_active).lower(),
            "tags": tags,
            "ssh_profile_name": ssh_profile_name,
            "open_ports": open_ports,
            "cve_count": cve_count,
            "created_at": asset.created_at.isoformat() if asset.created_at else "",
        })

    csv_content = output.getvalue()
    output.close()

    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="assets.csv"'},
    )


@router.post("/assets/import/csv")
async def import_assets_csv(
    db: DbDep,
    file: UploadFile = File(...),
) -> dict:
    """Import assets from a CSV file. Creates or updates assets by IP address."""
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File must be a CSV (.csv extension required)",
        )

    content = await file.read()
    try:
        text = content.decode("utf-8-sig")  # handle BOM
    except UnicodeDecodeError:
        try:
            text = content.decode("latin-1")
        except UnicodeDecodeError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Could not decode CSV file — use UTF-8 encoding",
            )

    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CSV file is empty or has no header row",
        )

    # Normalise column names (strip whitespace, lowercase)
    fieldnames = [f.strip().lower() for f in reader.fieldnames]
    missing = _IMPORT_COLUMNS - {"ip"}  # ip is optional but useful for matching
    unknown = set(fieldnames) - _IMPORT_COLUMNS - {"ip"}

    imported = 0
    updated = 0
    errors: list[str] = []

    for row_num, raw_row in enumerate(reader, start=2):
        row = {k.strip().lower(): (v or "").strip() for k, v in raw_row.items()}
        ip = row.get("ip") or None
        mac = row.get("mac") or None

        # Validate IP address if provided
        if ip:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                errors.append(f"Row {row_num}: Invalid IP address '{ip}' — skipped")
                logger.warning("CSV import invalid IP", row=row_num, ip=ip)
                continue

        try:
            # Try to find existing asset by IP, then MAC
            existing: Asset | None = None
            if ip:
                res = await db.execute(select(Asset).where(Asset.ip == ip))
                existing = res.scalar_one_or_none()
            if existing is None and mac:
                res = await db.execute(select(Asset).where(Asset.mac == mac))
                existing = res.scalar_one_or_none()

            fields = {
                "name": row.get("name") or None,
                "ip": ip,
                "mac": mac,
                "hostname": row.get("hostname") or None,
                "vendor": row.get("vendor") or None,
                "device_type": row.get("device_type") or None,
                "os_family": row.get("os_family") or None,
                "os_version": row.get("os_version") or None,
                "notes": row.get("notes") or None,
            }

            if existing:
                for field, value in fields.items():
                    if value is not None:
                        setattr(existing, field, value)
                updated += 1
            else:
                asset = Asset(**{k: v for k, v in fields.items() if v is not None})
                db.add(asset)
                imported += 1

        except Exception as exc:
            errors.append(f"Row {row_num}: {exc}")
            logger.warning("CSV import row error", row=row_num, error=str(exc))

    await db.commit()

    return {"imported": imported, "updated": updated, "errors": errors}
