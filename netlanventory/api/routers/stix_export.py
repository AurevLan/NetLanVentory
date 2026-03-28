"""STIX 2.1 export router.

Exports asset security findings as a STIX 2.1 bundle for SIEM/SOC interoperability.
No external dependency required — generates STIX JSON natively.

Exports:
  - Asset → STIX Infrastructure
  - CVEs → STIX Vulnerability + Relationship
  - Open ports → STIX observed-data
  - Threat IOC matches → STIX Indicator
"""

from __future__ import annotations

import uuid as uuid_mod
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import get_current_active_user, get_db
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.threat_ioc import ThreatIoc

logger = get_logger(__name__)

router = APIRouter(prefix="/export/stix", tags=["export"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]

_STIX_SPEC_VERSION = "2.1"
_IDENTITY_ID = "identity--netlanventory-001"


def _stix_id(type_name: str, seed: str) -> str:
    """Deterministic STIX ID from type + seed (UUID5 in STIX namespace)."""
    ns = uuid_mod.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")  # app-specific namespace
    return f"{type_name}--{uuid_mod.uuid5(ns, seed)}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("/assets/{asset_id}")
@limiter.limit("10/minute")
async def export_asset_stix(
    request: Request,
    asset_id: uuid_mod.UUID,
    db: DbDep,
    _user: UserDep,
) -> JSONResponse:
    """Export a single asset's findings as a STIX 2.1 bundle."""
    asset = (
        await db.execute(
            select(Asset)
            .options(
                selectinload(Asset.ports),
                selectinload(Asset.cves).selectinload(AssetCve.cve),
                selectinload(Asset.dns_entries),
            )
            .where(Asset.id == asset_id)
        )
    ).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    objects = _build_stix_bundle_objects(asset)

    # Add IOC indicators if matching
    ioc_objects = await _build_ioc_indicators(db, asset)
    objects.extend(ioc_objects)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid_mod.uuid4()}",
        "objects": objects,
    }

    return JSONResponse(
        content=bundle,
        media_type="application/stix+json;version=2.1",
        headers={"Content-Disposition": f'attachment; filename="asset-{asset_id}-stix.json"'},
    )


@router.get("/all")
@limiter.limit("3/minute")
async def export_all_stix(
    request: Request,
    db: DbDep,
    _user: UserDep,
) -> JSONResponse:
    """Export all active assets as a STIX 2.1 bundle."""
    result = await db.execute(
        select(Asset)
        .options(
            selectinload(Asset.ports),
            selectinload(Asset.cves).selectinload(AssetCve.cve),
            selectinload(Asset.dns_entries),
        )
        .where(Asset.is_active.is_(True))
    )
    assets = list(result.scalars().all())

    all_objects: list[dict] = [_build_identity()]

    for asset in assets:
        all_objects.extend(_build_stix_bundle_objects(asset, include_identity=False))
        ioc_objects = await _build_ioc_indicators(db, asset)
        all_objects.extend(ioc_objects)

    # Deduplicate by ID
    seen: set[str] = set()
    deduped = []
    for obj in all_objects:
        obj_id = obj.get("id", "")
        if obj_id not in seen:
            seen.add(obj_id)
            deduped.append(obj)

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid_mod.uuid4()}",
        "objects": deduped,
    }

    return JSONResponse(
        content=bundle,
        media_type="application/stix+json;version=2.1",
        headers={"Content-Disposition": 'attachment; filename="netlanventory-all-stix.json"'},
    )


# ── STIX object builders ─────────────────────────────────────────────────────


def _build_identity() -> dict:
    return {
        "type": "identity",
        "spec_version": _STIX_SPEC_VERSION,
        "id": _IDENTITY_ID,
        "created": _now_iso(),
        "modified": _now_iso(),
        "name": "NetLanVentory",
        "identity_class": "system",
        "description": "Automated security audit platform",
    }


def _build_stix_bundle_objects(asset: Asset, include_identity: bool = True) -> list[dict]:
    now = _now_iso()
    objects: list[dict] = []

    if include_identity:
        objects.append(_build_identity())

    # Infrastructure object for the asset
    infra_id = _stix_id("infrastructure", str(asset.id))
    infra = {
        "type": "infrastructure",
        "spec_version": _STIX_SPEC_VERSION,
        "id": infra_id,
        "created": now,
        "modified": now,
        "name": asset.name or asset.hostname or str(asset.ip),
        "description": f"Asset {asset.ip} ({asset.hostname or 'unknown'})",
        "infrastructure_types": [_infer_infra_type(asset)],
        "created_by_ref": _IDENTITY_ID,
    }

    # Custom properties for asset metadata
    if asset.ip:
        infra["x_netlanventory_ip"] = str(asset.ip)
    if asset.mac:
        infra["x_netlanventory_mac"] = asset.mac
    if asset.os_family:
        infra["x_netlanventory_os"] = f"{asset.os_family} {asset.os_version or ''}".strip()
    if asset.criticality:
        infra["x_netlanventory_criticality"] = asset.criticality
    if asset.risk_score is not None:
        infra["x_netlanventory_risk_score"] = asset.risk_score

    objects.append(infra)

    # Vulnerability objects for CVEs
    for link in (asset.cves or []):
        cve = link.cve
        if not cve:
            continue

        vuln_id = _stix_id("vulnerability", cve.cve_id)
        vuln = {
            "type": "vulnerability",
            "spec_version": _STIX_SPEC_VERSION,
            "id": vuln_id,
            "created": now,
            "modified": now,
            "name": cve.cve_id,
            "description": (cve.description or "")[:500],
            "created_by_ref": _IDENTITY_ID,
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": cve.cve_id,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}",
                }
            ],
        }

        if cve.cvss_score is not None:
            vuln["x_netlanventory_cvss"] = cve.cvss_score
        if cve.severity:
            vuln["x_netlanventory_severity"] = cve.severity
        if hasattr(cve, "epss_score") and cve.epss_score is not None:
            vuln["x_netlanventory_epss"] = cve.epss_score

        objects.append(vuln)

        # Relationship: infrastructure → vulnerability
        rel_id = _stix_id("relationship", f"{asset.id}-{cve.cve_id}")
        objects.append({
            "type": "relationship",
            "spec_version": _STIX_SPEC_VERSION,
            "id": rel_id,
            "created": now,
            "modified": now,
            "relationship_type": "has",
            "source_ref": infra_id,
            "target_ref": vuln_id,
            "created_by_ref": _IDENTITY_ID,
        })

    # Observed-data for open ports
    open_ports = [p for p in (asset.ports or []) if p.state == "open"]
    if open_ports:
        observed_id = _stix_id("observed-data", f"{asset.id}-ports")
        objects.append({
            "type": "observed-data",
            "spec_version": _STIX_SPEC_VERSION,
            "id": observed_id,
            "created": now,
            "modified": now,
            "first_observed": now,
            "last_observed": now,
            "number_observed": len(open_ports),
            "created_by_ref": _IDENTITY_ID,
            "x_netlanventory_ports": [
                {
                    "port": p.port_number,
                    "protocol": p.protocol or "tcp",
                    "service": p.service_name or "",
                    "version": p.service_version or "",
                }
                for p in open_ports
            ],
        })

    return objects


async def _build_ioc_indicators(db: AsyncSession, asset: Asset) -> list[dict]:
    """Build STIX Indicator objects for IOCs matching this asset."""
    now = _now_iso()
    objects: list[dict] = []

    if not asset.ip:
        return objects

    result = await db.execute(
        select(ThreatIoc).where(
            ThreatIoc.indicator == str(asset.ip),
            ThreatIoc.ioc_type == "ip",
        )
    )
    iocs = list(result.scalars().all())

    for ioc in iocs:
        indicator_id = _stix_id("indicator", f"ioc-{ioc.id}")
        objects.append({
            "type": "indicator",
            "spec_version": _STIX_SPEC_VERSION,
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": f"IOC: {ioc.indicator}",
            "description": ioc.description or f"Threat indicator from {ioc.source}",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[ipv4-addr:value = '{ioc.indicator}']",
            "pattern_type": "stix",
            "valid_from": (ioc.first_seen or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "created_by_ref": _IDENTITY_ID,
            "x_netlanventory_source": ioc.source,
            "x_netlanventory_severity": ioc.severity,
        })

    return objects


def _infer_infra_type(asset: Asset) -> str:
    os_lower = (asset.os_family or "").lower()
    device = (asset.device_type or "").lower()
    if "windows" in os_lower and "server" in os_lower:
        return "hosting-target-lists"
    if any(kw in device for kw in ("router", "switch", "firewall", "gateway")):
        return "routers-switches"
    if any(kw in device for kw in ("workstation", "desktop", "laptop")):
        return "workstation"
    return "unknown"
