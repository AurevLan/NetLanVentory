"""Network topology API — graph data for D3.js visualization."""

from __future__ import annotations

import ipaddress
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import get_db
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve

router = APIRouter(prefix="/topology", tags=["topology"])

DbDep = Annotated[AsyncSession, Depends(get_db)]


class TopologyNode(BaseModel):
    id: str
    ip: str | None
    hostname: str | None
    name: str | None
    device_type: str | None
    os_family: str | None
    criticality: str
    risk_score: float | None
    cve_count: int
    critical_cve_count: int
    is_active: bool
    discovery_source: str | None
    subnet: str | None  # /24 subnet label


class TopologyLink(BaseModel):
    source: str
    target: str
    link_type: str  # "subnet" | "service"
    detail: str | None = None


class SubnetGroup(BaseModel):
    subnet: str  # e.g. "192.168.1.0/24"
    asset_count: int
    avg_risk_score: float
    critical_count: int


class TopologyData(BaseModel):
    nodes: list[TopologyNode]
    links: list[TopologyLink]
    subnets: list[SubnetGroup]


def _get_subnet24(ip: str | None) -> str | None:
    """Return the /24 subnet label for an IP, e.g. '192.168.1.0/24'."""
    if not ip:
        return None
    try:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(net)
    except ValueError:
        return None


@router.get("", response_model=TopologyData)
async def get_topology(db: DbDep) -> TopologyData:
    """Return graph data for the network topology visualization.

    Nodes = assets, Links = shared-subnet or shared-service relationships.
    """
    # Load all assets with ports and CVE counts
    result = await db.execute(
        select(Asset)
        .options(selectinload(Asset.ports))
        .order_by(Asset.ip)
    )
    assets = result.scalars().all()

    # CVE counts per asset
    cve_counts = {}
    critical_counts = {}
    cve_rows = (
        await db.execute(
            select(
                AssetCve.asset_id,
                func.count(AssetCve.id).label("total"),
                func.sum(
                    func.case((Cve.severity == "Critical", 1), else_=0)
                ).label("critical"),
            )
            .join(Cve, AssetCve.cve_id == Cve.id)
            .group_by(AssetCve.asset_id)
        )
    ).all()
    for row in cve_rows:
        cve_counts[str(row.asset_id)] = row.total or 0
        critical_counts[str(row.asset_id)] = int(row.critical or 0)

    # Build nodes
    nodes: list[TopologyNode] = []
    subnet_assets: dict[str, list[Asset]] = {}

    for asset in assets:
        asset_id = str(asset.id)
        subnet = _get_subnet24(asset.ip)
        if subnet:
            subnet_assets.setdefault(subnet, []).append(asset)

        nodes.append(TopologyNode(
            id=asset_id,
            ip=asset.ip,
            hostname=asset.hostname,
            name=asset.name,
            device_type=asset.device_type,
            os_family=asset.os_family,
            criticality=asset.criticality or "medium",
            risk_score=asset.risk_score,
            cve_count=cve_counts.get(asset_id, 0),
            critical_cve_count=critical_counts.get(asset_id, 0),
            is_active=asset.is_active,
            discovery_source=getattr(asset, "discovery_source", None),
            subnet=subnet,
        ))

    # Build subnet links: connect assets in the same /24
    links: list[TopologyLink] = []
    for subnet, subnet_asset_list in subnet_assets.items():
        if len(subnet_asset_list) < 2:
            continue
        # Connect first asset to all others (star topology within subnet)
        hub = str(subnet_asset_list[0].id)
        for other in subnet_asset_list[1:]:
            links.append(TopologyLink(
                source=hub,
                target=str(other.id),
                link_type="subnet",
                detail=subnet,
            ))

    # Build service links: assets sharing a common well-known service port
    # Group by open port number and connect pairs
    port_to_assets: dict[int, list[str]] = {}
    for asset in assets:
        for port in (asset.ports or []):
            if port.state == "open" and port.port_number in (
                22, 80, 443, 3306, 5432, 6379, 27017, 8080, 8443
            ):
                port_to_assets.setdefault(port.port_number, []).append(str(asset.id))

    seen_pairs: set[tuple[str, str]] = set()
    for port_num, asset_ids in port_to_assets.items():
        if len(asset_ids) < 2:
            continue
        # Connect at most 10 pairs per port to keep graph readable
        for i in range(min(len(asset_ids), 10)):
            for j in range(i + 1, min(len(asset_ids), 10)):
                pair = (min(asset_ids[i], asset_ids[j]), max(asset_ids[i], asset_ids[j]))
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    links.append(TopologyLink(
                        source=asset_ids[i],
                        target=asset_ids[j],
                        link_type="service",
                        detail=str(port_num),
                    ))

    # Build subnet summary
    subnets: list[SubnetGroup] = []
    for subnet, subnet_asset_list in subnet_assets.items():
        risk_scores = [a.risk_score for a in subnet_asset_list if a.risk_score is not None]
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
        critical = sum(
            1 for a in subnet_asset_list
            if critical_counts.get(str(a.id), 0) > 0
        )
        subnets.append(SubnetGroup(
            subnet=subnet,
            asset_count=len(subnet_asset_list),
            avg_risk_score=round(avg_risk, 1),
            critical_count=critical,
        ))

    subnets.sort(key=lambda s: s.asset_count, reverse=True)

    return TopologyData(nodes=nodes, links=links, subnets=subnets)
