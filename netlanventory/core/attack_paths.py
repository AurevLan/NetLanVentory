"""Attack Path Graph engine (innovation #1).

Builds a directed multi-edge graph of compromise relationships between
assets and finds the highest-weight bounded paths from internet-facing
entry points to "crown jewel" assets (criticality:critical).

Edge types and how their weights are computed:

  cve_exploit       — asset has an exploitable CVE; weight = CVSS * (1 + EPSS)
                      filtered to exploit_maturity in {poc, verified} or KEV
  ssh_pivot         — two assets share the same SshProfile (creds reused);
                      weight = 8.0
  network_reachable — two assets share the same /24 subnet AND target has
                      open ports; weight = 3.0
  ioc_pivot         — asset's IP/domain matches an active threat IOC;
                      weight = 7.0

Higher weight = higher attacker advantage (easier to exploit, more impact).
A "path" is a chain `entry → … → jewel` with hop count ≤ MAX_HOPS. The
total_weight of a path is the **sum** of its edge weights; we surface the
TOP-K highest-weight paths per crown jewel.

Algorithm: pure-Python depth-bounded DFS. With max_hops=4 and average
degree ≈ 5, worst case is 5^4 = 625 paths per source — tractable for any
realistic NetLanVentory deployment (≤ 10K assets) without bringing in
networkx as a dependency.

V1 simplifications (documented):
  - Subnet adjacency is inferred from /24 grouping, not from a real
    firewall reachability matrix. V2 should consume firewall exports.
  - "Internet-facing" is detected via tag membership (`internet-facing`,
    `public`) since the Asset model has no dedicated column.
  - Crown jewels are assets with `criticality == 'critical'` OR tag
    `crown-jewel`.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.asset_dns import AssetDns
from netlanventory.models.asset_tag import AssetTag
from netlanventory.models.attack_path import AttackPath
from netlanventory.models.cve import Cve
from netlanventory.models.threat_ioc import ThreatIoc

logger = get_logger(__name__)


# ── Tunables ──────────────────────────────────────────────────────────────────

MAX_HOPS = 4
TOP_K_PER_JEWEL = 10
MIN_PATH_WEIGHT = 5.0          # discard noise
WEIGHT_SSH_PIVOT = 8.0
WEIGHT_NETWORK_REACHABLE = 3.0
WEIGHT_IOC_PIVOT = 7.0
WEIGHT_CVE_FALLBACK = 4.0      # used when CVSS/EPSS is missing

ENTRY_TAGS = frozenset({"internet-facing", "public", "dmz", "edge"})
CROWN_JEWEL_TAGS = frozenset({"crown-jewel", "tier0", "production-db"})


# ── Edge type ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Edge:
    target: uuid.UUID
    edge_type: str
    weight: float
    cve_id: str | None = None
    evidence: str = ""


@dataclass(frozen=True)
class Hop:
    asset_id: str
    edge_type: str
    weight: float
    cve_id: str | None
    evidence: str

    def to_dict(self) -> dict:
        return {
            "asset_id": self.asset_id,
            "edge_type": self.edge_type,
            "weight": round(self.weight, 2),
            "cve_id": self.cve_id,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class Path:
    source: uuid.UUID
    target: uuid.UUID
    hops: tuple[Hop, ...]
    total_weight: float


# ── Pure graph builder ────────────────────────────────────────────────────────


@dataclass
class GraphData:
    """Snapshot of facts pulled from the DB. Pure data — easy to mock."""

    assets: dict[uuid.UUID, Asset]
    asset_tags: dict[uuid.UUID, frozenset[str]]
    asset_subnet: dict[uuid.UUID, str | None]            # "10.0.5.0/24" or None
    cves_by_asset: dict[uuid.UUID, list[tuple[str, float, float, str | None]]]
    # value: (cve_id, cvss, epss, kev_date_added or None)
    ssh_profile_by_asset: dict[uuid.UUID, uuid.UUID | None]
    ioc_match_assets: set[uuid.UUID]


def _ip_subnet(ip: str | None) -> str | None:
    if not ip or "." not in ip:
        return None
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def _is_entry_point(asset: Asset, tags: frozenset[str]) -> bool:
    return bool(tags & ENTRY_TAGS)


def _is_crown_jewel(asset: Asset, tags: frozenset[str]) -> bool:
    if (asset.criticality or "").lower() == "critical":
        return True
    return bool(tags & CROWN_JEWEL_TAGS)


def _cve_edge_weight(cvss: float, epss: float) -> float:
    """Higher = easier/more impactful for the attacker."""
    if cvss <= 0:
        return WEIGHT_CVE_FALLBACK
    return round(cvss * (1.0 + max(0.0, epss)), 2)


def build_adjacency(data: GraphData) -> dict[uuid.UUID, list[Edge]]:
    """Build the directed adjacency dict from a GraphData snapshot.

    Pure function, no DB. Easy to unit-test by handcrafting a GraphData.
    """
    adj: dict[uuid.UUID, list[Edge]] = defaultdict(list)

    # 1. CVE exploits — edge from any asset to any asset that has the CVE
    #    Semantically: "if I'm anywhere in the network, I can compromise this
    #    target if it has an exploitable CVE". V1 keeps it simple by adding a
    #    self-targeting edge per asset+CVE; the path enumerator combines this
    #    with adjacency edges to form chains.
    for asset_id, cves in data.cves_by_asset.items():
        for cve_id, cvss, epss, kev in cves:
            # Only consider CVEs that are realistically exploitable
            if kev is None and cvss < 6.0:
                continue
            adj[asset_id].append(
                Edge(
                    target=asset_id,  # self-edge: "this asset can be compromised here"
                    edge_type="cve_exploit",
                    weight=_cve_edge_weight(cvss, epss),
                    cve_id=cve_id,
                    evidence=f"CVE {cve_id} CVSS {cvss} EPSS {epss:.2f}"
                    + (" (KEV)" if kev else ""),
                )
            )

    # 2. SSH pivots — two assets sharing the same SshProfile
    by_profile: dict[uuid.UUID, list[uuid.UUID]] = defaultdict(list)
    for asset_id, profile_id in data.ssh_profile_by_asset.items():
        if profile_id:
            by_profile[profile_id].append(asset_id)
    for profile_id, members in by_profile.items():
        if len(members) < 2:
            continue
        for a in members:
            for b in members:
                if a == b:
                    continue
                adj[a].append(
                    Edge(
                        target=b,
                        edge_type="ssh_pivot",
                        weight=WEIGHT_SSH_PIVOT,
                        evidence=f"shared SshProfile {str(profile_id)[:8]}",
                    )
                )

    # 3. Network reachability — same /24
    by_subnet: dict[str, list[uuid.UUID]] = defaultdict(list)
    for asset_id, subnet in data.asset_subnet.items():
        if subnet:
            by_subnet[subnet].append(asset_id)
    for subnet, members in by_subnet.items():
        if len(members) < 2:
            continue
        for a in members:
            for b in members:
                if a == b:
                    continue
                adj[a].append(
                    Edge(
                        target=b,
                        edge_type="network_reachable",
                        weight=WEIGHT_NETWORK_REACHABLE,
                        evidence=f"same subnet {subnet}",
                    )
                )

    # 4. IOC pivot — assets matched by threat intel
    for asset_id in data.ioc_match_assets:
        adj[asset_id].append(
            Edge(
                target=asset_id,
                edge_type="ioc_pivot",
                weight=WEIGHT_IOC_PIVOT,
                evidence="threat IOC match (active C2/scanner)",
            )
        )

    return adj


# ── Path enumeration ──────────────────────────────────────────────────────────


def enumerate_paths(
    adjacency: dict[uuid.UUID, list[Edge]],
    source: uuid.UUID,
    *,
    max_hops: int = MAX_HOPS,
) -> list[Path]:
    """Depth-bounded DFS yielding every simple path from `source`.

    Self-loops (target == source via cve_exploit) are kept inline as
    "this asset is compromisable from itself" markers but they do NOT
    advance the hop count.
    """
    results: list[Path] = []

    def dfs(
        node: uuid.UUID,
        path_hops: list[Hop],
        visited: set[uuid.UUID],
        weight: float,
        depth: int,
    ) -> None:
        if depth >= max_hops:
            return
        for edge in adjacency.get(node, ()):
            if edge.target in visited and edge.target != node:
                continue
            hop = Hop(
                asset_id=str(edge.target),
                edge_type=edge.edge_type,
                weight=edge.weight,
                cve_id=edge.cve_id,
                evidence=edge.evidence,
            )
            new_hops = path_hops + [hop]
            new_weight = weight + edge.weight

            if edge.target == node:
                # Self-edge (CVE/IOC): does NOT advance the position, but
                # contributes weight. Record the path so far at this node.
                results.append(
                    Path(
                        source=source,
                        target=node,
                        hops=tuple(new_hops),
                        total_weight=new_weight,
                    )
                )
                continue

            results.append(
                Path(
                    source=source,
                    target=edge.target,
                    hops=tuple(new_hops),
                    total_weight=new_weight,
                )
            )
            new_visited = visited | {edge.target}
            dfs(edge.target, new_hops, new_visited, new_weight, depth + 1)

    dfs(source, [], {source}, 0.0, 0)
    return results


def select_top_paths_per_jewel(
    paths: Iterable[Path],
    jewels: set[uuid.UUID],
    *,
    top_k: int = TOP_K_PER_JEWEL,
    min_weight: float = MIN_PATH_WEIGHT,
) -> list[Path]:
    """Keep only paths ending on a crown jewel, top-K by weight per jewel."""
    by_jewel: dict[uuid.UUID, list[Path]] = defaultdict(list)
    for p in paths:
        if p.target in jewels and p.total_weight >= min_weight:
            by_jewel[p.target].append(p)
    out: list[Path] = []
    for jewel, ps in by_jewel.items():
        ps.sort(key=lambda x: x.total_weight, reverse=True)
        out.extend(ps[:top_k])
    return out


# ── DB integration ────────────────────────────────────────────────────────────


async def load_graph_data(session: AsyncSession) -> GraphData:
    """Fetch the minimum facts needed to build the adjacency graph.

    One query per fact type; everything is in-memory after this. The
    function returns a `GraphData` snapshot that downstream pure helpers
    can consume.
    """
    asset_rows = (
        await session.execute(
            select(Asset).options(selectinload(Asset.tags)).where(Asset.is_active == True)  # noqa: E712
        )
    ).scalars().all()
    assets = {a.id: a for a in asset_rows}

    asset_tags: dict[uuid.UUID, frozenset[str]] = {}
    for a in asset_rows:
        try:
            asset_tags[a.id] = frozenset((t.name or "").lower() for t in (a.tags or []))
        except Exception:
            asset_tags[a.id] = frozenset()

    asset_subnet: dict[uuid.UUID, str | None] = {a.id: _ip_subnet(a.ip) for a in asset_rows}

    # CVE edges: only consider CVEs likely exploitable (KEV or CVSS ≥ 6 or
    # exploit_maturity in {poc, verified}). The pure builder filters again,
    # so this is just a perf hint.
    cve_rows = (
        await session.execute(
            select(
                AssetCve.asset_id,
                Cve.cve_id,
                Cve.cvss_score,
                Cve.epss_score,
                Cve.kev_date_added,
                Cve.exploit_maturity,
            )
            .join(Cve, Cve.id == AssetCve.cve_id)
            .where(AssetCve.ack_status.notin_(("false_positive", "accepted")))
        )
    ).all()

    cves_by_asset: dict[uuid.UUID, list[tuple[str, float, float, str | None]]] = defaultdict(list)
    for asset_id, cve_str, cvss, epss, kev, maturity in cve_rows:
        if kev is None and (cvss or 0) < 6.0 and (maturity or "none") == "none":
            continue
        cves_by_asset[asset_id].append(
            (cve_str, float(cvss or 0.0), float(epss or 0.0), kev.isoformat() if kev else None)
        )

    ssh_profile_by_asset = {a.id: a.ssh_profile_id for a in asset_rows}

    # IOC matches by IP and DNS
    ip_set = {a.ip for a in asset_rows if a.ip}
    ioc_ip_rows = (
        await session.execute(
            select(ThreatIoc.indicator)
            .where(ThreatIoc.ioc_type == "ip", ThreatIoc.indicator.in_(ip_set))
        )
    ).scalars().all() if ip_set else []
    ioc_ips = set(ioc_ip_rows)

    dns_rows = (
        await session.execute(select(AssetDns.asset_id, AssetDns.fqdn))
    ).all()
    ioc_domain_rows = (
        await session.execute(
            select(ThreatIoc.indicator)
            .where(ThreatIoc.ioc_type == "domain")
        )
    ).scalars().all()
    ioc_domains = {d.lower() for d in ioc_domain_rows}

    ioc_match_assets: set[uuid.UUID] = set()
    for a in asset_rows:
        if a.ip and a.ip in ioc_ips:
            ioc_match_assets.add(a.id)
    for asset_id, fqdn in dns_rows:
        if fqdn and fqdn.lower() in ioc_domains:
            ioc_match_assets.add(asset_id)

    return GraphData(
        assets=assets,
        asset_tags=asset_tags,
        asset_subnet=asset_subnet,
        cves_by_asset=cves_by_asset,
        ssh_profile_by_asset=ssh_profile_by_asset,
        ioc_match_assets=ioc_match_assets,
    )


def find_entry_points(data: GraphData) -> list[uuid.UUID]:
    return [
        aid for aid, asset in data.assets.items()
        if _is_entry_point(asset, data.asset_tags.get(aid, frozenset()))
    ]


def find_crown_jewels(data: GraphData) -> set[uuid.UUID]:
    return {
        aid for aid, asset in data.assets.items()
        if _is_crown_jewel(asset, data.asset_tags.get(aid, frozenset()))
    }


def compute_paths(data: GraphData) -> list[Path]:
    """Full pipeline: build adjacency, enumerate, filter to top paths."""
    adjacency = build_adjacency(data)
    entries = find_entry_points(data)
    jewels = find_crown_jewels(data)
    if not entries or not jewels:
        logger.info(
            "attack_paths_skipped",
            entries=len(entries),
            jewels=len(jewels),
            reason="no entry points or crown jewels tagged",
        )
        return []

    raw_paths: list[Path] = []
    for entry in entries:
        raw_paths.extend(enumerate_paths(adjacency, entry))
    return select_top_paths_per_jewel(raw_paths, jewels)


async def persist_paths(session: AsyncSession, paths: list[Path]) -> int:
    """Replace `attack_paths` table contents with the given paths.

    V1 uses TRUNCATE-then-INSERT — simpler than incremental sync and the
    table never holds more than TOP_K × jewel_count rows.
    """
    await session.execute(delete(AttackPath))
    now = datetime.now(timezone.utc)
    for p in paths:
        session.add(
            AttackPath(
                source_asset_id=p.source,
                target_asset_id=p.target,
                hops=[h.to_dict() for h in p.hops],
                total_weight=round(p.total_weight, 2),
                hop_count=len(p.hops),
                computed_at=now,
            )
        )
    return len(paths)


async def refresh_attack_paths(session: AsyncSession) -> int:
    """End-to-end refresh: load → compute → persist. Returns row count."""
    data = await load_graph_data(session)
    paths = compute_paths(data)
    count = await persist_paths(session, paths)
    await session.commit()
    logger.info(
        "attack_paths_refreshed",
        assets=len(data.assets),
        entries=len(find_entry_points(data)),
        jewels=len(find_crown_jewels(data)),
        paths_persisted=count,
    )
    return count
