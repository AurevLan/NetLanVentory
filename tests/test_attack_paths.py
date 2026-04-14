"""Unit tests for the Attack Path Graph engine.

Pure-function tests — no DB. Build a `GraphData` snapshot by hand and
exercise the adjacency builder, the path enumerator, and the top-K
selector. The DB integration (`load_graph_data`, `persist_paths`) is
covered separately by integration tests.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest

from netlanventory.core.attack_paths import (
    MAX_HOPS,
    MIN_PATH_WEIGHT,
    Edge,
    GraphData,
    build_adjacency,
    compute_paths,
    enumerate_paths,
    find_crown_jewels,
    find_entry_points,
    select_top_paths_per_jewel,
)


def _id() -> uuid.UUID:
    return uuid.uuid4()


def _asset(criticality="medium", ip="10.0.0.1"):
    return SimpleNamespace(criticality=criticality, ip=ip)


def _empty_graph(**overrides) -> GraphData:
    base = dict(
        assets={},
        asset_tags={},
        asset_subnet={},
        cves_by_asset={},
        ssh_profile_by_asset={},
        ioc_match_assets=set(),
    )
    base.update(overrides)
    return GraphData(**base)


# ── Adjacency builder ─────────────────────────────────────────────────────────


def test_empty_graph_yields_no_edges():
    adj = build_adjacency(_empty_graph())
    assert adj == {}


def test_cve_edge_only_above_threshold():
    a = _id()
    data = _empty_graph(
        assets={a: _asset()},
        cves_by_asset={a: [
            ("CVE-2020-1", 4.0, 0.1, None),    # below threshold (CVSS<6, no KEV) → ignored
            ("CVE-2024-2", 9.8, 0.9, None),    # included
        ]},
    )
    adj = build_adjacency(data)
    assert len(adj[a]) == 1
    edge = adj[a][0]
    assert edge.edge_type == "cve_exploit"
    assert edge.cve_id == "CVE-2024-2"
    # weight = 9.8 * (1 + 0.9) = 18.62
    assert edge.weight == pytest.approx(18.62, abs=0.01)


def test_kev_cve_included_even_with_low_cvss():
    a = _id()
    data = _empty_graph(
        assets={a: _asset()},
        cves_by_asset={a: [("CVE-2024-3", 5.5, 0.5, "2024-01-01")]},
    )
    adj = build_adjacency(data)
    assert len(adj[a]) == 1
    assert "KEV" in adj[a][0].evidence


def test_ssh_pivot_creates_bidirectional_edges():
    a, b = _id(), _id()
    profile = _id()
    data = _empty_graph(
        assets={a: _asset(), b: _asset()},
        ssh_profile_by_asset={a: profile, b: profile},
    )
    adj = build_adjacency(data)
    targets_from_a = [e.target for e in adj[a]]
    targets_from_b = [e.target for e in adj[b]]
    assert b in targets_from_a
    assert a in targets_from_b
    assert all(e.edge_type == "ssh_pivot" for e in adj[a])
    assert adj[a][0].weight == 8.0


def test_lone_ssh_profile_creates_no_edge():
    """A profile assigned to a single asset doesn't enable pivot."""
    a = _id()
    profile = _id()
    data = _empty_graph(
        assets={a: _asset()},
        ssh_profile_by_asset={a: profile},
    )
    adj = build_adjacency(data)
    assert adj == {}


def test_network_reachable_uses_subnet_grouping():
    a, b, c = _id(), _id(), _id()
    data = _empty_graph(
        assets={a: _asset(), b: _asset(), c: _asset()},
        asset_subnet={
            a: "10.0.5.0/24",
            b: "10.0.5.0/24",
            c: "192.168.1.0/24",  # different subnet
        },
    )
    adj = build_adjacency(data)
    # a ↔ b connected, c isolated
    assert any(e.target == b for e in adj[a])
    assert all(e.target != c for e in adj[a])


def test_ioc_pivot_creates_self_edge():
    a = _id()
    data = _empty_graph(
        assets={a: _asset()},
        ioc_match_assets={a},
    )
    adj = build_adjacency(data)
    assert any(e.edge_type == "ioc_pivot" and e.target == a for e in adj[a])
    assert adj[a][0].weight == 7.0


# ── Entry points and crown jewels ─────────────────────────────────────────────


def test_entry_point_detection_via_tag():
    a, b = _id(), _id()
    data = _empty_graph(
        assets={a: _asset(), b: _asset()},
        asset_tags={a: frozenset({"internet-facing"}), b: frozenset()},
    )
    entries = find_entry_points(data)
    assert a in entries
    assert b not in entries


def test_crown_jewel_detection_via_criticality():
    a, b = _id(), _id()
    data = _empty_graph(
        assets={a: _asset(criticality="critical"), b: _asset(criticality="medium")},
        asset_tags={a: frozenset(), b: frozenset()},
    )
    jewels = find_crown_jewels(data)
    assert a in jewels
    assert b not in jewels


def test_crown_jewel_detection_via_tag():
    a = _id()
    data = _empty_graph(
        assets={a: _asset(criticality="medium")},
        asset_tags={a: frozenset({"crown-jewel"})},
    )
    assert a in find_crown_jewels(data)


# ── Path enumeration ──────────────────────────────────────────────────────────


def test_enumerate_paths_respects_max_hops():
    """A linear chain longer than MAX_HOPS gets truncated."""
    nodes = [_id() for _ in range(6)]
    adj = {
        nodes[i]: [Edge(target=nodes[i + 1], edge_type="ssh_pivot", weight=8.0)]
        for i in range(5)
    }
    paths = enumerate_paths(adj, nodes[0], max_hops=4)
    # Should reach at most node[4] (4 hops from node[0])
    deepest_targets = {p.target for p in paths if p.hops}
    assert nodes[5] not in deepest_targets


def test_enumerate_paths_no_cycles():
    a, b = _id(), _id()
    adj = {
        a: [Edge(target=b, edge_type="ssh_pivot", weight=8.0)],
        b: [Edge(target=a, edge_type="ssh_pivot", weight=8.0)],
    }
    paths = enumerate_paths(adj, a)
    # We must not bounce a→b→a→b…
    for p in paths:
        seen = [p.source] + [uuid.UUID(h.asset_id) for h in p.hops]
        # Allow self-loops (CVE/IOC) but no real revisits
        non_self = [n for i, n in enumerate(seen) if i == 0 or n != seen[i - 1]]
        assert len(set(non_self)) == len(non_self) or all(
            uuid.UUID(p.hops[i].asset_id) == seen[i] for i in range(len(p.hops))
        )


def test_self_loop_does_not_advance_position():
    """A CVE self-edge contributes weight but keeps `target` at the asset."""
    a = _id()
    adj = {
        a: [
            Edge(target=a, edge_type="cve_exploit", weight=10.0, cve_id="CVE-1"),
        ]
    }
    paths = enumerate_paths(adj, a)
    assert len(paths) == 1
    assert paths[0].target == a
    assert paths[0].total_weight == 10.0


# ── Top-K selection ───────────────────────────────────────────────────────────


def test_top_k_per_jewel_filters_min_weight():
    a, jewel = _id(), _id()
    paths_in = [
        SimpleNamespace(source=a, target=jewel, hops=(), total_weight=2.0),   # below MIN
        SimpleNamespace(source=a, target=jewel, hops=(), total_weight=10.0),  # kept
    ]
    out = select_top_paths_per_jewel(paths_in, jewels={jewel}, top_k=10, min_weight=MIN_PATH_WEIGHT)
    assert len(out) == 1
    assert out[0].total_weight == 10.0


def test_top_k_per_jewel_caps_count():
    jewel = _id()
    paths_in = [
        SimpleNamespace(source=_id(), target=jewel, hops=(), total_weight=float(i + 10))
        for i in range(20)
    ]
    out = select_top_paths_per_jewel(paths_in, jewels={jewel}, top_k=5)
    assert len(out) == 5
    # Top 5 by weight desc: 29, 28, 27, 26, 25
    assert [p.total_weight for p in out] == [29.0, 28.0, 27.0, 26.0, 25.0]


# ── End-to-end pure pipeline ──────────────────────────────────────────────────


def test_compute_paths_finds_real_chain():
    """edge → pivot → jewel must be detected end-to-end."""
    edge_asset = _id()      # internet-facing entry
    pivot_asset = _id()     # middle host with shared SSH
    jewel = _id()           # critical
    profile = _id()

    data = _empty_graph(
        assets={
            edge_asset: _asset(criticality="medium"),
            pivot_asset: _asset(criticality="medium"),
            jewel: _asset(criticality="critical"),
        },
        asset_tags={
            edge_asset: frozenset({"internet-facing"}),
            pivot_asset: frozenset(),
            jewel: frozenset(),
        },
        # CVE on the edge — entry foothold
        cves_by_asset={
            edge_asset: [("CVE-2024-X", 9.8, 0.95, None)],
        },
        # SSH pivot connects edge ↔ pivot ↔ jewel via shared profile
        ssh_profile_by_asset={
            edge_asset: profile,
            pivot_asset: profile,
            jewel: profile,
        },
    )

    paths = compute_paths(data)
    targets = {p.target for p in paths}
    assert jewel in targets
    # Path weight should be > MIN_PATH_WEIGHT
    jewel_paths = [p for p in paths if p.target == jewel]
    assert all(p.total_weight >= MIN_PATH_WEIGHT for p in jewel_paths)


def test_compute_paths_returns_empty_without_jewels():
    """No crown jewel ⇒ no paths surfaced even if entries exist."""
    a = _id()
    data = _empty_graph(
        assets={a: _asset()},
        asset_tags={a: frozenset({"internet-facing"})},
    )
    assert compute_paths(data) == []


def test_compute_paths_returns_empty_without_entries():
    """No internet-facing tag ⇒ no chains start anywhere."""
    a = _id()
    data = _empty_graph(
        assets={a: _asset(criticality="critical")},
        asset_tags={a: frozenset()},
    )
    assert compute_paths(data) == []
