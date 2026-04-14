"""Tests for remediation, CVE acknowledgment, and SLA routers.

Covers: remediation plan, remediation stats/board, CVE ack (single + bulk),
SLA config CRUD, SLA breaches.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


# ── Remediation Plan ────────────────────────────────────────────────────────


async def test_remediation_plan_empty(client):
    """GET /api/v1/remediation-plan returns empty list when no CVEs exist."""
    r = await client.get("/api/v1/remediation-plan")
    assert r.status_code == 200
    body = r.json()
    assert body["total_groups"] == 0
    assert body["groups"] == []


async def test_remediation_plan_with_filters(client):
    """GET /api/v1/remediation-plan accepts query parameters."""
    r = await client.get(
        "/api/v1/remediation-plan",
        params={"min_score": 50, "only_kev": True, "limit": 10},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["total_groups"] == 0
    assert body["filters_applied"]["min_score"] == 50
    assert body["filters_applied"]["only_kev"] is True
    assert body["filters_applied"]["limit"] == 10


async def test_remediation_plan_source_filter(client):
    """GET /api/v1/remediation-plan with source filter returns 200."""
    r = await client.get("/api/v1/remediation-plan", params={"source": "ssh"})
    assert r.status_code == 200
    body = r.json()
    assert body["filters_applied"]["source"] == "ssh"


# ── Remediation Stats ──────────────────────────────────────────────────────


async def test_remediation_stats_empty(client):
    """GET /api/v1/remediation/stats returns zeros when no CVEs exist."""
    r = await client.get("/api/v1/remediation/stats")
    assert r.status_code == 200
    body = r.json()
    assert "funnel" in body
    assert body["mttr_hours"] == 0.0
    assert body["overdue_count"] == 0
    assert body["total"] == 0
    assert isinstance(body["assigned_breakdown"], list)
    assert len(body["assigned_breakdown"]) == 0


async def test_remediation_stats_funnel_keys(client):
    """GET /api/v1/remediation/stats funnel contains all expected statuses."""
    r = await client.get("/api/v1/remediation/stats")
    assert r.status_code == 200
    funnel = r.json()["funnel"]
    for status in ("open", "planned", "in_progress", "resolved", "blocked"):
        assert status in funnel


# ── Remediation Board ──────────────────────────────────────────────────────


async def test_remediation_board_empty(client):
    """GET /api/v1/remediation/board returns empty columns when no CVEs exist."""
    r = await client.get("/api/v1/remediation/board")
    assert r.status_code == 200
    body = r.json()
    for status in ("open", "planned", "in_progress", "resolved", "blocked"):
        assert status in body
        assert isinstance(body[status], list)
        assert len(body[status]) == 0


# ── CVE Acknowledgment ─────────────────────────────────────────────────────


async def test_ack_single_not_found(client):
    """PATCH ack on a non-existent link returns 404."""
    fake_asset = "00000000-0000-0000-0000-000000000001"
    fake_link = "00000000-0000-0000-0000-000000000002"
    r = await client.patch(
        f"/api/v1/assets/{fake_asset}/cves/{fake_link}/ack",
        json={"ack_status": "accepted"},
    )
    assert r.status_code == 404


async def test_ack_single_invalid_status(client):
    """PATCH ack with invalid ack_status returns 422."""
    fake_asset = "00000000-0000-0000-0000-000000000001"
    fake_link = "00000000-0000-0000-0000-000000000002"
    r = await client.patch(
        f"/api/v1/assets/{fake_asset}/cves/{fake_link}/ack",
        json={"ack_status": "invalid_status"},
    )
    assert r.status_code == 422


# ── Bulk Acknowledge ───────────────────────────────────────────────────────


async def test_ack_bulk_empty_list(client):
    """POST /api/v1/cves/bulk-ack with empty list returns updated=0."""
    r = await client.post(
        "/api/v1/cves/bulk-ack",
        json={"link_ids": [], "ack_status": "accepted"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["updated"] == 0


async def test_ack_bulk_invalid_status(client):
    """POST /api/v1/cves/bulk-ack with invalid status returns 422."""
    r = await client.post(
        "/api/v1/cves/bulk-ack",
        json={"link_ids": [], "ack_status": "bad_value"},
    )
    assert r.status_code == 422


async def test_ack_bulk_nonexistent_ids(client):
    """POST /api/v1/cves/bulk-ack with non-existent IDs returns updated=0."""
    r = await client.post(
        "/api/v1/cves/bulk-ack",
        json={
            "link_ids": ["00000000-0000-0000-0000-000000000099"],
            "ack_status": "accepted",
        },
    )
    assert r.status_code == 200
    assert r.json()["updated"] == 0


# ── SLA Config ─────────────────────────────────────────────────────────────


async def test_sla_config_get(client):
    """GET /api/v1/sla/config returns default config."""
    r = await client.get("/api/v1/sla/config")
    assert r.status_code == 200
    body = r.json()
    assert body["critical_days"] == 3
    assert body["high_days"] == 7
    assert body["medium_days"] == 30
    assert body["low_days"] == 90


async def test_sla_config_update(client):
    """PUT /api/v1/sla/config updates values and returns them."""
    payload = {
        "critical_days": 1,
        "high_days": 5,
        "medium_days": 14,
        "low_days": 60,
    }
    r = await client.put("/api/v1/sla/config", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["critical_days"] == 1
    assert body["high_days"] == 5
    assert body["medium_days"] == 14
    assert body["low_days"] == 60


async def test_sla_config_update_persists(client):
    """PUT then GET /api/v1/sla/config shows updated values."""
    payload = {
        "critical_days": 2,
        "high_days": 10,
        "medium_days": 21,
        "low_days": 45,
    }
    r = await client.put("/api/v1/sla/config", json=payload)
    assert r.status_code == 200

    r2 = await client.get("/api/v1/sla/config")
    assert r2.status_code == 200
    body = r2.json()
    assert body["critical_days"] == 2
    assert body["high_days"] == 10
    assert body["medium_days"] == 21
    assert body["low_days"] == 45


async def test_sla_config_update_non_admin_forbidden(user_client):
    """PUT /api/v1/sla/config as regular user returns 403."""
    payload = {"critical_days": 1, "high_days": 5, "medium_days": 14, "low_days": 60}
    r = await user_client.put("/api/v1/sla/config", json=payload)
    assert r.status_code == 403


# ── SLA Breaches ───────────────────────────────────────────────────────────


async def test_sla_breaches_empty(client):
    """GET /api/v1/sla/breaches returns empty list when no CVEs exist."""
    r = await client.get("/api/v1/sla/breaches")
    assert r.status_code == 200
    assert r.json() == []


# ── SLA Compute ────────────────────────────────────────────────────────────


async def test_sla_compute_empty(client):
    """POST /api/v1/sla/compute with no CVEs returns updated=0."""
    r = await client.post("/api/v1/sla/compute")
    assert r.status_code == 200
    assert r.json()["updated"] == 0


async def test_sla_compute_non_admin_forbidden(user_client):
    """POST /api/v1/sla/compute as regular user returns 403."""
    r = await user_client.post("/api/v1/sla/compute")
    assert r.status_code == 403
