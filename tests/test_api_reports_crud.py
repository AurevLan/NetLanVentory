"""Tests for reports and scheduled-reports routers."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio

# ── Executive reports ────────────────────────────────────────────────────────


async def test_executive_report_json(client):
    """GET /reports/executive/data returns 200 with JSON data."""
    r = await client.get("/api/v1/reports/executive/data")
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body, dict)


async def test_executive_report_html(client):
    """GET /reports/executive returns 200 with HTML content."""
    r = await client.get("/api/v1/reports/executive")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")


# ── Scheduled reports ────────────────────────────────────────────────────────

_SCHED_PAYLOAD = {
    "name": "Weekly exec report",
    "report_type": "executive",
    "schedule": "weekly",
    "recipients": ["admin@test.local"],
    "enabled": True,
}


async def _create_scheduled(client) -> dict:
    r = await client.post("/api/v1/scheduled-reports", json=_SCHED_PAYLOAD)
    assert r.status_code == 201
    return r.json()


async def test_scheduled_reports_list_empty(client):
    """GET /scheduled-reports returns empty list."""
    r = await client.get("/api/v1/scheduled-reports")
    assert r.status_code == 200
    assert r.json() == []


async def test_create_scheduled_report(client):
    """POST /scheduled-reports returns 201 with report data."""
    body = await _create_scheduled(client)
    assert body["name"] == _SCHED_PAYLOAD["name"]
    assert body["report_type"] == "executive"
    assert body["schedule"] == "weekly"
    assert "id" in body


async def test_delete_scheduled_report(client):
    """DELETE /scheduled-reports/{id} returns 204."""
    created = await _create_scheduled(client)
    report_id = created["id"]
    r = await client.delete(f"/api/v1/scheduled-reports/{report_id}")
    assert r.status_code == 204
