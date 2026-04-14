"""Tests for notification config router — CRUD + admin guard."""

from __future__ import annotations

import pytest

from tests.conftest import UNKNOWN_UUID

pytestmark = pytest.mark.asyncio

_VALID_PAYLOAD = {
    "name": "Slack alerts",
    "type": "webhook",
    "url": "https://hooks.slack.example/test",
    "enabled": True,
    "events": ["cve_critical", "scan_done"],
}


async def _create_config(client) -> dict:
    """Helper — create a notification config and return its JSON."""
    r = await client.post("/api/v1/admin/notifications", json=_VALID_PAYLOAD)
    assert r.status_code == 201
    return r.json()


# ── List ─────────────────────────────────────────────────────────────────────


async def test_list_notifications_empty(client):
    """GET /admin/notifications returns [] when none exist."""
    r = await client.get("/api/v1/admin/notifications")
    assert r.status_code == 200
    assert r.json() == []


# ── Create ───────────────────────────────────────────────────────────────────


async def test_create_notification(client):
    """POST /admin/notifications with valid body returns 201."""
    body = await _create_config(client)
    assert body["name"] == _VALID_PAYLOAD["name"]
    assert body["type"] == "webhook"
    assert body["enabled"] is True
    assert "id" in body


async def test_create_notification_invalid_event(client):
    """POST with unknown event returns 422."""
    payload = {**_VALID_PAYLOAD, "events": ["totally_unknown_event"]}
    r = await client.post("/api/v1/admin/notifications", json=payload)
    assert r.status_code == 422


# ── Update ───────────────────────────────────────────────────────────────────


async def test_update_notification(client):
    """PUT /admin/notifications/{id} updates and returns 200."""
    created = await _create_config(client)
    config_id = created["id"]
    r = await client.put(
        f"/api/v1/admin/notifications/{config_id}",
        json={"name": "Updated name"},
    )
    assert r.status_code == 200
    assert r.json()["name"] == "Updated name"


# ── Delete ───────────────────────────────────────────────────────────────────


async def test_delete_notification(client):
    """DELETE /admin/notifications/{id} returns 204."""
    created = await _create_config(client)
    config_id = created["id"]
    r = await client.delete(f"/api/v1/admin/notifications/{config_id}")
    assert r.status_code == 204


# ── Not found ────────────────────────────────────────────────────────────────


async def test_notification_not_found(client):
    """PUT unknown id returns 404."""
    r = await client.put(
        f"/api/v1/admin/notifications/{UNKNOWN_UUID}",
        json={"name": "nope"},
    )
    assert r.status_code == 404


# ── Auth guard ───────────────────────────────────────────────────────────────


async def test_notification_requires_admin(user_client):
    """Regular user GET /admin/notifications returns 403."""
    r = await user_client.get("/api/v1/admin/notifications")
    assert r.status_code == 403
