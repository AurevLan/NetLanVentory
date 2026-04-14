"""Tests for threat intelligence router — IOC listing, feed refresh, asset IOCs."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch

from tests.conftest import UNKNOWN_UUID

pytestmark = pytest.mark.asyncio


# ── IOC listing ──────────────────────────────────────────────────────────────


async def test_list_iocs_empty(client):
    """GET /threat-intel/iocs returns empty list when no IOCs exist."""
    r = await client.get("/api/v1/threat-intel/iocs")
    assert r.status_code == 200
    assert r.json() == []


async def test_list_iocs_with_type_filter(client):
    """GET /threat-intel/iocs?ioc_type=ip returns empty list."""
    r = await client.get("/api/v1/threat-intel/iocs", params={"ioc_type": "ip"})
    assert r.status_code == 200
    assert r.json() == []


async def test_list_iocs_with_severity_filter(client):
    """GET /threat-intel/iocs?severity=critical returns empty list."""
    r = await client.get("/api/v1/threat-intel/iocs", params={"severity": "critical"})
    assert r.status_code == 200
    assert r.json() == []


# ── Feed refresh ─────────────────────────────────────────────────────────────


async def test_refresh_feeds(client):
    """POST /threat-intel/refresh returns 200 with result shape."""
    r = await client.post("/api/v1/threat-intel/refresh")
    assert r.status_code == 200
    body = r.json()
    assert "otx_count" in body
    assert "abusech_count" in body
    assert "errors" in body
    assert isinstance(body["errors"], list)


# ── Asset IOCs ───────────────────────────────────────────────────────────────


async def test_asset_iocs_not_found(client):
    """GET /threat-intel/asset/{unknown}/iocs returns 404."""
    r = await client.get(f"/api/v1/threat-intel/asset/{UNKNOWN_UUID}/iocs")
    assert r.status_code == 404


async def test_asset_iocs_empty(client, create_asset):
    """GET /threat-intel/asset/{id}/iocs returns empty IOC list for valid asset."""
    asset = await create_asset("192.168.99.1")
    asset_id = asset["id"]
    with patch(
        "netlanventory.api.routers.threat_intel.check_asset_against_iocs",
        new_callable=AsyncMock,
        return_value=[],
    ):
        r = await client.get(f"/api/v1/threat-intel/asset/{asset_id}/iocs")
    assert r.status_code == 200
    body = r.json()
    assert body["asset_id"] == asset_id
    assert body["iocs"] == []
