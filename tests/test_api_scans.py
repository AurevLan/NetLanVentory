"""Tests for the Scans API — create, list, validate."""

from unittest.mock import AsyncMock, patch

import pytest


# Patch _run_scan so tests don't try to open a real PostgreSQL connection
_PATCH = "netlanventory.api.routers.scans._run_scan"


@pytest.mark.asyncio
async def test_create_scan_unknown_module(client):
    r = await client.post(
        "/api/v1/scans",
        json={"target": "192.168.1.0/24", "modules": ["does_not_exist"]},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_create_scan_accepted(client):
    """Creating a scan returns 202 Accepted (runs in background)."""
    with patch(_PATCH, new_callable=AsyncMock):
        r = await client.post(
            "/api/v1/scans",
            json={"target": "192.168.1.0/24", "modules": ["arp_sweep"]},
        )
    assert r.status_code == 202
    data = r.json()
    assert data["target"] == "192.168.1.0/24"
    assert data["status"] in ("pending", "running")
    assert "id" in data


@pytest.mark.asyncio
async def test_get_scan(client):
    with patch(_PATCH, new_callable=AsyncMock):
        r = await client.post(
            "/api/v1/scans",
            json={"target": "10.0.0.0/8", "modules": ["arp_sweep"]},
        )
    scan_id = r.json()["id"]

    r2 = await client.get(f"/api/v1/scans/{scan_id}")
    assert r2.status_code == 200
    assert r2.json()["id"] == scan_id


@pytest.mark.asyncio
async def test_scan_not_found(client):
    r = await client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_delete_scan(client):
    with patch(_PATCH, new_callable=AsyncMock):
        r = await client.post(
            "/api/v1/scans",
            json={"target": "172.16.0.0/12", "modules": ["arp_sweep"]},
        )
    scan_id = r.json()["id"]
    r2 = await client.delete(f"/api/v1/scans/{scan_id}")
    assert r2.status_code == 204
