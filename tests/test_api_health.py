"""Basic API smoke tests — health, modules listing."""

import pytest


@pytest.mark.asyncio
async def test_health(client):
    r = await client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"


@pytest.mark.asyncio
async def test_modules_list(client):
    r = await client.get("/api/v1/modules")
    assert r.status_code == 200
    data = r.json()
    assert "total" in data
    assert "items" in data
    assert data["total"] >= 4
    names = [m["name"] for m in data["items"]]
    assert "arp_sweep" in names


@pytest.mark.asyncio
async def test_module_get(client):
    r = await client.get("/api/v1/modules/arp_sweep")
    assert r.status_code == 200
    m = r.json()
    assert m["name"] == "arp_sweep"
    assert m["requires_root"] is True


@pytest.mark.asyncio
async def test_module_not_found(client):
    r = await client.get("/api/v1/modules/does_not_exist")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_assets_list_empty(client):
    r = await client.get("/api/v1/assets")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 0
    assert data["items"] == []


@pytest.mark.asyncio
async def test_scans_list_empty(client):
    r = await client.get("/api/v1/scans")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 0
