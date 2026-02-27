"""CRUD tests for the Assets API."""

import pytest


@pytest.mark.asyncio
async def test_create_and_get_asset(client):
    # Create
    r = await client.post("/api/v1/assets", json={"ip": "10.0.0.1", "hostname": "router"})
    assert r.status_code == 201
    asset = r.json()
    assert asset["ip"] == "10.0.0.1"
    assert asset["hostname"] == "router"
    asset_id = asset["id"]

    # Retrieve by ID
    r2 = await client.get(f"/api/v1/assets/{asset_id}")
    assert r2.status_code == 200
    assert r2.json()["id"] == asset_id


@pytest.mark.asyncio
async def test_get_asset_by_ip(client):
    await client.post("/api/v1/assets", json={"ip": "10.0.0.2"})
    r = await client.get("/api/v1/assets/by-ip/10.0.0.2")
    assert r.status_code == 200
    assert r.json()["ip"] == "10.0.0.2"


@pytest.mark.asyncio
async def test_update_asset(client):
    r = await client.post("/api/v1/assets", json={"ip": "10.0.0.3"})
    asset_id = r.json()["id"]

    r2 = await client.patch(f"/api/v1/assets/{asset_id}", json={"vendor": "Cisco"})
    assert r2.status_code == 200
    assert r2.json()["vendor"] == "Cisco"


@pytest.mark.asyncio
async def test_delete_asset(client):
    r = await client.post("/api/v1/assets", json={"ip": "10.0.0.99"})
    asset_id = r.json()["id"]

    r2 = await client.delete(f"/api/v1/assets/{asset_id}")
    assert r2.status_code == 204

    r3 = await client.get(f"/api/v1/assets/{asset_id}")
    assert r3.status_code == 404


@pytest.mark.asyncio
async def test_asset_not_found(client):
    r = await client.get("/api/v1/assets/00000000-0000-0000-0000-000000000000")
    assert r.status_code == 404
