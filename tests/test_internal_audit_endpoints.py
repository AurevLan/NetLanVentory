"""Smoke tests for internal audit endpoints (SSH-based).

These tests verify API wiring only — no actual SSH connections are made.
Background task runners are mocked out for trigger (POST) endpoints.
Each audit type uses a unique IP range (10.60.X.Y) to avoid conflicts.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

UNKNOWN_UUID = "00000000-0000-0000-0000-000000000000"


# ── Privesc Audit (/api/v1/assets/{id}/privesc-audit) ────────────────────────
# Requires SSH creds → 400 without them.


@pytest.mark.asyncio
async def test_privesc_list_empty(client, create_asset):
    asset = await create_asset("10.60.1.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/privesc-audit")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_privesc_report_not_found(client, create_asset):
    asset = await create_asset("10.60.1.2")
    r = await client.get(f"/api/v1/assets/{asset['id']}/privesc-audit/{UNKNOWN_UUID}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_privesc_trigger_unknown_asset(client):
    with patch(
        "netlanventory.api.routers.privesc_audit._run_privesc_audit",
        new=AsyncMock(return_value=None),
    ):
        r = await client.post(f"/api/v1/assets/{UNKNOWN_UUID}/privesc-audit")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_privesc_trigger_no_creds(client, create_asset):
    asset = await create_asset("10.60.1.3")
    r = await client.post(f"/api/v1/assets/{asset['id']}/privesc-audit")
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_privesc_trigger_no_ip(client):
    r = await client.post("/api/v1/assets", json={"mac": "AA:BB:CC:DD:EE:01"})
    assert r.status_code == 201
    asset_id = r.json()["id"]
    r2 = await client.post(f"/api/v1/assets/{asset_id}/privesc-audit")
    assert r2.status_code == 400


# ── Firewall Audit (/api/v1/assets/{id}/firewall-audit) ──────────────────────


@pytest.mark.asyncio
async def test_firewall_list_empty(client, create_asset):
    asset = await create_asset("10.60.2.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/firewall-audit")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_firewall_report_not_found(client, create_asset):
    asset = await create_asset("10.60.2.2")
    r = await client.get(f"/api/v1/assets/{asset['id']}/firewall-audit/{UNKNOWN_UUID}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_firewall_trigger_unknown_asset(client):
    with patch(
        "netlanventory.api.routers.firewall_audit._run_firewall_audit",
        new=AsyncMock(return_value=None),
    ):
        r = await client.post(f"/api/v1/assets/{UNKNOWN_UUID}/firewall-audit")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_firewall_trigger_no_creds(client, create_asset):
    asset = await create_asset("10.60.2.3")
    r = await client.post(f"/api/v1/assets/{asset['id']}/firewall-audit")
    assert r.status_code == 400


# ── Rootkit Audit (/api/v1/assets/{id}/rootkit-audit) ─────────────────────────


@pytest.mark.asyncio
async def test_rootkit_list_empty(client, create_asset):
    asset = await create_asset("10.60.3.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/rootkit-audit")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_rootkit_report_not_found(client, create_asset):
    asset = await create_asset("10.60.3.2")
    r = await client.get(f"/api/v1/assets/{asset['id']}/rootkit-audit/{UNKNOWN_UUID}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_rootkit_trigger_unknown_asset(client):
    with patch(
        "netlanventory.api.routers.rootkit_audit._run_rootkit_audit",
        new=AsyncMock(return_value=None),
    ):
        r = await client.post(f"/api/v1/assets/{UNKNOWN_UUID}/rootkit-audit")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_rootkit_trigger_no_creds(client, create_asset):
    asset = await create_asset("10.60.3.3")
    r = await client.post(f"/api/v1/assets/{asset['id']}/rootkit-audit")
    assert r.status_code == 400


# ── Docker Bench (/api/v1/assets/{id}/docker-bench) ──────────────────────────


@pytest.mark.asyncio
async def test_docker_bench_list_empty(client, create_asset):
    asset = await create_asset("10.60.4.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/docker-bench")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_docker_bench_report_not_found(client, create_asset):
    asset = await create_asset("10.60.4.2")
    r = await client.get(f"/api/v1/assets/{asset['id']}/docker-bench/{UNKNOWN_UUID}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_docker_bench_trigger_unknown_asset(client):
    with patch(
        "netlanventory.api.routers.docker_bench_audit._run_docker_bench",
        new=AsyncMock(return_value=None),
    ):
        r = await client.post(f"/api/v1/assets/{UNKNOWN_UUID}/docker-bench")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_docker_bench_trigger_no_creds(client, create_asset):
    asset = await create_asset("10.60.4.3")
    r = await client.post(f"/api/v1/assets/{asset['id']}/docker-bench")
    assert r.status_code == 400


# ── Auth Log Audit (/api/v1/assets/{id}/auth-log-audit) ──────────────────────


@pytest.mark.asyncio
async def test_auth_log_list_empty(client, create_asset):
    asset = await create_asset("10.60.5.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/auth-log-audit")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_auth_log_report_not_found(client, create_asset):
    asset = await create_asset("10.60.5.2")
    r = await client.get(f"/api/v1/assets/{asset['id']}/auth-log-audit/{UNKNOWN_UUID}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_auth_log_trigger_unknown_asset(client):
    with patch(
        "netlanventory.api.routers.auth_log_audit._run_auth_log_audit",
        new=AsyncMock(return_value=None),
    ):
        r = await client.post(f"/api/v1/assets/{UNKNOWN_UUID}/auth-log-audit")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_auth_log_trigger_no_creds(client, create_asset):
    asset = await create_asset("10.60.5.3")
    r = await client.post(f"/api/v1/assets/{asset['id']}/auth-log-audit")
    assert r.status_code == 400
