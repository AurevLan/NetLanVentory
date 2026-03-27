"""API smoke tests for the new security feature endpoints (v0.7.0).

These tests verify endpoint wiring, auth enforcement, and 404/400 handling.
They do NOT test actual scan execution (requires SSH/ZAP/msfrpcd — external deps).
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _create_asset(client, ip: str = "192.168.1.1") -> str:
    r = await client.post("/api/v1/assets", json={"ip": ip})
    assert r.status_code == 201
    return r.json()["id"]


UNKNOWN_ID = str(uuid.uuid4())


# ── Priority Matrix ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_priority_matrix_unknown_asset(client):
    r = await client.get(f"/api/v1/assets/{UNKNOWN_ID}/priority-matrix")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_priority_matrix_empty_asset(client):
    asset_id = await _create_asset(client, "10.10.0.1")
    r = await client.get(f"/api/v1/assets/{asset_id}/priority-matrix")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 0
    assert data["P1"] == []
    assert data["P2"] == []
    assert data["P3"] == []
    assert data["P4"] == []
    assert data["asset_id"] == asset_id


# ── Hardening Scan ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_hardening_scan_unknown_asset(client):
    r = await client.post(f"/api/v1/assets/{UNKNOWN_ID}/hardening-scan")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_hardening_scan_no_ssh_creds(client):
    asset_id = await _create_asset(client, "10.10.0.2")
    r = await client.post(f"/api/v1/assets/{asset_id}/hardening-scan")
    assert r.status_code == 400
    assert "SSH" in r.json()["detail"] or "ssh" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_hardening_scan_list_empty(client):
    asset_id = await _create_asset(client, "10.10.0.3")
    r = await client.get(f"/api/v1/assets/{asset_id}/hardening-scan")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_hardening_scan_report_not_found(client):
    asset_id = await _create_asset(client, "10.10.0.4")
    r = await client.get(f"/api/v1/assets/{asset_id}/hardening-scan/{UNKNOWN_ID}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_hardening_scan_asset_no_ip(client):
    # Asset with no IP should return 400
    r = await client.post("/api/v1/assets", json={"hostname": "myhost"})
    assert r.status_code == 201
    asset_id = r.json()["id"]
    r2 = await client.post(f"/api/v1/assets/{asset_id}/hardening-scan")
    assert r2.status_code == 400


# ── Lynis Scan ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_lynis_scan_unknown_asset(client):
    r = await client.post(f"/api/v1/assets/{UNKNOWN_ID}/lynis-scan")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_lynis_scan_no_ssh_creds(client):
    asset_id = await _create_asset(client, "10.10.0.5")
    r = await client.post(f"/api/v1/assets/{asset_id}/lynis-scan")
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_lynis_scan_list_empty(client):
    asset_id = await _create_asset(client, "10.10.0.6")
    r = await client.get(f"/api/v1/assets/{asset_id}/lynis-scan")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_lynis_scan_report_not_found(client):
    asset_id = await _create_asset(client, "10.10.0.7")
    r = await client.get(f"/api/v1/assets/{asset_id}/lynis-scan/{UNKNOWN_ID}")
    assert r.status_code == 404


# ── Hardening vs Lynis report isolation ───────────────────────────────────────

@pytest.mark.asyncio
async def test_hardening_and_lynis_lists_are_independent(client):
    """GET /hardening-scan and GET /lynis-scan must return disjoint sets."""
    asset_id = await _create_asset(client, "10.10.0.8")
    r_hard = await client.get(f"/api/v1/assets/{asset_id}/hardening-scan")
    r_lynis = await client.get(f"/api/v1/assets/{asset_id}/lynis-scan")
    assert r_hard.status_code == 200
    assert r_lynis.status_code == 200
    # Both empty → no overlap possible
    hard_ids = {x["id"] for x in r_hard.json()}
    lynis_ids = {x["id"] for x in r_lynis.json()}
    assert hard_ids.isdisjoint(lynis_ids)


# ── HTTP Headers Audit ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_headers_audit_unknown_asset(client):
    r = await client.post(
        f"/api/v1/assets/{UNKNOWN_ID}/headers-audit",
        json={"target_url": "http://192.168.1.1"},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_headers_audit_list_empty(client):
    asset_id = await _create_asset(client, "10.10.0.9")
    r = await client.get(f"/api/v1/assets/{asset_id}/headers-audit")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_headers_audit_report_not_found(client):
    asset_id = await _create_asset(client, "10.10.0.10")
    r = await client.get(f"/api/v1/assets/{asset_id}/headers-audit/{UNKNOWN_ID}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_headers_audit_trigger_returns_202(client):
    asset_id = await _create_asset(client, "10.10.0.11")
    # Mock the background task to avoid it trying to open a production DB session
    # (background tasks use get_session_factory() directly, bypassing the test override).
    with patch(
        "netlanventory.api.routers.headers_audit._run_headers_audit",
        new=AsyncMock(return_value=None),
    ):
        r = await client.post(
            f"/api/v1/assets/{asset_id}/headers-audit",
            json={"target_url": "http://10.10.0.11"},
        )
    assert r.status_code == 202
    data = r.json()
    assert "report_id" in data


# ── Metasploit Validation ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_msf_validate_unknown_asset(client):
    r = await client.post(f"/api/v1/assets/{UNKNOWN_ID}/metasploit-validate")
    # 503 when MSFRPC_PASS not configured (guard fires before asset lookup)
    # 404 when MSFRPC_PASS is set but asset doesn't exist
    assert r.status_code in (404, 503)


@pytest.mark.asyncio
async def test_msf_validate_list_empty(client):
    asset_id = await _create_asset(client, "10.10.0.12")
    r = await client.get(f"/api/v1/assets/{asset_id}/metasploit-validate")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_msf_validate_report_not_found(client):
    asset_id = await _create_asset(client, "10.10.0.13")
    r = await client.get(f"/api/v1/assets/{asset_id}/metasploit-validate/{UNKNOWN_ID}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_msf_validate_no_eligible_cves(client):
    """Asset with no CVEs should fail gracefully."""
    asset_id = await _create_asset(client, "10.10.0.14")
    r = await client.post(f"/api/v1/assets/{asset_id}/metasploit-validate")
    # 503 when MSFRPC_PASS not configured; 400 when configured but no CVEs
    assert r.status_code in (400, 503)
