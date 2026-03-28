"""Smoke tests for all scan-related endpoints.

These tests verify API wiring only — no actual scans are executed.
For trigger endpoints (POST), background task runners are mocked out.
Each scanner uses a unique IP range (10.50.X.Y) to avoid conflicts.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

UNKNOWN_UUID = "00000000-0000-0000-0000-000000000000"


# ── Nuclei (/api/v1/assets/{id}/nuclei) ─────────────────────────────────────
# Mock: netlanventory.api.routers.nuclei._run_nuclei_scan


@pytest.mark.asyncio
async def test_nuclei_list_empty(client, create_asset):
    asset = await create_asset("10.50.1.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/nuclei")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_nuclei_report_not_found(client, create_asset):
    asset = await create_asset("10.50.1.2")
    r = await client.get(f"/api/v1/assets/{asset['id']}/nuclei/{UNKNOWN_UUID}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_nuclei_trigger_unknown_asset(client):
    with patch(
        "netlanventory.api.routers.nuclei._run_nuclei_scan",
        new=AsyncMock(return_value=None),
    ):
        r = await client.post(f"/api/v1/assets/{UNKNOWN_UUID}/nuclei")
    assert r.status_code in (400, 404, 422, 503)


# ── SSH Scan (/api/v1/assets/{id}/ssh-scan) ──────────────────────────────────
# No mock needed — triggers 400 without SSH credentials.


@pytest.mark.asyncio
async def test_ssh_scan_list_empty(client, create_asset):
    asset = await create_asset("10.50.2.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/ssh-scan")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_ssh_scan_report_not_found(client, create_asset):
    asset = await create_asset("10.50.2.2")
    r = await client.get(f"/api/v1/assets/{asset['id']}/ssh-scan/{UNKNOWN_UUID}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_ssh_scan_trigger_unknown_asset(client):
    r = await client.post(f"/api/v1/assets/{UNKNOWN_UUID}/ssh-scan")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_ssh_scan_trigger_no_creds(client, create_asset):
    asset = await create_asset("10.50.2.3")
    r = await client.post(f"/api/v1/assets/{asset['id']}/ssh-scan")
    assert r.status_code == 400


# ── ZAP (/api/v1/assets/{id}/zap) ───────────────────────────────────────────
# Mock: netlanventory.api.routers.zap._run_zap_scan


@pytest.mark.asyncio
async def test_zap_list_empty(client, create_asset):
    asset = await create_asset("10.50.3.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/zap")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_zap_report_not_found(client, create_asset):
    asset = await create_asset("10.50.3.2")
    r = await client.get(f"/api/v1/assets/{asset['id']}/zap/{UNKNOWN_UUID}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_zap_trigger_unknown_asset(client):
    with patch(
        "netlanventory.api.routers.zap._run_zap_scan",
        new=AsyncMock(return_value=None),
    ):
        r = await client.post(
            f"/api/v1/assets/{UNKNOWN_UUID}/zap",
            json={"target_url": "http://10.50.3.99"},
        )
    assert r.status_code == 404


# ── Trivy Docker (/api/v1/assets/{id}/trivy-docker) ─────────────────────────
# No mock needed — triggers 400 without SSH credentials / Docker.


@pytest.mark.asyncio
async def test_trivy_list_empty(client, create_asset):
    asset = await create_asset("10.50.4.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/trivy-docker")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_trivy_report_not_found(client, create_asset):
    asset = await create_asset("10.50.4.2")
    r = await client.get(f"/api/v1/assets/{asset['id']}/trivy-docker/{UNKNOWN_UUID}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_trivy_trigger_unknown_asset(client):
    r = await client.post(f"/api/v1/assets/{UNKNOWN_UUID}/trivy-docker")
    assert r.status_code in (400, 404, 422, 503)


# ── testssl (/api/v1/assets/{id}/testssl) ────────────────────────────────────
# Mock: netlanventory.api.routers.testssl._run_testssl_scan


@pytest.mark.asyncio
async def test_testssl_list_empty(client, create_asset):
    asset = await create_asset("10.50.5.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/testssl")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_testssl_report_not_found(client, create_asset):
    asset = await create_asset("10.50.5.2")
    r = await client.get(f"/api/v1/assets/{asset['id']}/testssl/{UNKNOWN_UUID}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_testssl_trigger_unknown_asset(client):
    with patch(
        "netlanventory.api.routers.testssl._run_testssl",
        new=AsyncMock(return_value=None),
    ):
        r = await client.post(f"/api/v1/assets/{UNKNOWN_UUID}/testssl")
    assert r.status_code in (400, 404, 422, 503)


# ── SSH Audit (/api/v1/assets/{id}/ssh-audit) ────────────────────────────────
# Mock: netlanventory.api.routers.ssh_audit._run_ssh_audit


@pytest.mark.asyncio
async def test_ssh_audit_list_empty(client, create_asset):
    asset = await create_asset("10.50.6.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/ssh-audit")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_ssh_audit_report_not_found(client, create_asset):
    asset = await create_asset("10.50.6.2")
    r = await client.get(f"/api/v1/assets/{asset['id']}/ssh-audit/{UNKNOWN_UUID}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_ssh_audit_trigger_unknown_asset(client):
    with patch(
        "netlanventory.api.routers.ssh_audit._run_ssh_audit",
        new=AsyncMock(return_value=None),
    ):
        r = await client.post(f"/api/v1/assets/{UNKNOWN_UUID}/ssh-audit")
    assert r.status_code in (400, 404, 422, 503)


# ── Default Creds (/api/v1/assets/{id}/default-creds) ────────────────────────
# Will 400/503 without nmap or IP/ports — no mock needed.


@pytest.mark.asyncio
async def test_default_creds_list_empty(client, create_asset):
    asset = await create_asset("10.50.7.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/default-creds")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_default_creds_report_not_found(client, create_asset):
    asset = await create_asset("10.50.7.2")
    r = await client.get(
        f"/api/v1/assets/{asset['id']}/default-creds/{UNKNOWN_UUID}"
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_default_creds_trigger_unknown_asset(client):
    r = await client.post(f"/api/v1/assets/{UNKNOWN_UUID}/default-creds")
    assert r.status_code in (400, 404, 422, 503)


# ── Headers Audit (/api/v1/assets/{id}/headers-audit) ────────────────────────
# Mock: netlanventory.api.routers.headers_audit._run_headers_audit


@pytest.mark.asyncio
async def test_headers_audit_list_empty(client, create_asset):
    asset = await create_asset("10.50.8.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/headers-audit")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_headers_audit_report_not_found(client, create_asset):
    asset = await create_asset("10.50.8.2")
    r = await client.get(
        f"/api/v1/assets/{asset['id']}/headers-audit/{UNKNOWN_UUID}"
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_headers_audit_trigger_unknown_asset(client):
    with patch(
        "netlanventory.api.routers.headers_audit._run_headers_audit",
        new=AsyncMock(return_value=None),
    ):
        r = await client.post(
            f"/api/v1/assets/{UNKNOWN_UUID}/headers-audit",
            json={"target_url": "https://10.50.8.99"},
        )
    assert r.status_code == 404


# ── SSL Scan (/api/v1/assets/{id}/ssl-scan) ──────────────────────────────────


@pytest.mark.asyncio
async def test_ssl_scan_list_empty(client, create_asset):
    asset = await create_asset("10.50.9.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/ssl-scan")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_ssl_scan_report_not_found(client, create_asset):
    asset = await create_asset("10.50.9.2")
    r = await client.get(f"/api/v1/assets/{asset['id']}/ssl-scan/{UNKNOWN_UUID}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_ssl_scan_trigger_unknown_asset(client):
    r = await client.post(f"/api/v1/assets/{UNKNOWN_UUID}/ssl-scan")
    assert r.status_code == 404


# ── Baseline (/api/v1/assets/{id}/baseline) ──────────────────────────────────


@pytest.mark.asyncio
async def test_baseline_list_empty(client, create_asset):
    asset = await create_asset("10.50.10.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/baseline")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_baseline_diff_not_found(client, create_asset):
    asset = await create_asset("10.50.10.2")
    r = await client.get(
        f"/api/v1/assets/{asset['id']}/baseline/{UNKNOWN_UUID}/diff"
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_baseline_trigger_unknown_asset(client):
    r = await client.post(f"/api/v1/assets/{UNKNOWN_UUID}/baseline")
    assert r.status_code in (400, 404, 422, 503)


# ── Full Audit (/api/v1/assets/{id}/full-audit) ─────────────────────────────
# Mock: netlanventory.api.routers.full_audit._run_full_audit


@pytest.mark.asyncio
async def test_full_audit_list_empty(client, create_asset):
    asset = await create_asset("10.50.11.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/full-audit")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_full_audit_job_not_found(client, create_asset):
    asset = await create_asset("10.50.11.2")
    r = await client.get(
        f"/api/v1/assets/{asset['id']}/full-audit/{UNKNOWN_UUID}"
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_full_audit_trigger_unknown_asset(client):
    with patch(
        "netlanventory.api.routers.full_audit._run_full_audit",
        new=AsyncMock(return_value=None),
    ):
        r = await client.post(f"/api/v1/assets/{UNKNOWN_UUID}/full-audit")
    assert r.status_code == 404


# ── Exploit Validation (/api/v1/assets/{id}/exploit-validation) ──────────────


@pytest.mark.asyncio
async def test_exploit_validation_list_empty(client, create_asset):
    asset = await create_asset("10.50.12.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/exploit-validation")
    assert r.status_code == 200
    assert r.json() == []


@pytest.mark.asyncio
async def test_exploit_validation_trigger_unknown_asset(client):
    r = await client.post(f"/api/v1/assets/{UNKNOWN_UUID}/exploit-validation")
    assert r.status_code in (400, 404, 422, 503)


# ── Scans API (/api/v1/scans) ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scans_list_empty(client):
    r = await client.get("/api/v1/scans")
    assert r.status_code == 200
    body = r.json()
    assert "items" in body
    assert "total" in body


@pytest.mark.asyncio
async def test_scans_get_not_found(client):
    r = await client.get(f"/api/v1/scans/{UNKNOWN_UUID}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_scans_create(client):
    payload = {
        "target": "10.50.13.0/24",
        "modules": ["arp_sweep"],
    }
    with patch(
        "netlanventory.api.routers.scans._run_scan",
        new=AsyncMock(return_value=None),
    ):
        r = await client.post("/api/v1/scans", json=payload)
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "pending"
    assert "id" in body


@pytest.mark.asyncio
async def test_scans_rerun_not_found(client):
    r = await client.post(f"/api/v1/scans/{UNKNOWN_UUID}/rerun")
    assert r.status_code == 404
