"""Tests for transverse features: IOC correlation, audit diff, STIX export.

These tests verify API wiring and basic logic without external dependencies.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

UNKNOWN_UUID = "00000000-0000-0000-0000-000000000000"


# ── IOC Correlation (/api/v1/threat-intel/correlations) ───────────────────────


@pytest.mark.asyncio
async def test_ioc_correlations_empty(client):
    """No IOCs in DB → empty correlation result."""
    r = await client.get("/api/v1/threat-intel/correlations")
    assert r.status_code == 200
    body = r.json()
    assert body["total_matches"] == 0
    assert body["affected_assets"] == 0
    assert body["matches"] == []


@pytest.mark.asyncio
async def test_ioc_correlations_with_severity_filter(client):
    r = await client.get("/api/v1/threat-intel/correlations?severity=critical")
    assert r.status_code == 200
    assert r.json()["total_matches"] == 0


@pytest.mark.asyncio
async def test_ioc_correlations_with_type_filter(client):
    r = await client.get("/api/v1/threat-intel/correlations?ioc_type=ip")
    assert r.status_code == 200
    assert r.json()["total_matches"] == 0


@pytest.mark.asyncio
async def test_ioc_asset_correlation_not_found(client):
    r = await client.get(f"/api/v1/threat-intel/correlations/assets/{UNKNOWN_UUID}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_ioc_asset_correlation_empty(client, create_asset):
    asset = await create_asset("10.70.1.1")
    r = await client.get(f"/api/v1/threat-intel/correlations/assets/{asset['id']}")
    assert r.status_code == 200
    body = r.json()
    assert body["asset_id"] == asset["id"]
    assert body["matches"] == []


# ── Audit Diff (/api/v1/assets/{id}/audit-diff) ──────────────────────────────


@pytest.mark.asyncio
async def test_audit_diff_needs_two_jobs(client, create_asset):
    """Audit diff requires at least 2 completed full-audit jobs."""
    asset = await create_asset("10.70.2.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/audit-diff")
    assert r.status_code == 400
    assert "at least 2" in r.json()["detail"].lower()


@pytest.mark.asyncio
async def test_audit_diff_unknown_before_job(client, create_asset):
    asset = await create_asset("10.70.2.2")
    r = await client.get(
        f"/api/v1/assets/{asset['id']}/audit-diff"
        f"?before_job_id={UNKNOWN_UUID}&after_job_id={UNKNOWN_UUID}"
    )
    assert r.status_code == 404


# ── STIX Export (/api/v1/export/stix) ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_stix_export_single_asset(client, create_asset):
    asset = await create_asset("10.70.3.1", hostname="stix-test")
    r = await client.get(f"/api/v1/export/stix/assets/{asset['id']}")
    assert r.status_code == 200
    body = r.json()
    assert body["type"] == "bundle"
    assert "objects" in body
    # Must contain at least identity + infrastructure
    types = {obj["type"] for obj in body["objects"]}
    assert "identity" in types
    assert "infrastructure" in types


@pytest.mark.asyncio
async def test_stix_export_single_asset_not_found(client):
    r = await client.get(f"/api/v1/export/stix/assets/{UNKNOWN_UUID}")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_stix_export_all_assets(client, create_asset):
    await create_asset("10.70.3.2", hostname="stix-a")
    await create_asset("10.70.3.3", hostname="stix-b")
    r = await client.get("/api/v1/export/stix/all")
    assert r.status_code == 200
    body = r.json()
    assert body["type"] == "bundle"
    # Should have at least identity + 2 infrastructure objects
    infra_objects = [o for o in body["objects"] if o["type"] == "infrastructure"]
    assert len(infra_objects) >= 2


@pytest.mark.asyncio
async def test_stix_export_content_type(client, create_asset):
    asset = await create_asset("10.70.3.4")
    r = await client.get(f"/api/v1/export/stix/assets/{asset['id']}")
    assert "stix+json" in r.headers.get("content-type", "")


@pytest.mark.asyncio
async def test_stix_export_has_download_header(client, create_asset):
    asset = await create_asset("10.70.3.5")
    r = await client.get(f"/api/v1/export/stix/assets/{asset['id']}")
    assert "attachment" in r.headers.get("content-disposition", "")


@pytest.mark.asyncio
async def test_stix_infrastructure_has_ip(client, create_asset):
    asset = await create_asset("10.70.3.6", hostname="infra-test")
    r = await client.get(f"/api/v1/export/stix/assets/{asset['id']}")
    body = r.json()
    infra = [o for o in body["objects"] if o["type"] == "infrastructure"][0]
    assert infra.get("x_netlanventory_ip") == "10.70.3.6"
