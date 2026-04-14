"""Tests for the security posture radar endpoint.

Covers: GET /assets/{asset_id}/security-posture
"""

from __future__ import annotations

import pytest

UNKNOWN_UUID = "00000000-0000-0000-0000-000000000000"
EXPECTED_DOMAINS = {"network", "vulnerabilities", "crypto", "system", "access", "threat_intel"}


@pytest.mark.asyncio
async def test_security_posture_asset_not_found(client):
    """GET /assets/{unknown}/security-posture returns 404."""
    r = await client.get(f"/api/v1/assets/{UNKNOWN_UUID}/security-posture")
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_security_posture_empty_asset(client, create_asset):
    """Fresh asset must return 6 domain scores."""
    asset = await create_asset("10.90.0.1")
    r = await client.get(f"/api/v1/assets/{asset['id']}/security-posture")
    assert r.status_code == 200
    d = r.json()
    assert len(d["domains"]) == 6
    for domain in d["domains"]:
        assert "score" in domain
        assert isinstance(domain["score"], int)


@pytest.mark.asyncio
async def test_security_posture_overall_score_range(client, create_asset):
    """overall_score must be between 0 and 100."""
    asset = await create_asset("10.90.0.2")
    r = await client.get(f"/api/v1/assets/{asset['id']}/security-posture")
    assert r.status_code == 200
    d = r.json()
    assert 0 <= d["overall_score"] <= 100


@pytest.mark.asyncio
async def test_security_posture_domain_names(client, create_asset):
    """Domain names must be network, vulnerabilities, crypto, system, access, threat_intel."""
    asset = await create_asset("10.90.0.3")
    r = await client.get(f"/api/v1/assets/{asset['id']}/security-posture")
    assert r.status_code == 200
    d = r.json()
    returned_domains = {dom["domain"] for dom in d["domains"]}
    assert returned_domains == EXPECTED_DOMAINS


@pytest.mark.asyncio
async def test_security_posture_has_labels(client, create_asset):
    """Each domain must have label and detail fields."""
    asset = await create_asset("10.90.0.4")
    r = await client.get(f"/api/v1/assets/{asset['id']}/security-posture")
    assert r.status_code == 200
    for domain in r.json()["domains"]:
        assert "label" in domain and isinstance(domain["label"], str)
        assert "detail" in domain and isinstance(domain["detail"], str)


@pytest.mark.asyncio
async def test_security_posture_clean_asset_high_score(client, create_asset):
    """Asset with no CVEs or issues should have high scores (>= 50 each)."""
    asset = await create_asset("10.90.0.5")
    r = await client.get(f"/api/v1/assets/{asset['id']}/security-posture")
    assert r.status_code == 200
    d = r.json()
    for domain in d["domains"]:
        assert domain["score"] >= 50, (
            f"Domain '{domain['domain']}' score {domain['score']} is below 50 for a clean asset"
        )
    assert d["overall_score"] >= 50


@pytest.mark.asyncio
async def test_security_posture_requires_auth(anon_client, create_asset):
    """Unauthenticated request must return 401 or 403."""
    # Use a fake UUID — auth check should happen before DB lookup
    r = await anon_client.get(f"/api/v1/assets/{UNKNOWN_UUID}/security-posture")
    assert r.status_code in (401, 403)
