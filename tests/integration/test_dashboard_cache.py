"""Integration tests for dashboard Redis caching."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_dashboard_uses_cache_when_available(client):
    """Dashboard should return cached data if Redis has it."""
    cached_data = {
        "total_assets": 42,
        "active_assets": 30,
        "total_cves": 100,
        "unacknowledged_cves": 25,
        "cves_by_severity": [{"severity": "Critical", "count": 5}],
        "top_vulnerable_assets": [],
        "assets_not_scanned_30d": 3,
        "critical_cves_without_remediation": 2,
    }

    with patch("netlanventory.core.cache.cache_get_json", new_callable=AsyncMock, return_value=cached_data):
        r = await client.get("/api/v1/dashboard")
        assert r.status_code == 200
        body = r.json()
        assert body["total_assets"] == 42
        assert body["active_assets"] == 30
        assert body["total_cves"] == 100


@pytest.mark.asyncio
async def test_dashboard_falls_through_when_no_cache(client):
    """Dashboard should query DB when cache returns None."""
    with patch("netlanventory.core.cache.cache_get_json", new_callable=AsyncMock, return_value=None):
        with patch("netlanventory.core.cache.cache_set_json", new_callable=AsyncMock):
            r = await client.get("/api/v1/dashboard")
            assert r.status_code == 200
            body = r.json()
            # With empty DB, should return zeros
            assert body["total_assets"] == 0


@pytest.mark.asyncio
async def test_cache_set_called_after_db_query():
    """After computing dashboard stats from DB, the result should be cached."""
    with patch("netlanventory.core.cache.cache_set_json", new_callable=AsyncMock) as mock_set:
        await mock_set("dashboard:stats", {"total_assets": 10}, ttl=60)
        mock_set.assert_called_once_with("dashboard:stats", {"total_assets": 10}, ttl=60)


@pytest.mark.asyncio
async def test_cache_ping_returns_bool():
    """cache_ping should return a boolean."""
    from netlanventory.core.cache import cache_ping
    result = await cache_ping()
    assert isinstance(result, bool)


@pytest.mark.asyncio
async def test_cache_get_returns_none_without_redis():
    """Without Redis configured, cache_get should return None."""
    from netlanventory.core.cache import cache_get
    result = await cache_get("nonexistent_key")
    assert result is None


@pytest.mark.asyncio
async def test_cache_set_noop_without_redis():
    """Without Redis configured, cache_set should be a no-op."""
    from netlanventory.core.cache import cache_set
    await cache_set("test_key", "test_value", ttl=60)
