"""Integration tests for the Assets API endpoints."""

from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.app import APP_VERSION
from netlanventory.models.asset import Asset


@pytest.mark.asyncio
async def test_create_and_list_asset(db_session: AsyncSession):
    """An asset created in the DB should be queryable."""
    asset = Asset(
        ip="10.0.0.1",
        hostname="test-host",
        name="Test Server",
        criticality="high",
        is_active=True,
        discovery_source="manual",
    )
    db_session.add(asset)
    await db_session.flush()

    result = await db_session.execute(select(Asset).where(Asset.ip == "10.0.0.1"))
    found = result.scalar_one_or_none()
    assert found is not None
    assert found.hostname == "test-host"
    assert found.discovery_source == "manual"
    assert found.criticality == "high"


@pytest.mark.asyncio
async def test_asset_discovery_source_field(db_session: AsyncSession):
    """The discovery_source field should accept all valid values."""
    for source in ("manual", "arp_sweep", "passive", "ldap", "aws", "azure"):
        asset = Asset(
            ip=f"10.0.1.{hash(source) % 254 + 1}",
            name=f"test-{source}",
            discovery_source=source,
            is_active=True,
        )
        db_session.add(asset)

    await db_session.flush()

    result = await db_session.execute(
        select(Asset).where(Asset.discovery_source == "passive")
    )
    passive = result.scalar_one_or_none()
    assert passive is not None


@pytest.mark.asyncio
async def test_asset_risk_score_nullable(db_session: AsyncSession):
    """Risk score should be nullable for newly discovered assets."""
    asset = Asset(ip="10.0.0.99", is_active=True)
    db_session.add(asset)
    await db_session.flush()

    result = await db_session.execute(select(Asset).where(Asset.ip == "10.0.0.99"))
    found = result.scalar_one()
    assert found.risk_score is None


@pytest.mark.asyncio
async def test_health_endpoint(client):
    """The /health endpoint should return 200."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ("ok", "degraded")
    assert "version" in data
    assert data["version"] == APP_VERSION
