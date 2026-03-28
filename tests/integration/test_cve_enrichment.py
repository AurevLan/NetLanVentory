"""Integration tests for CVE enrichment and MITRE mapping."""

from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import AsyncMock, patch, MagicMock

from netlanventory.models.cve import Cve


@pytest.mark.asyncio
async def test_cve_mitre_techniques_field(db_session: AsyncSession):
    """The mitre_techniques JSONB field should store a list of dicts."""
    cve = Cve(
        cve_id="CVE-2024-9999",
        severity="Critical",
        cvss_score=9.8,
        mitre_techniques=[
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
            }
        ],
    )
    db_session.add(cve)
    await db_session.flush()

    result = await db_session.execute(
        select(Cve).where(Cve.cve_id == "CVE-2024-9999")
    )
    found = result.scalar_one()
    assert found.mitre_techniques is not None
    assert len(found.mitre_techniques) == 1
    assert found.mitre_techniques[0]["technique_id"] == "T1190"


@pytest.mark.asyncio
async def test_cve_without_mitre(db_session: AsyncSession):
    """CVEs without MITRE data should have mitre_techniques as None."""
    cve = Cve(
        cve_id="CVE-2024-0001",
        severity="Low",
        cvss_score=2.0,
    )
    db_session.add(cve)
    await db_session.flush()

    result = await db_session.execute(
        select(Cve).where(Cve.cve_id == "CVE-2024-0001")
    )
    found = result.scalar_one()
    # Default is [] (empty list) or None depending on model default
    assert found.mitre_techniques is None or found.mitre_techniques == []


@pytest.mark.asyncio
async def test_enrich_cves_calls_mitre(db_session: AsyncSession):
    """enrich_cves should attempt MITRE enrichment after OSV/NVD."""
    cve = Cve(
        cve_id="CVE-2024-5555",
        severity=None,
        cvss_score=None,
    )
    db_session.add(cve)
    await db_session.flush()

    with patch("netlanventory.core.cve_enrichment.httpx") as mock_httpx:
        # Mock OSV returning 404 (no data)
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_httpx.AsyncClient.return_value = mock_client

        with patch("netlanventory.core.mitre_enrichment.enrich_mitre", new_callable=AsyncMock) as mock_mitre:
            from netlanventory.core.cve_enrichment import enrich_cves
            await enrich_cves(db_session, ["CVE-2024-5555"])

            # MITRE enrichment should have been called
            mock_mitre.assert_called_once()
