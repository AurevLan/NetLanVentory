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


def _mock_httpx(status_code: int, json_payload: dict | None = None):
    """Build a patched httpx whose AsyncClient.get returns one canned response."""
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.json = MagicMock(return_value=json_payload or {})
    mock_client.get = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    mock_httpx = MagicMock()
    mock_httpx.AsyncClient.return_value = mock_client
    return mock_httpx


@pytest.mark.asyncio
async def test_backfill_populates_vector_and_keeps_score(db_session: AsyncSession):
    """backfill_cvss_vectors fills cvss_vector from OSV without touching score."""
    from netlanventory.core.cve_enrichment import backfill_cvss_vectors

    cve = Cve(cve_id="CVE-2021-44228", severity="Critical", cvss_score=10.0)
    db_session.add(cve)
    await db_session.flush()

    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    osv_payload = {"severity": [{"type": "CVSS_V3", "score": vector}]}

    with patch("netlanventory.core.cve_enrichment.httpx", _mock_httpx(200, osv_payload)):
        processed, updated, last_id = await backfill_cvss_vectors(db_session)

    assert (processed, updated) == (1, 1)
    assert last_id == cve.id
    await db_session.refresh(cve)
    assert cve.cvss_vector == vector
    assert cve.cvss_score == 10.0  # not clobbered


@pytest.mark.asyncio
async def test_backfill_keyset_terminates_on_unresolved(db_session: AsyncSession):
    """A CVE with no available vector stays NULL but keyset paging still ends."""
    from netlanventory.core.cve_enrichment import backfill_cvss_vectors

    cve = Cve(cve_id="CVE-2024-7777", severity="High", cvss_score=7.5)
    db_session.add(cve)
    await db_session.flush()

    # OSV + NVD both 404 -> vector stays None.
    with patch("netlanventory.core.cve_enrichment.httpx", _mock_httpx(404)):
        processed, updated, last_id = await backfill_cvss_vectors(db_session)
        assert (processed, updated) == (1, 0)
        assert last_id == cve.id
        await db_session.refresh(cve)
        assert cve.cvss_vector is None

        # Feeding last_id back advances past the unresolved row -> drained.
        processed2, updated2, last_id2 = await backfill_cvss_vectors(
            db_session, after_id=last_id
        )
        assert (processed2, updated2, last_id2) == (0, 0, None)
