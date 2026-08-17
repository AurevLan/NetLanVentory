"""API tests for GET /prioritization/todo — the fleet-wide « À traiter » feed."""

from __future__ import annotations

from datetime import date

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.asset_tag import AssetTag
from netlanventory.models.cve import Cve


@pytest.mark.asyncio
async def test_todo_empty(client):
    r = await client.get("/api/v1/prioritization/todo")
    assert r.status_code == 200
    d = r.json()
    assert d["total_open"] == 0
    assert d["items"] == []
    assert d["counts"] == {
        "act_open": 0,
        "attend_open": 0,
        "internet_facing_open": 0,
        "sla_breached": 0,
        "unevaluated": 0,
    }


@pytest.mark.asyncio
async def test_todo_limit_validation(client):
    assert (await client.get("/api/v1/prioritization/todo?limit=0")).status_code == 422
    assert (await client.get("/api/v1/prioritization/todo?limit=101")).status_code == 422


async def _seed(db: AsyncSession) -> None:
    """One internet-facing critical asset with an act + attend + acked +
    unevaluated pair, and one quiet internal asset with a track pair."""
    exposed = Asset(ip="203.0.113.10", name="edge-web", is_active=True, criticality="critical")
    internal = Asset(ip="10.0.0.5", name="lan-db", is_active=True, criticality="medium")
    db.add_all([exposed, internal])
    await db.flush()
    db.add(AssetTag(asset_id=exposed.id, name="internet-facing"))

    kev_cve = Cve(
        cve_id="CVE-2025-0001", severity="Critical", cvss_score=9.8,
        epss_percentile=0.99, kev_date_added=date(2025, 1, 1),
    )
    attend_cve = Cve(
        cve_id="CVE-2025-0002", severity="High", cvss_score=8.1, epss_percentile=0.80,
    )
    acked_cve = Cve(cve_id="CVE-2025-0003", severity="Critical", cvss_score=9.0)
    fresh_cve = Cve(cve_id="CVE-2025-0004", severity="High", cvss_score=7.5)
    track_cve = Cve(cve_id="CVE-2025-0005", severity="Low", cvss_score=3.1)
    db.add_all([kev_cve, attend_cve, acked_cve, fresh_cve, track_cve])
    await db.flush()

    db.add_all([
        AssetCve(
            asset_id=exposed.id, cve_id=kev_cve.id, source="test",
            ssvc_decision="act", fixed_version="1.2.3", exploit_verified=True,
            sla_breached=True,
        ),
        AssetCve(
            asset_id=exposed.id, cve_id=attend_cve.id, source="test",
            ssvc_decision="attend",
        ),
        AssetCve(
            asset_id=exposed.id, cve_id=acked_cve.id, source="test",
            ssvc_decision="act", ack_status="accepted",
        ),
        AssetCve(asset_id=exposed.id, cve_id=fresh_cve.id, source="test"),
        AssetCve(
            asset_id=internal.id, cve_id=track_cve.id, source="test",
            ssvc_decision="track",
        ),
    ])
    await db.commit()


@pytest.mark.asyncio
async def test_todo_ranked_feed(client, db_session):
    await _seed(db_session)

    r = await client.get("/api/v1/prioritization/todo")
    assert r.status_code == 200
    d = r.json()

    # Counts: acked pair excluded everywhere; unevaluated surfaced.
    assert d["counts"]["act_open"] == 1
    assert d["counts"]["attend_open"] == 1
    assert d["counts"]["unevaluated"] == 1
    assert d["counts"]["sla_breached"] == 1
    # 3 open pairs on the tagged asset (act + attend + unevaluated)
    assert d["counts"]["internet_facing_open"] == 3
    assert d["total_open"] == 4

    # Items: only evaluated open pairs, most urgent first.
    ids = [i["cve_id"] for i in d["items"]]
    assert ids == ["CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0005"]

    top = d["items"][0]
    assert top["decision"] == "act"
    assert top["tier"] == "P1"
    assert top["sla_label"] == "<24h"
    assert top["kev"] is True
    assert top["internet_facing"] is True
    assert top["asset_criticality"] == "critical"
    assert top["ssvc_source"] == "stored"
    assert "Exploitée dans la nature (KEV)" in top["reasons"]
    assert "Exploit vérifié sur cet asset" in top["reasons"]
    assert "Exposé à Internet" in top["reasons"]
    assert "Asset critique" in top["reasons"]
    assert "Correctif disponible (1.2.3)" in top["reasons"]

    quiet = d["items"][2]
    assert quiet["decision"] == "track"
    assert quiet["internet_facing"] is False
    assert quiet["reasons"] == []


@pytest.mark.asyncio
async def test_todo_limit_slices_most_urgent(client, db_session):
    await _seed(db_session)

    r = await client.get("/api/v1/prioritization/todo?limit=1")
    assert r.status_code == 200
    d = r.json()
    assert len(d["items"]) == 1
    assert d["items"][0]["cve_id"] == "CVE-2025-0001"
    # Counts stay fleet-wide regardless of the slice.
    assert d["total_open"] == 4
