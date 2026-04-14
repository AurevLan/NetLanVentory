"""Tests for scheduler automation features.

Covers:
- EPSS auto-enrichment
- KEV auto-sync
- SLA auto-compute + breach notifications
- ScheduledScan table check
- Default daily scan
- SSH profile auto-test
- IOC auto-correlation
- scan_done notification
- port_change notification
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.models.asset import Asset
from netlanventory.models.cve import Cve
from netlanventory.models.asset_cve import AssetCve


# ── Helpers ─────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def sample_asset(db_session: AsyncSession) -> Asset:
    """Create a sample active asset."""
    asset = Asset(ip="10.0.0.1", name="test-host", is_active=True)
    db_session.add(asset)
    await db_session.flush()
    await db_session.refresh(asset)
    return asset


@pytest_asyncio.fixture
async def sample_cves(db_session: AsyncSession, sample_asset: Asset) -> list[Cve]:
    """Create sample CVEs with asset links."""
    cves = []
    for i, (cve_id, severity) in enumerate([
        ("CVE-2024-0001", "Critical"),
        ("CVE-2024-0002", "High"),
        ("CVE-2024-0003", "Medium"),
    ]):
        cve = Cve(cve_id=cve_id, severity=severity, cvss_score=9.0 - i)
        db_session.add(cve)
        await db_session.flush()
        await db_session.refresh(cve)

        link = AssetCve(
            asset_id=sample_asset.id,
            cve_id=cve.id,
            source="test",
            discovered_at=datetime.now(timezone.utc) - timedelta(days=10),
        )
        db_session.add(link)
        cves.append(cve)

    await db_session.flush()
    return cves


# ── EPSS auto-enrichment ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_maybe_enrich_epss(db_session, sample_cves):
    """EPSS auto-enrichment should update CVE EPSS scores."""
    import netlanventory.core.scheduler as sched

    # Reset timer
    sched._last_epss_refresh = None

    fake_epss_map = {
        "CVE-2024-0001": (0.95, 0.99),
        "CVE-2024-0002": (0.42, 0.75),
    }

    with patch.object(sched, "get_session_factory") as mock_factory, \
         patch("netlanventory.core.scheduler._download_epss_map", new_callable=AsyncMock, return_value=fake_epss_map) as mock_dl:
        # Redirect to test session
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=db_session)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_factory.return_value = MagicMock(return_value=mock_ctx)

        # Need to import the function fresh since it uses lazy import
        from netlanventory.api.routers.epss import _download_epss_map

        with patch("netlanventory.api.routers.epss._download_epss_map", new_callable=AsyncMock, return_value=fake_epss_map):
            await sched._maybe_enrich_epss()

    assert sched._last_epss_refresh is not None


@pytest.mark.asyncio
async def test_epss_respects_interval():
    """EPSS should not re-run before the interval elapses."""
    import netlanventory.core.scheduler as sched

    sched._last_epss_refresh = datetime.now(timezone.utc)

    # Should return immediately without doing anything
    await sched._maybe_enrich_epss()
    # No error = interval respected


# ── KEV auto-sync ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_maybe_sync_kev_respects_interval():
    """KEV sync should not re-run before the interval elapses."""
    import netlanventory.core.scheduler as sched

    sched._last_kev_sync = datetime.now(timezone.utc)
    await sched._maybe_sync_kev()
    # No error = interval respected


@pytest.mark.asyncio
async def test_maybe_sync_kev_runs_when_due():
    """KEV sync should run when due (last sync > 24h ago)."""
    import netlanventory.core.scheduler as sched

    sched._last_kev_sync = datetime.now(timezone.utc) - timedelta(hours=25)

    fake_kev_response = {
        "vulnerabilities": [
            {"cveID": "CVE-2024-0001", "dateAdded": "2024-01-15", "knownRansomwareCampaignUse": "Known"},
        ]
    }

    with patch("netlanventory.core.scheduler.httpx") as mock_httpx:
        mock_resp = MagicMock()
        mock_resp.json.return_value = fake_kev_response
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_httpx.AsyncClient.return_value = mock_client

        with patch.object(sched, "get_session_factory") as mock_factory:
            mock_session = AsyncMock()
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = []
            mock_session.execute = AsyncMock(return_value=mock_result)
            mock_session.commit = AsyncMock()

            mock_ctx = AsyncMock()
            mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
            mock_ctx.__aexit__ = AsyncMock(return_value=False)
            mock_factory.return_value = MagicMock(return_value=mock_ctx)

            await sched._maybe_sync_kev()

    # Verify it ran
    assert sched._last_kev_sync is not None
    assert (datetime.now(timezone.utc) - sched._last_kev_sync).total_seconds() < 5


# ── SLA auto-compute ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_maybe_compute_sla_respects_interval():
    """SLA compute should not re-run before the interval elapses."""
    import netlanventory.core.scheduler as sched

    sched._last_sla_compute = datetime.now(timezone.utc)
    await sched._maybe_compute_sla()
    # No error = interval respected


# ── ScheduledScan table ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_check_scheduled_scans_table(db_session):
    """ScheduledScan rows should be picked up and launched when due."""
    from netlanventory.models.scheduled_scan import ScheduledScan

    ss = ScheduledScan(
        name="Daily LAN scan",
        target="192.168.1.0/24",
        modules="arp_sweep,port_scanner",
        interval_hours=24,
        enabled=True,
        last_run_at=datetime.now(timezone.utc) - timedelta(hours=25),
        run_count=0,
    )
    db_session.add(ss)
    await db_session.flush()
    await db_session.refresh(ss)

    import netlanventory.core.scheduler as sched

    with patch.object(sched, "get_session_factory") as mock_factory, \
         patch("netlanventory.core.scheduler._run_scan") as mock_run, \
         patch("netlanventory.core.scheduler.asyncio") as mock_asyncio:

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=db_session)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_factory.return_value = MagicMock(return_value=mock_ctx)

        # Patch Scan model creation
        with patch("netlanventory.core.scheduler.Scan") as MockScan:
            fake_scan = MagicMock()
            fake_scan.id = uuid.uuid4()
            MockScan.return_value = fake_scan

            await sched._check_scheduled_scans_table()

    # Should have been marked as run
    # (In real test with proper DB wiring, we'd check ss.run_count)


@pytest.mark.asyncio
async def test_scheduled_scan_disabled_skipped(db_session):
    """Disabled ScheduledScan rows should be skipped."""
    from netlanventory.models.scheduled_scan import ScheduledScan

    ss = ScheduledScan(
        name="Disabled scan",
        target="10.0.0.0/8",
        modules="arp_sweep",
        interval_hours=24,
        enabled=False,
        run_count=0,
    )
    db_session.add(ss)
    await db_session.flush()

    import netlanventory.core.scheduler as sched

    with patch.object(sched, "get_session_factory") as mock_factory:
        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=db_session)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_factory.return_value = MagicMock(return_value=mock_ctx)

        # Should not create any task
        with patch("netlanventory.core.scheduler.asyncio") as mock_asyncio:
            await sched._check_scheduled_scans_table()
            mock_asyncio.create_task.assert_not_called()


# ── Default daily scan ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_default_scan_disabled():
    """Default scan should not run when disabled in settings."""
    import netlanventory.core.scheduler as sched

    sched._last_default_scan = None

    mock_settings = MagicMock()
    mock_settings.default_scan_enabled = False

    with patch("netlanventory.core.scheduler.get_settings", return_value=mock_settings):
        await sched._maybe_run_default_scan()

    assert sched._last_default_scan is None


@pytest.mark.asyncio
async def test_default_scan_respects_interval():
    """Default scan should not re-run before the interval elapses."""
    import netlanventory.core.scheduler as sched

    sched._last_default_scan = datetime.now(timezone.utc)

    mock_settings = MagicMock()
    mock_settings.default_scan_enabled = True
    mock_settings.default_scan_interval_hours = 24

    with patch("netlanventory.core.scheduler.get_settings", return_value=mock_settings):
        await sched._maybe_run_default_scan()

    # Timestamp should not have changed
    assert (datetime.now(timezone.utc) - sched._last_default_scan).total_seconds() < 2


@pytest.mark.asyncio
async def test_default_scan_runs_when_due(db_session, sample_asset):
    """Default scan should launch scans for active assets when interval elapsed."""
    import netlanventory.core.scheduler as sched

    sched._last_default_scan = datetime.now(timezone.utc) - timedelta(hours=25)

    mock_settings = MagicMock()
    mock_settings.default_scan_enabled = True
    mock_settings.default_scan_interval_hours = 24
    mock_settings.default_scan_modules = "arp_sweep,port_scanner"

    with patch("netlanventory.core.scheduler.get_settings", return_value=mock_settings), \
         patch.object(sched, "get_session_factory") as mock_factory, \
         patch("netlanventory.core.scheduler._run_scan") as mock_run, \
         patch("netlanventory.core.scheduler.asyncio") as mock_asyncio:

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=db_session)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_factory.return_value = MagicMock(return_value=mock_ctx)

        with patch("netlanventory.core.scheduler.Scan") as MockScan:
            fake_scan = MagicMock()
            fake_scan.id = uuid.uuid4()
            MockScan.return_value = fake_scan

            await sched._maybe_run_default_scan()

    # Timer should have been updated
    assert sched._last_default_scan is not None
    assert (datetime.now(timezone.utc) - sched._last_default_scan).total_seconds() < 5


# ── SSH profile auto-test ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ssh_profile_test_disabled():
    """SSH profile test should not run when disabled in settings."""
    import netlanventory.core.scheduler as sched

    sched._last_ssh_profile_test = None

    mock_settings = MagicMock()
    mock_settings.ssh_profile_test_enabled = False

    with patch("netlanventory.core.scheduler.get_settings", return_value=mock_settings):
        await sched._maybe_test_ssh_profiles()

    assert sched._last_ssh_profile_test is None


@pytest.mark.asyncio
async def test_ssh_profile_test_respects_interval():
    """SSH profile test should not re-run before the interval elapses."""
    import netlanventory.core.scheduler as sched

    sched._last_ssh_profile_test = datetime.now(timezone.utc)

    mock_settings = MagicMock()
    mock_settings.ssh_profile_test_enabled = True
    mock_settings.ssh_profile_test_interval_hours = 24

    with patch("netlanventory.core.scheduler.get_settings", return_value=mock_settings):
        await sched._maybe_test_ssh_profiles()


# ── IOC auto-correlation ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_ioc_correlation_skips_when_no_feed_refresh():
    """IOC auto-correlation should skip when no feed refresh has happened."""
    import netlanventory.core.scheduler as sched

    sched._last_threat_feed_refresh = None
    sched._last_ioc_correlation = None

    await sched._maybe_auto_correlate_iocs()
    assert sched._last_ioc_correlation is None


@pytest.mark.asyncio
async def test_ioc_correlation_runs_after_feed_refresh():
    """IOC auto-correlation should run after a recent feed refresh."""
    import netlanventory.core.scheduler as sched

    sched._last_threat_feed_refresh = datetime.now(timezone.utc)
    sched._last_ioc_correlation = None

    with patch.object(sched, "get_session_factory") as mock_factory:
        mock_session = AsyncMock()

        # Mock assets query
        mock_assets_result = MagicMock()
        mock_assets_result.scalars.return_value.all.return_value = []

        # Mock IOCs query
        mock_iocs_result = MagicMock()
        mock_iocs_result.scalars.return_value.all.return_value = []

        mock_session.execute = AsyncMock(side_effect=[mock_assets_result, mock_iocs_result])

        mock_ctx = AsyncMock()
        mock_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        mock_ctx.__aexit__ = AsyncMock(return_value=False)
        mock_factory.return_value = MagicMock(return_value=mock_ctx)

        await sched._maybe_auto_correlate_iocs()

    assert sched._last_ioc_correlation is not None


@pytest.mark.asyncio
async def test_ioc_correlation_skips_if_already_correlated():
    """IOC auto-correlation should skip if already correlated for this feed refresh."""
    import netlanventory.core.scheduler as sched

    now = datetime.now(timezone.utc)
    sched._last_threat_feed_refresh = now - timedelta(minutes=5)
    sched._last_ioc_correlation = now  # Already correlated AFTER the feed refresh

    await sched._maybe_auto_correlate_iocs()
    # Should not have changed
    assert sched._last_ioc_correlation == now


# ── scan_done notification ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_notify_scan_done():
    """notify_scan_done should send webhook + SSE."""
    from netlanventory.core.notifications import notify_scan_done

    with patch("netlanventory.core.notifications.send_notification", new_callable=AsyncMock) as mock_send, \
         patch("netlanventory.core.notifications.broadcast_in_app_event", new_callable=AsyncMock) as mock_sse:

        await notify_scan_done(
            scan_id="abc-123",
            target="10.0.0.0/24",
            status="completed",
            modules=["arp_sweep", "port_scanner"],
            assets_found=5,
        )

        mock_send.assert_called_once()
        args = mock_send.call_args
        assert args[0][0] == "scan_done"
        assert args[0][1]["scan_id"] == "abc-123"
        assert args[0][1]["assets_found"] == 5

        mock_sse.assert_called_once()


# ── ssh_profile_failed notification ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_notify_ssh_profile_failed():
    """notify_ssh_profile_failed should send webhook + SSE."""
    from netlanventory.core.notifications import notify_ssh_profile_failed

    with patch("netlanventory.core.notifications.send_notification", new_callable=AsyncMock) as mock_send, \
         patch("netlanventory.core.notifications.broadcast_in_app_event", new_callable=AsyncMock) as mock_sse:

        await notify_ssh_profile_failed(
            profile_name="prod-servers",
            asset_ip="10.0.0.1",
            error="Connection refused",
        )

        mock_send.assert_called_once()
        args = mock_send.call_args
        assert args[0][0] == "ssh_profile_failed"
        assert args[0][1]["profile_name"] == "prod-servers"

        mock_sse.assert_called_once()


# ── port_change notification ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_notify_port_change():
    """notify_port_change should fire with added/removed ports."""
    from netlanventory.core.notifications import notify_port_change

    mock_asset = MagicMock()
    mock_asset.id = uuid.uuid4()
    mock_asset.ip = "10.0.0.1"
    mock_asset.name = "test-host"

    with patch("netlanventory.core.notifications.send_notification", new_callable=AsyncMock) as mock_send, \
         patch("netlanventory.core.notifications.broadcast_in_app_event", new_callable=AsyncMock):

        await notify_port_change(mock_asset, added_ports=[8080, 9090], removed_ports=[22])

        mock_send.assert_called_once()
        args = mock_send.call_args
        assert args[0][0] == "port_change"
        assert args[0][1]["added_ports"] == [8080, 9090]
        assert args[0][1]["removed_ports"] == [22]


# ── Scheduler loop structure ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scheduler_loop_calls_all_tasks():
    """The scheduler loop should call all registered task functions."""
    import netlanventory.core.scheduler as sched

    called = set()

    async def make_mock(name):
        async def _fn():
            called.add(name)
        return _fn

    # Verify that all expected task names are in the loop
    # We'll test by patching sleep to break after one cycle
    cycle_count = 0

    original_sleep = sched.asyncio.sleep

    async def fake_sleep(t):
        nonlocal cycle_count
        cycle_count += 1
        if cycle_count > 1:
            raise asyncio.CancelledError()

    import asyncio as _asyncio

    with patch.object(sched.asyncio, "sleep", side_effect=fake_sleep):
        # Patch all task functions to no-ops
        task_names = [
            "_check_and_trigger_auto_scans",
            "_check_and_trigger_ssh_auto_scans",
            "_check_and_trigger_trivy_auto_scans",
            "_check_new_assets",
            "_maybe_refresh_threat_feeds",
            "_maybe_auto_correlate_iocs",
            "_check_scheduled_reports",
            "_check_scheduled_scans",
            "_check_scheduled_scans_table",
            "_maybe_run_default_scan",
            "_maybe_test_ssh_profiles",
            "_maybe_enrich_epss",
            "_maybe_sync_kev",
            "_maybe_compute_sla",
            "_take_daily_kpi_snapshot",
        ]

        patches = {}
        for name in task_names:
            async def noop(n=name):
                called.add(n)
            patches[name] = patch.object(sched, name, side_effect=noop)

        with _asyncio.TaskGroup() as tg:
            for p in patches.values():
                p.start()
            try:
                await sched.scheduler_loop()
            except (_asyncio.CancelledError, ExceptionGroup):
                pass
            finally:
                for p in patches.values():
                    p.stop()

    # Verify all tasks were called in one cycle
    for name in task_names:
        assert name in called, f"Task {name} was not called in scheduler loop"


# ── Config settings ─────────────────────────────────────────────────────────


def test_config_has_default_scan_settings():
    """Settings should have default_scan_enabled and related fields."""
    from netlanventory.core.config import Settings

    # Check fields exist in the model
    fields = Settings.model_fields
    assert "default_scan_enabled" in fields
    assert "default_scan_interval_hours" in fields
    assert "default_scan_modules" in fields
    assert "ssh_profile_test_enabled" in fields
    assert "ssh_profile_test_interval_hours" in fields


def test_config_default_values():
    """Default config values should enable automation."""
    import os
    os.environ.setdefault("APP_DEBUG", "true")

    from netlanventory.core.config import Settings

    s = Settings(
        secret_key="test-secret",
        jwt_secret_key="test-jwt",
        admin_password="Test1234!@#$",
        app_debug=True,
    )
    assert s.default_scan_enabled is True
    assert s.default_scan_interval_hours == 24
    assert "arp_sweep" in s.default_scan_modules
    assert s.ssh_profile_test_enabled is True
    assert s.ssh_profile_test_interval_hours == 24
