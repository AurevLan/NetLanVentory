"""Integration tests for the smart-scheduler queue drain (innovation #5, v0.15).

Covers the wiring added in v0.15:
- `core.scan_dispatch._primary_web_url` / `dispatch_module` routing
- `core.scheduler._drain_priority_queue` orchestration (pop → dispatch →
  mark_scanned / defer), gated by `smart_scheduler_queue_enabled`
- the SSH/Trivy fixed-interval loops yielding when the flag is on

Real ScanPriority rows are used against the SQLite test session; the actual
scan launch (`dispatch_module`) is mocked so no background task is spawned.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-unit-tests")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-for-tests")
os.environ.setdefault("ADMIN_PASSWORD", "Test1234!@#$")
os.environ.setdefault("APP_DEBUG", "true")

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.core import scan_dispatch
from netlanventory.models.asset import Asset
from netlanventory.models.scan_priority import ScanPriority


# ── scan_dispatch._primary_web_url (pure) ────────────────────────────────────


def _asset_with_ports(ip, ports):
    """Build a lightweight Asset-like object for _primary_web_url."""
    port_objs = [
        SimpleNamespace(port_number=pn, state=state) for pn, state in ports
    ]
    return SimpleNamespace(ip=ip, ports=port_objs)


class TestPrimaryWebUrl:
    def test_https_preferred_over_http(self):
        a = _asset_with_ports("10.0.0.5", [(80, "open"), (443, "open")])
        assert scan_dispatch._primary_web_url(a) == "https://10.0.0.5"

    def test_plain_http_port_80_omits_port(self):
        a = _asset_with_ports("10.0.0.5", [(80, "open")])
        assert scan_dispatch._primary_web_url(a) == "http://10.0.0.5"

    def test_nonstandard_port_kept(self):
        a = _asset_with_ports("10.0.0.5", [(8080, "open")])
        assert scan_dispatch._primary_web_url(a) == "http://10.0.0.5:8080"

    def test_https_nonstandard_port_kept(self):
        a = _asset_with_ports("10.0.0.5", [(8443, "open")])
        assert scan_dispatch._primary_web_url(a) == "https://10.0.0.5:8443"

    def test_no_web_port_returns_none(self):
        a = _asset_with_ports("10.0.0.5", [(22, "open")])
        assert scan_dispatch._primary_web_url(a) is None

    def test_closed_web_port_ignored(self):
        a = _asset_with_ports("10.0.0.5", [(443, "closed")])
        assert scan_dispatch._primary_web_url(a) is None

    def test_no_ip_returns_none(self):
        a = _asset_with_ports(None, [(443, "open")])
        assert scan_dispatch._primary_web_url(a) is None


@pytest.mark.asyncio
async def test_dispatch_unknown_module_returns_false(db_session):
    asset = Asset(ip="10.0.0.9", name="x", is_active=True)
    db_session.add(asset)
    await db_session.flush()
    assert await scan_dispatch.dispatch_module(db_session, asset, "bogus") is False


# ── _drain_priority_queue orchestration ──────────────────────────────────────


def _patch_factory(sched, db_session):
    """Return a patch context that points get_session_factory at db_session."""
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=db_session)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)
    p = patch.object(sched, "get_session_factory")
    mock_factory = p.start()
    mock_factory.return_value = MagicMock(return_value=mock_ctx)
    return p


def _settings(flag: bool):
    return MagicMock(smart_scheduler_queue_enabled=flag)


def _aware(dt: datetime) -> datetime:
    """SQLite drops tzinfo — re-attach UTC for comparison."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


@pytest_asyncio.fixture
async def due_priority(db_session: AsyncSession):
    """An active asset with one overdue, high-score ssh_scan priority row."""
    asset = Asset(ip="10.0.0.20", name="drain-host", is_active=True)
    db_session.add(asset)
    await db_session.flush()
    await db_session.refresh(asset)

    now = datetime.now(timezone.utc)
    row = ScanPriority(
        asset_id=asset.id,
        module="ssh_scan",
        score=30.0,
        last_score_update=now,
        next_eligible_at=now - timedelta(minutes=5),  # overdue → poppable
        max_age_hours=72,
        last_scan_at=None,
    )
    db_session.add(row)
    await db_session.flush()
    return asset, row


@pytest.mark.asyncio
async def test_drain_noop_when_flag_off(db_session, due_priority):
    import netlanventory.core.scheduler as sched

    sched._last_famine_guard = datetime.now(timezone.utc)
    p = _patch_factory(sched, db_session)
    try:
        with patch("netlanventory.core.scheduler.get_settings", return_value=_settings(False)), \
             patch("netlanventory.core.scan_dispatch.dispatch_module", new_callable=AsyncMock) as disp:
            await sched._drain_priority_queue()
            disp.assert_not_called()
    finally:
        p.stop()


@pytest.mark.asyncio
async def test_drain_dispatches_and_marks_scanned(db_session, due_priority):
    import netlanventory.core.scheduler as sched

    asset, row = due_priority
    sched._last_famine_guard = datetime.now(timezone.utc)  # skip famine guard
    p = _patch_factory(sched, db_session)
    try:
        with patch("netlanventory.core.scheduler.get_settings", return_value=_settings(True)), \
             patch("netlanventory.core.scan_dispatch.dispatch_module", new_callable=AsyncMock, return_value=True) as disp:
            await sched._drain_priority_queue()
            disp.assert_awaited_once()
            # routed with the right asset + module
            _sess, got_asset, got_module = disp.await_args.args
            assert got_asset.id == asset.id
            assert got_module == "ssh_scan"

    finally:
        p.stop()

    await db_session.refresh(row)  # Core update()s bypass the identity map
    # mark_scanned resets the score and stamps last_scan_at
    assert row.score == 1.0
    assert row.last_scan_at is not None


@pytest.mark.asyncio
async def test_drain_defers_when_ineligible(db_session, due_priority):
    import netlanventory.core.scheduler as sched

    asset, row = due_priority
    sched._last_famine_guard = datetime.now(timezone.utc)
    p = _patch_factory(sched, db_session)
    try:
        with patch("netlanventory.core.scheduler.get_settings", return_value=_settings(True)), \
             patch("netlanventory.core.scan_dispatch.dispatch_module", new_callable=AsyncMock, return_value=False) as disp:
            await sched._drain_priority_queue()
            disp.assert_awaited_once()
    finally:
        p.stop()

    await db_session.refresh(row)
    # defer leaves score & last_scan_at untouched, only pushes eligibility out
    assert row.score == 30.0
    assert row.last_scan_at is None
    # defer pushed eligibility ~15 min out (was 5 min in the past)
    assert _aware(row.next_eligible_at) > datetime.now(timezone.utc) + timedelta(minutes=10)


@pytest.mark.asyncio
async def test_drain_defers_when_asset_inactive(db_session, due_priority):
    import netlanventory.core.scheduler as sched

    asset, row = due_priority
    asset.is_active = False  # asset no longer eligible to load
    await db_session.flush()
    sched._last_famine_guard = datetime.now(timezone.utc)
    p = _patch_factory(sched, db_session)
    try:
        with patch("netlanventory.core.scheduler.get_settings", return_value=_settings(True)), \
             patch("netlanventory.core.scan_dispatch.dispatch_module", new_callable=AsyncMock) as disp:
            await sched._drain_priority_queue()
            disp.assert_not_called()  # asset not loaded → never dispatched
    finally:
        p.stop()

    await db_session.refresh(row)
    assert _aware(row.next_eligible_at) > datetime.now(timezone.utc) + timedelta(minutes=10)


@pytest.mark.asyncio
async def test_ssh_fixed_loop_yields_when_flag_on(db_session):
    """The fixed-interval SSH loop must return early when the queue owns it."""
    import netlanventory.core.scheduler as sched

    p = _patch_factory(sched, db_session)
    try:
        with patch("netlanventory.core.scheduler.get_settings", return_value=_settings(True)):
            # If it did not yield, it would call the factory; assert it doesn't.
            sched.get_session_factory.reset_mock()
            await sched._check_and_trigger_ssh_auto_scans()
            sched.get_session_factory.assert_not_called()
    finally:
        p.stop()
