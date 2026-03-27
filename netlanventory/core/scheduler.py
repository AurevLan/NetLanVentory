"""Background auto-scan scheduler.

Runs as an asyncio task in the app lifespan. Every 60 seconds it checks
all assets where ZAP, SSH, or Trivy auto-scan is enabled and triggers
scans when the configured interval has elapsed since the last scan.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from netlanventory.core.logging import get_logger

logger = get_logger(__name__)

# Web service ports that ZAP should scan
_WEB_PORTS_HTTP = {80, 8080, 8000, 3000, 8888}
_WEB_PORTS_HTTPS = {443, 8443, 4443}
_WEB_PORTS_ALL = _WEB_PORTS_HTTP | _WEB_PORTS_HTTPS

_CHECK_INTERVAL_SECONDS = 60  # how often the scheduler wakes up to check


_THREAT_FEED_INTERVAL_SECONDS = 6 * 3600  # 6 hours
_last_threat_feed_refresh: datetime | None = None


async def scheduler_loop() -> None:
    """Infinite loop: wake every 60 s and trigger due ZAP, SSH, Trivy scans and other checks."""
    logger.info("Auto-scan scheduler started (ZAP + SSH + Trivy + scheduled rescans + threat feeds + new assets)")
    while True:
        await asyncio.sleep(_CHECK_INTERVAL_SECONDS)
        try:
            await _check_and_trigger_auto_scans()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("ZAP scheduler error — will retry next cycle")
        try:
            await _check_and_trigger_ssh_auto_scans()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("SSH scheduler error — will retry next cycle")
        try:
            await _check_and_trigger_trivy_auto_scans()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Trivy scheduler error — will retry next cycle")
        try:
            await _check_new_assets()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("New-assets check error — will retry next cycle")
        try:
            await _maybe_refresh_threat_feeds()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Threat feeds refresh error — will retry next cycle")
        try:
            await _check_scheduled_reports()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Scheduled reports check error — will retry next cycle")
        try:
            await _check_scheduled_scans()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Scheduled scans check error — will retry next cycle")


async def _check_and_trigger_auto_scans() -> None:
    """Check all assets and trigger ZAP scans where due."""
    from netlanventory.core.database import get_session_factory
    from netlanventory.models.asset import Asset
    from netlanventory.models.asset_dns import AssetDns
    from netlanventory.models.global_settings import GlobalSettings
    from netlanventory.models.port import Port
    from netlanventory.models.zap_report import ZapReport
    from netlanventory.api.routers.zap import _run_zap_scan

    factory = get_session_factory()

    async with factory() as session:
        # 1. Load global settings (singleton id=1)
        gs_result = await session.execute(
            select(GlobalSettings).where(GlobalSettings.id == 1)
        )
        gs = gs_result.scalar_one_or_none()
        global_enabled = gs.zap_auto_scan_enabled if gs else False
        global_interval = gs.zap_scan_interval_minutes if gs else 60

        # 2. Load all active assets with their ports and DNS entries
        assets_result = await session.execute(
            select(Asset)
            .where(Asset.is_active.is_(True))
            .options(
                selectinload(Asset.ports),
                selectinload(Asset.dns_entries),
            )
        )
        assets = assets_result.scalars().all()

        now = datetime.now(timezone.utc)

        for asset in assets:
            # Resolve effective enabled/interval for this asset
            asset_enabled = asset.zap_auto_scan_enabled
            if asset_enabled is None:
                effective_enabled = global_enabled
            else:
                effective_enabled = asset_enabled

            if not effective_enabled:
                continue

            asset_interval = asset.zap_scan_interval_minutes
            effective_interval_minutes = asset_interval if asset_interval is not None else global_interval

            # Check if it's time to scan
            last = asset.zap_last_auto_scan_at
            if last is not None:
                # Ensure last is timezone-aware for comparison
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                elapsed_minutes = (now - last).total_seconds() / 60
                if elapsed_minutes < effective_interval_minutes:
                    continue

            # Find open web ports
            open_ports = [p for p in (asset.ports or []) if p.state == "open"]
            web_ports = [p for p in open_ports if p.port_number in _WEB_PORTS_ALL]
            if not web_ports:
                continue

            # Build target list: IP + all DNS names, on each web port
            targets: list[str] = []
            hosts: list[str] = []

            if asset.ip:
                hosts.append(asset.ip)
            for dns in (asset.dns_entries or []):
                if dns.fqdn:
                    hosts.append(dns.fqdn)

            if not hosts:
                continue

            for port in web_ports:
                scheme = "https" if port.port_number in _WEB_PORTS_HTTPS else "http"
                for host in hosts:
                    if (scheme == "http" and port.port_number == 80) or \
                       (scheme == "https" and port.port_number == 443):
                        targets.append(f"{scheme}://{host}")
                    else:
                        targets.append(f"{scheme}://{host}:{port.port_number}")

            if not targets:
                continue

            # Update last-scan timestamp before launching tasks so we don't
            # accidentally double-trigger if a scan is slow
            asset.zap_last_auto_scan_at = now
            await session.flush()

            logger.info(
                "Auto-scan triggered",
                asset_id=str(asset.id),
                ip=asset.ip,
                targets=targets,
            )

            # Create a ZapReport and launch a background task for each target
            for target_url in targets:
                report = ZapReport(
                    asset_id=asset.id,
                    status="pending",
                    target_url=target_url,
                )
                session.add(report)
                await session.flush()
                await session.refresh(report)

                # Fire-and-forget — _run_zap_scan manages its own session
                asyncio.create_task(
                    _run_zap_scan(
                        report_id=report.id,
                        asset_id=asset.id,
                        target_url=target_url,
                        spider=True,
                    ),
                    name=f"zap-auto-{asset.id}-{report.id}",
                )

        await session.commit()


async def _check_and_trigger_ssh_auto_scans() -> None:
    """Check all assets and trigger SSH CVE scans where due."""
    from netlanventory.core.database import get_session_factory
    from netlanventory.models.asset import Asset
    from netlanventory.models.ssh_scan_report import SshScanReport
    from netlanventory.api.routers.ssh_scan import _run_ssh_scan

    factory = get_session_factory()

    async with factory() as session:
        assets_result = await session.execute(
            select(Asset)
            .where(Asset.is_active.is_(True))
            .where(Asset.ssh_auto_scan_enabled.is_(True))
            .options(selectinload(Asset.ssh_profile))
        )
        assets = assets_result.scalars().all()

        now = datetime.now(timezone.utc)

        for asset in assets:
            # Must have SSH credentials to scan
            if not asset.has_ssh_credentials:
                continue

            if not asset.ip:
                continue

            interval_minutes = asset.ssh_scan_interval_minutes or 60

            last = asset.ssh_last_auto_scan_at
            if last is not None:
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                elapsed_minutes = (now - last).total_seconds() / 60
                if elapsed_minutes < interval_minutes:
                    continue

            # Mark before launching to avoid double-trigger
            asset.ssh_last_auto_scan_at = now
            await session.flush()

            report = SshScanReport(asset_id=asset.id, status="pending")
            session.add(report)
            await session.flush()
            await session.refresh(report)

            logger.info(
                "SSH auto-scan triggered",
                asset_id=str(asset.id),
                ip=asset.ip,
            )

            asyncio.create_task(
                _run_ssh_scan(report_id=report.id, asset_id=asset.id),
                name=f"ssh-auto-{asset.id}-{report.id}",
            )

        await session.commit()


async def _check_and_trigger_trivy_auto_scans() -> None:
    """Check all assets and trigger Trivy Docker scans where due."""
    import shutil
    from netlanventory.core.database import get_session_factory
    from netlanventory.models.asset import Asset
    from netlanventory.models.trivy_docker_report import TrivyDockerReport
    from netlanventory.api.routers.trivy_docker_scan import _run_trivy_docker_scan, TRIVY_BINARY

    if not shutil.which(TRIVY_BINARY):
        return  # Trivy not installed, skip silently

    factory = get_session_factory()

    async with factory() as session:
        assets_result = await session.execute(
            select(Asset)
            .where(Asset.is_active.is_(True))
            .where(Asset.trivy_auto_scan_enabled.is_(True))
            .options(selectinload(Asset.ssh_profile))
        )
        assets = assets_result.scalars().all()

        now = datetime.now(timezone.utc)

        for asset in assets:
            if not asset.has_ssh_credentials:
                continue

            if not asset.ip:
                continue

            interval_minutes = asset.trivy_scan_interval_minutes or 60

            last = asset.trivy_last_auto_scan_at
            if last is not None:
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                elapsed_minutes = (now - last).total_seconds() / 60
                if elapsed_minutes < interval_minutes:
                    continue

            # Mark before launching to avoid double-trigger
            asset.trivy_last_auto_scan_at = now
            await session.flush()

            report = TrivyDockerReport(asset_id=asset.id, status="pending")
            session.add(report)
            await session.flush()
            await session.refresh(report)

            logger.info(
                "Trivy auto-scan triggered",
                asset_id=str(asset.id),
                ip=asset.ip,
            )

            asyncio.create_task(
                _run_trivy_docker_scan(report_id=report.id, asset_id=asset.id),
                name=f"trivy-auto-{asset.id}-{report.id}",
            )

        await session.commit()


async def _check_new_assets() -> None:
    """Notify about high/critical assets discovered in the last 5 minutes."""
    from datetime import timedelta
    from netlanventory.core.database import get_session_factory
    from netlanventory.core.notifications import notify_new_critical_asset
    from netlanventory.models.asset import Asset

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
    factory = get_session_factory()

    async with factory() as session:
        result = await session.execute(
            select(Asset).where(
                Asset.created_at >= cutoff,
                Asset.criticality.in_(["high", "critical"]),
                Asset.is_active.is_(True),
            )
        )
        new_critical = result.scalars().all()
        for asset in new_critical:
            await notify_new_critical_asset(asset)


async def _maybe_refresh_threat_feeds() -> None:
    """Refresh threat intelligence feeds every 6 hours."""
    global _last_threat_feed_refresh

    now = datetime.now(timezone.utc)
    if _last_threat_feed_refresh is not None:
        elapsed = (now - _last_threat_feed_refresh).total_seconds()
        if elapsed < _THREAT_FEED_INTERVAL_SECONDS:
            return

    from netlanventory.core.config import get_settings
    from netlanventory.core.threat_feeds import refresh_abusech_feed, refresh_otx_feed

    _last_threat_feed_refresh = now
    settings = get_settings()

    if settings.otx_api_key:
        try:
            count = await refresh_otx_feed(settings.otx_api_key)
            logger.info("OTX feed refreshed", count=count)
        except Exception:  # noqa: BLE001
            logger.exception("OTX feed refresh failed")

    try:
        count = await refresh_abusech_feed()
        logger.info("Abuse.ch feed refreshed", count=count)
    except Exception:  # noqa: BLE001
        logger.exception("Abuse.ch feed refresh failed")


async def _check_scheduled_reports() -> None:
    """Send overdue scheduled reports."""
    from datetime import timedelta
    from netlanventory.core.database import get_session_factory
    from netlanventory.core.email_sender import send_report_email
    from netlanventory.models.scheduled_report import ScheduledReport

    now = datetime.now(timezone.utc)
    factory = get_session_factory()

    async with factory() as session:
        result = await session.execute(
            select(ScheduledReport).where(
                ScheduledReport.enabled.is_(True),
                ScheduledReport.next_run_at <= now,
            )
        )
        due_reports = result.scalars().all()

        interval_map = {
            "daily": timedelta(days=1),
            "weekly": timedelta(weeks=1),
            "monthly": timedelta(days=30),
        }

        for report in due_reports:
            try:
                subject = f"[NetLanVentory] {report.name} — {report.report_type} report"
                html_body = f"<h1>NetLanVentory Report: {report.name}</h1><p>Type: {report.report_type}</p>"

                await send_report_email(
                    recipients=report.recipients,
                    subject=subject,
                    html_body=html_body,
                    pdf_attachment=None,
                )

                report.last_sent_at = now
                report.next_run_at = now + interval_map.get(report.schedule, timedelta(days=1))
                logger.info("Scheduled report sent", name=report.name, recipients=report.recipients)
            except Exception:  # noqa: BLE001
                logger.exception("Failed to send scheduled report", name=report.name)

        await session.commit()


async def _check_scheduled_scans() -> None:
    """Trigger recurring scans when their interval has elapsed.

    A scan with recurring=True and recurring_interval_hours set will be
    automatically re-launched (same target + modules) when the interval
    has elapsed since the last trigger.
    """
    from netlanventory.core.database import get_session_factory
    from netlanventory.models.scan import Scan
    from netlanventory.api.routers.scans import _run_scan

    factory = get_session_factory()
    now = datetime.now(timezone.utc)

    async with factory() as session:
        result = await session.execute(
            select(Scan).where(
                Scan.recurring.is_(True),
                Scan.recurring_interval_hours.isnot(None),
            )
        )
        recurring_scans = result.scalars().all()

        for parent in recurring_scans:
            interval = parent.recurring_interval_hours or 24

            # Check if interval has elapsed since last trigger (or creation)
            last = parent.recurring_last_triggered_at or parent.created_at
            if last is not None:
                if last.tzinfo is None:
                    last = last.replace(tzinfo=timezone.utc)
                elapsed_hours = (now - last).total_seconds() / 3600
                if elapsed_hours < interval:
                    continue

            modules = parent.modules_run or []
            if not modules:
                continue

            # Create a NEW scan from the parent's config
            child = Scan(
                target=parent.target,
                status="pending",
                modules_run=modules,
            )
            session.add(child)
            await session.flush()
            await session.refresh(child)

            # Update parent tracking
            parent.recurring_last_triggered_at = now
            parent.recurring_run_count = (parent.recurring_run_count or 0) + 1
            await session.flush()

            logger.info(
                "Recurring scan triggered",
                parent_scan_id=str(parent.id),
                child_scan_id=str(child.id),
                target=parent.target,
                modules=modules,
                run_count=parent.recurring_run_count,
            )

            asyncio.create_task(
                _run_scan(child.id, parent.target, modules, {}),
                name=f"recurring-{parent.id}-{child.id}",
            )

        await session.commit()
