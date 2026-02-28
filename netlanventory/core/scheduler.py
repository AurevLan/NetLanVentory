"""Background ZAP auto-scan scheduler.

Runs as an asyncio task in the app lifespan. Every 60 seconds it checks
all assets where ZAP auto-scan is enabled and triggers scans when the
configured interval has elapsed since the last scan.
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


async def scheduler_loop() -> None:
    """Infinite loop: wake every 60 s and trigger due ZAP scans."""
    logger.info("ZAP auto-scan scheduler started")
    while True:
        await asyncio.sleep(_CHECK_INTERVAL_SECONDS)
        try:
            await _check_and_trigger_auto_scans()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("ZAP scheduler error — will retry next cycle")


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
