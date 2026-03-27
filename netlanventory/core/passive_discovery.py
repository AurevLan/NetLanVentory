"""Passive network discovery via ARP and DHCP sniffing.

Listens on a network interface for ARP replies and DHCP packets to detect
hosts without actively probing the network. Requires root/CAP_NET_RAW.

Relies on scapy (already in dependencies via python-nmap's requirements or
as a direct dep). Enabled via PASSIVE_DISCOVERY_ENABLED=true in the env.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from netlanventory.core.logging import get_logger

logger = get_logger(__name__)


async def start_passive_listener(interface: str = "eth0") -> None:
    """Start the ARP/DHCP passive listener as an asyncio-friendly task.

    Runs scapy's AsyncSniffer in a background thread via run_in_executor so
    it doesn't block the event loop.
    """
    try:
        from scapy.all import AsyncSniffer, ARP, DHCP  # type: ignore[import]
    except ImportError:
        logger.warning("scapy not available — passive discovery disabled")
        return

    loop = asyncio.get_event_loop()

    def _packet_callback(pkt) -> None:  # type: ignore[no-untyped-def]
        """Called in the scapy thread for each matching packet."""
        try:
            if ARP in pkt and pkt[ARP].op == 2:  # ARP reply
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                asyncio.run_coroutine_threadsafe(
                    _handle_discovered_host(ip=ip, mac=mac, source="passive"),
                    loop,
                )
        except Exception as exc:  # noqa: BLE001
            logger.debug("Passive packet error", error=str(exc))

    logger.info("Passive discovery started", interface=interface)
    sniffer = AsyncSniffer(
        iface=interface,
        filter="arp",
        prn=_packet_callback,
        store=False,
    )
    try:
        sniffer.start()
        # Keep alive until cancelled
        while True:
            await asyncio.sleep(30)
    except asyncio.CancelledError:
        logger.info("Passive discovery stopped")
        sniffer.stop()
        raise
    except Exception as exc:  # noqa: BLE001
        logger.error("Passive discovery error", error=str(exc))
        try:
            sniffer.stop()
        except Exception:
            pass


async def _handle_discovered_host(ip: str, mac: str | None = None, source: str = "passive") -> None:
    """Upsert an asset from a passively discovered host.

    Creates the asset if it doesn't exist, updates last_seen if it does.
    Fires a notification if the asset is new and unknown.
    """
    from sqlalchemy import select

    from netlanventory.core.database import get_session_factory
    from netlanventory.models.asset import Asset

    factory = get_session_factory()
    try:
        async with factory() as session:
            # Check if the asset already exists (by IP or MAC)
            existing = None
            if ip:
                result = await session.execute(select(Asset).where(Asset.ip == ip))
                existing = result.scalar_one_or_none()
            if not existing and mac:
                result = await session.execute(select(Asset).where(Asset.mac == mac))
                existing = result.scalar_one_or_none()

            now = datetime.now(timezone.utc)

            if existing:
                existing.last_seen = now
                if not existing.ip and ip:
                    existing.ip = ip
                if not existing.mac and mac:
                    existing.mac = mac
            else:
                asset = Asset(
                    ip=ip,
                    mac=mac,
                    is_active=True,
                    last_seen=now,
                    discovery_source=source,
                )
                session.add(asset)
                await session.flush()
                await session.refresh(asset)
                logger.info("Passive: new asset detected", ip=ip, mac=mac)
                # Fire notification for unknown assets
                try:
                    from netlanventory.core.notifications import notify_new_asset_detected
                    await notify_new_asset_detected(asset)
                except Exception:
                    pass

            await session.commit()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Passive discovery DB error", error=str(exc))
