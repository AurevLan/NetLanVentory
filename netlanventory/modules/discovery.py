"""ARP sweep discovery module with async ping fallback."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.modules.base import BaseModule, ModuleCategory, ModuleMetadata

logger = get_logger(__name__)


class ARPSweepModule(BaseModule):
    metadata = ModuleMetadata(
        name="arp_sweep",
        display_name="ARP Sweep",
        version="1.0.0",
        category=ModuleCategory.DISCOVERY,
        description=(
            "Discovers hosts on the local network using ARP requests (Layer 2). "
            "Falls back to ICMP ping if ARP is unavailable."
        ),
        author="NetLanVentory",
        requires_root=True,
        options_schema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target CIDR range or single IP (e.g. 192.168.1.0/24)",
                },
                "timeout": {
                    "type": "number",
                    "default": 2,
                    "description": "ARP reply timeout in seconds",
                },
                "ping_fallback": {
                    "type": "boolean",
                    "default": True,
                    "description": "Use ICMP ping if ARP fails or is unavailable",
                },
                "ping_concurrency": {
                    "type": "integer",
                    "default": 50,
                    "description": "Max concurrent ping probes",
                },
            },
            "required": ["target"],
        },
    )

    async def run(self, session: AsyncSession, options: dict[str, Any]) -> dict[str, Any]:
        target = options["target"]
        timeout = float(options.get("timeout", 2))
        ping_fallback = bool(options.get("ping_fallback", True))
        ping_concurrency = int(options.get("ping_concurrency", 50))

        discovered: list[dict[str, Any]] = []

        # Try ARP first
        arp_results = await self._arp_sweep(target, timeout)

        if arp_results:
            discovered = arp_results
        elif ping_fallback:
            logger.info("ARP sweep returned no results — falling back to ping", target=target)
            discovered = await self._ping_sweep(target, ping_concurrency, timeout)

        # Upsert assets into DB
        assets_upserted = 0
        for host in discovered:
            asset = await self._upsert_asset(session, host)
            if asset:
                assets_upserted += 1

        return {
            "module": self.metadata.name,
            "status": "success",
            "assets_found": len(discovered),
            "details": {
                "target": target,
                "method": "arp" if arp_results else ("ping" if ping_fallback else "none"),
                "hosts": discovered,
                "assets_upserted": assets_upserted,
            },
        }

    # ── ARP sweep ────────────────────────────────────────────────────────────

    async def _arp_sweep(self, target: str, timeout: float) -> list[dict[str, Any]]:
        """Send ARP requests using scapy (requires root)."""
        try:
            from scapy.layers.l2 import ARP, Ether
            from scapy.sendrecv import srp

            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
            answered, _ = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: srp(pkt, timeout=timeout, verbose=False),
            )
            results = []
            for sent, received in answered:
                results.append(
                    {
                        "ip": received.psrc,
                        "mac": received.hwsrc.upper(),
                        "hostname": self._resolve_hostname(received.psrc),
                    }
                )
            logger.info("ARP sweep complete", target=target, found=len(results))
            return results
        except ImportError:
            logger.warning("scapy not available — skipping ARP sweep")
            return []
        except PermissionError:
            logger.warning("ARP sweep requires root — skipping")
            return []
        except Exception as exc:
            logger.warning("ARP sweep failed", error=str(exc))
            return []

    # ── Ping sweep ───────────────────────────────────────────────────────────

    async def _ping_sweep(
        self, target: str, concurrency: int, timeout: float
    ) -> list[dict[str, Any]]:
        """Async ICMP ping sweep using asyncio subprocess."""
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            try:
                network = ipaddress.ip_network(f"{target}/32", strict=False)
            except ValueError:
                return []

        hosts = list(network.hosts()) or [network.network_address]
        semaphore = asyncio.Semaphore(concurrency)
        results: list[dict[str, Any]] = []

        async def probe(ip: str) -> dict[str, Any] | None:
            async with semaphore:
                alive = await self._ping_host(ip, timeout)
                if alive:
                    return {
                        "ip": ip,
                        "mac": None,
                        "hostname": self._resolve_hostname(ip),
                    }
                return None

        tasks = [probe(str(h)) for h in hosts]
        gathered = await asyncio.gather(*tasks, return_exceptions=True)
        for item in gathered:
            if isinstance(item, dict):
                results.append(item)

        logger.info("Ping sweep complete", target=target, found=len(results))
        return results

    @staticmethod
    async def _ping_host(ip: str, timeout: float) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", str(int(timeout)), ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=timeout + 1)
            return proc.returncode == 0
        except (asyncio.TimeoutError, OSError):
            return False

    @staticmethod
    def _resolve_hostname(ip: str) -> str | None:
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, OSError):
            return None

    # ── DB upsert ────────────────────────────────────────────────────────────

    @staticmethod
    async def _upsert_asset(
        session: AsyncSession, host: dict[str, Any]
    ) -> Asset | None:
        """Insert or update an asset by MAC (preferred) or IP."""
        now = datetime.now(timezone.utc)
        asset: Asset | None = None

        if host.get("mac"):
            result = await session.execute(
                select(Asset).where(Asset.mac == host["mac"])
            )
            asset = result.scalar_one_or_none()

        if asset is None and host.get("ip"):
            result = await session.execute(
                select(Asset).where(Asset.ip == host["ip"])
            )
            asset = result.scalar_one_or_none()

        if asset is None:
            asset = Asset(
                mac=host.get("mac"),
                ip=host.get("ip"),
                hostname=host.get("hostname"),
                is_active=True,
                last_seen=now,
            )
            session.add(asset)
        else:
            if host.get("ip"):
                asset.ip = host["ip"]
            if host.get("mac"):
                asset.mac = host["mac"]
            if host.get("hostname"):
                asset.hostname = host["hostname"]
            asset.is_active = True
            asset.last_seen = now

        return asset
