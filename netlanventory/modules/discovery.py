"""Ping sweep discovery module."""

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
        display_name="Ping Sweep",
        version="1.1.0",
        category=ModuleCategory.DISCOVERY,
        description="Discovers hosts on the network using ICMP ping.",
        author="NetLanVentory",
        requires_root=False,
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
                    "description": "Ping timeout in seconds",
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
        ping_concurrency = int(options.get("ping_concurrency", 50))

        discovered = await self._ping_sweep(target, ping_concurrency, timeout)

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
                "method": "ping",
                "hosts": discovered,
                "assets_upserted": assets_upserted,
            },
        }

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
        """Insert or update an asset by IP."""
        now = datetime.now(timezone.utc)
        asset: Asset | None = None

        if host.get("ip"):
            result = await session.execute(
                select(Asset).where(Asset.ip == host["ip"])
            )
            asset = result.scalar_one_or_none()

        if asset is None:
            asset = Asset(
                ip=host.get("ip"),
                hostname=host.get("hostname"),
                is_active=True,
                last_seen=now,
            )
            session.add(asset)
        else:
            if host.get("ip"):
                asset.ip = host["ip"]
            if host.get("hostname"):
                asset.hostname = host["hostname"]
            asset.is_active = True
            asset.last_seen = now

        return asset
