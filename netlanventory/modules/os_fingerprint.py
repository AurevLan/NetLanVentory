"""OS fingerprinting module — nmap -O with heuristic fallback."""

from __future__ import annotations

import asyncio
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.port import Port
from netlanventory.modules.base import BaseModule, ModuleCategory, ModuleMetadata

logger = get_logger(__name__)

# Heuristic rules: if certain ports are open, guess OS family
_PORT_HEURISTICS: list[tuple[set[int], str, str]] = [
    ({3389}, "Windows", "Windows (RDP detected)"),
    ({445, 139}, "Windows", "Windows (SMB detected)"),
    ({548}, "macOS", "macOS/Darwin (AFP detected)"),
    ({22}, "Linux/Unix", "Linux/Unix (SSH detected)"),
    ({23}, "Network Device", "Network Device (Telnet detected)"),
]


class OSFingerprintModule(BaseModule):
    metadata = ModuleMetadata(
        name="os_fingerprint",
        display_name="OS Fingerprint",
        version="1.0.0",
        category=ModuleCategory.OS_DETECT,
        description=(
            "Identifies the operating system of discovered hosts using nmap -O "
            "TCP/IP stack fingerprinting with heuristic port-based fallback."
        ),
        author="NetLanVentory",
        requires_root=True,
        options_schema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target CIDR, IP, or comma-separated IPs",
                },
                "guess_os": {
                    "type": "boolean",
                    "default": True,
                    "description": "Allow nmap OS guesses when certainty < 100%",
                },
                "use_heuristics": {
                    "type": "boolean",
                    "default": True,
                    "description": "Fall back to port-based heuristics when nmap cannot determine OS",
                },
            },
            "required": ["target"],
        },
    )

    async def run(self, session: AsyncSession, options: dict[str, Any]) -> dict[str, Any]:
        target = options["target"]
        guess_os = bool(options.get("guess_os", True))
        use_heuristics = bool(options.get("use_heuristics", True))

        assets = await self._load_active_assets(session, target)

        if not assets:
            return {
                "module": self.metadata.name,
                "status": "success",
                "assets_found": 0,
                "details": {"message": "No active assets found for target"},
            }

        results: list[dict[str, Any]] = []

        for asset in assets:
            if not asset.ip:
                continue

            os_info = await self._detect_os(asset.ip, guess_os)

            if not os_info and use_heuristics:
                os_info = await self._heuristic_os(session, asset)

            if os_info:
                asset.os_family = os_info.get("family") or asset.os_family
                asset.os_version = os_info.get("version") or asset.os_version

            results.append(
                {
                    "ip": asset.ip,
                    "os_family": asset.os_family,
                    "os_version": asset.os_version,
                    "method": os_info.get("method") if os_info else "unknown",
                    "confidence": os_info.get("confidence") if os_info else None,
                }
            )

        return {
            "module": self.metadata.name,
            "status": "success",
            "assets_found": len(results),
            "details": {
                "target": target,
                "hosts_analysed": len(results),
                "hosts": results,
            },
        }

    # ── nmap -O ──────────────────────────────────────────────────────────────

    @staticmethod
    async def _detect_os(
        ip: str, allow_guess: bool
    ) -> dict[str, Any] | None:
        try:
            import nmap as python_nmap  # type: ignore[import]
        except ImportError:
            logger.warning("python-nmap not installed — skipping nmap -O")
            return None

        nm = python_nmap.PortScanner()
        os_args = "-O --osscan-limit" + (" --osscan-guess" if allow_guess else "")
        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: nm.scan(hosts=ip, arguments=os_args),
            )
        except Exception as exc:
            logger.warning("nmap -O failed", ip=ip, error=str(exc))
            return None

        if ip not in nm.all_hosts():
            return None

        host = nm[ip]
        os_matches = host.get("osmatch", [])
        if not os_matches:
            return None

        best = os_matches[0]
        os_classes = best.get("osclass", [{}])
        os_class = os_classes[0] if os_classes else {}

        return {
            "family": os_class.get("osfamily", best.get("name", "Unknown")),
            "version": os_class.get("osgen", ""),
            "confidence": int(best.get("accuracy", 0)),
            "method": "nmap_os",
        }

    # ── Port heuristics ──────────────────────────────────────────────────────

    @staticmethod
    async def _heuristic_os(
        session: AsyncSession, asset: Asset
    ) -> dict[str, Any] | None:
        result = await session.execute(
            select(Port.port_number).where(
                Port.asset_id == asset.id, Port.state == "open"
            )
        )
        open_ports = {row[0] for row in result.fetchall()}

        for required_ports, family, version in _PORT_HEURISTICS:
            if required_ports.issubset(open_ports):
                return {
                    "family": family,
                    "version": version,
                    "confidence": 50,
                    "method": "heuristic",
                }
        return None

    # ── DB helpers ───────────────────────────────────────────────────────────

    @staticmethod
    async def _load_active_assets(
        session: AsyncSession, target: str
    ) -> list[Asset]:
        import ipaddress

        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            network = None

        result = await session.execute(
            select(Asset).where(Asset.is_active.is_(True))
        )
        assets = result.scalars().all()

        if network is None:
            return [a for a in assets if a.ip == target]

        filtered = []
        for asset in assets:
            if not asset.ip:
                continue
            try:
                if ipaddress.ip_address(asset.ip) in network:
                    filtered.append(asset)
            except ValueError:
                continue
        return filtered
