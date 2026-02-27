"""Service detector module — banner grabbing + nmap -sV."""

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

# Ports that commonly return readable banners
BANNER_PORTS = {21, 22, 23, 25, 80, 110, 143, 443, 445, 8080, 8443}


class ServiceDetectorModule(BaseModule):
    metadata = ModuleMetadata(
        name="service_detector",
        display_name="Service Detector",
        version="1.0.0",
        category=ModuleCategory.SERVICE,
        description=(
            "Identifies services on open ports using async banner grabbing "
            "combined with nmap -sV version detection."
        ),
        author="NetLanVentory",
        requires_root=False,
        options_schema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target CIDR, IP, or comma-separated IPs",
                },
                "ports": {
                    "type": "string",
                    "default": "",
                    "description": "Ports to probe (leave blank to use DB open ports)",
                },
                "banner_timeout": {
                    "type": "number",
                    "default": 3,
                    "description": "Banner grab connection timeout in seconds",
                },
                "use_nmap_version": {
                    "type": "boolean",
                    "default": True,
                    "description": "Also run nmap -sV for deeper version detection",
                },
                "nmap_intensity": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 9,
                    "default": 5,
                    "description": "nmap -sV intensity (0=light, 9=aggressive)",
                },
            },
            "required": ["target"],
        },
    )

    async def run(self, session: AsyncSession, options: dict[str, Any]) -> dict[str, Any]:
        target = options["target"]
        banner_timeout = float(options.get("banner_timeout", 3))
        use_nmap_version = bool(options.get("use_nmap_version", True))
        nmap_intensity = int(options.get("nmap_intensity", 5))

        # Collect IPs + open ports from DB
        assets_data = await self._load_assets_with_ports(session, target)

        if not assets_data:
            return {
                "module": self.metadata.name,
                "status": "success",
                "assets_found": 0,
                "details": {"message": "No assets with open ports found in DB for target"},
            }

        results: list[dict[str, Any]] = []

        for asset, ports in assets_data:
            host_result: dict[str, Any] = {"ip": asset.ip, "services": []}

            # Banner grabbing (async, non-root)
            banner_tasks = [
                self._grab_banner(asset.ip, p.port_number, banner_timeout)
                for p in ports
                if p.port_number in BANNER_PORTS
            ]
            banners = await asyncio.gather(*banner_tasks, return_exceptions=True)
            banner_map = {
                p.port_number: (b if isinstance(b, str) else None)
                for p, b in zip(
                    [p for p in ports if p.port_number in BANNER_PORTS], banners
                )
            }

            # nmap -sV
            nmap_services: dict[int, dict[str, str]] = {}
            if use_nmap_version:
                port_list = ",".join(str(p.port_number) for p in ports)
                nmap_services = await self._nmap_version(
                    asset.ip, port_list, nmap_intensity
                )

            for p in ports:
                banner = banner_map.get(p.port_number)
                nmap_info = nmap_services.get(p.port_number, {})
                service_name = (
                    nmap_info.get("name") or p.service_name or ""
                )
                version = nmap_info.get("version") or nmap_info.get("product") or p.version or ""

                # Persist findings
                p.service_name = service_name or p.service_name
                p.version = version or p.version
                if banner:
                    p.banner = banner[:1000]  # cap banner size

                host_result["services"].append(
                    {
                        "port": p.port_number,
                        "protocol": p.protocol,
                        "service": p.service_name,
                        "version": p.version,
                        "banner_snippet": (banner[:200] if banner else None),
                    }
                )

            results.append(host_result)

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

    # ── Banner grabbing ──────────────────────────────────────────────────────

    @staticmethod
    async def _grab_banner(ip: str, port: int, timeout: float) -> str | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            try:
                # Send a minimal HTTP GET for web ports, otherwise just read
                if port in {80, 8080, 8443, 443}:
                    writer.write(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    await writer.drain()
                banner = await asyncio.wait_for(reader.read(512), timeout=timeout)
                return banner.decode("utf-8", errors="replace").strip()
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        except Exception:
            return None

    # ── nmap -sV ────────────────────────────────────────────────────────────

    @staticmethod
    async def _nmap_version(
        ip: str, ports: str, intensity: int
    ) -> dict[int, dict[str, str]]:
        try:
            import nmap as python_nmap  # type: ignore[import]
        except ImportError:
            return {}

        nm = python_nmap.PortScanner()
        args = f"-sV --version-intensity {intensity} -T4"
        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: nm.scan(hosts=ip, ports=ports, arguments=args),
            )
        except Exception as exc:
            logger.warning("nmap -sV failed", ip=ip, error=str(exc))
            return {}

        services: dict[int, dict[str, str]] = {}
        if ip in nm.all_hosts():
            host = nm[ip]
            for proto in host.all_protocols():
                for pnum, pdata in host[proto].items():
                    services[pnum] = {
                        "name": pdata.get("name", ""),
                        "product": pdata.get("product", ""),
                        "version": pdata.get("version", ""),
                        "extrainfo": pdata.get("extrainfo", ""),
                    }
        return services

    # ── DB helpers ───────────────────────────────────────────────────────────

    @staticmethod
    async def _load_assets_with_ports(
        session: AsyncSession, target: str
    ) -> list[tuple[Asset, list[Port]]]:
        """Load all active assets whose IP falls within target, with open ports."""
        import ipaddress

        try:
            network = ipaddress.ip_network(target, strict=False)
            ip_filter = None  # filter in Python below
        except ValueError:
            network = None

        result = await session.execute(
            select(Asset).where(Asset.is_active.is_(True))
        )
        assets = result.scalars().all()

        data: list[tuple[Asset, list[Port]]] = []
        for asset in assets:
            if not asset.ip:
                continue
            if network:
                try:
                    if ipaddress.ip_address(asset.ip) not in network:
                        continue
                except ValueError:
                    continue
            elif asset.ip != target:
                continue

            port_result = await session.execute(
                select(Port).where(Port.asset_id == asset.id, Port.state == "open")
            )
            ports = list(port_result.scalars().all())
            if ports:
                data.append((asset, ports))

        return data
