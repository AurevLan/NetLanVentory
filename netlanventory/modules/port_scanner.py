"""Port scanner module — python-nmap SYN/connect scan."""

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


class PortScannerModule(BaseModule):
    metadata = ModuleMetadata(
        name="port_scanner",
        display_name="Port Scanner",
        version="1.0.0",
        category=ModuleCategory.PORT_SCAN,
        description=(
            "Performs TCP SYN scan (requires root) or TCP connect scan on discovered hosts. "
            "Uses python-nmap wrapper for reliable multi-host scanning."
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
                "ports": {
                    "type": "string",
                    "default": "21-23,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,6379,8080,8443,8888,9200,27017",
                    "description": "Port range / list (nmap format)",
                },
                "scan_type": {
                    "type": "string",
                    "enum": ["syn", "connect"],
                    "default": "syn",
                    "description": "SYN (stealth, root required) or Connect scan",
                },
                "timing": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 5,
                    "default": 4,
                    "description": "nmap timing template T0–T5",
                },
            },
            "required": ["target"],
        },
    )

    async def run(self, session: AsyncSession, options: dict[str, Any]) -> dict[str, Any]:
        target = options["target"]
        ports = options.get(
            "ports",
            "21-23,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,6379,8080,8443,8888,9200,27017",
        )
        scan_type = options.get("scan_type", "syn")
        timing = int(options.get("timing", 4))

        scan_flag = "-sS" if scan_type == "syn" else "-sT"
        nmap_args = f"{scan_flag} -T{timing} --open"

        logger.info("Starting port scan", target=target, ports=ports, args=nmap_args)

        try:
            import nmap as python_nmap  # type: ignore[import]
        except ImportError:
            return {
                "module": self.metadata.name,
                "status": "error",
                "assets_found": 0,
                "details": {"error": "python-nmap is not installed"},
            }

        nm = python_nmap.PortScanner()

        try:
            # Run blocking nmap in a thread pool
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: nm.scan(hosts=target, ports=ports, arguments=nmap_args),
            )
        except Exception as exc:
            logger.error("nmap scan failed", error=str(exc))
            return {
                "module": self.metadata.name,
                "status": "error",
                "assets_found": 0,
                "details": {"error": str(exc)},
            }

        hosts_data: list[dict[str, Any]] = []
        total_ports = 0

        for host_ip in nm.all_hosts():
            host_info = nm[host_ip]
            open_ports: list[dict[str, Any]] = []

            for proto in host_info.all_protocols():
                for pnum in sorted(host_info[proto].keys()):
                    pdata = host_info[proto][pnum]
                    if pdata["state"] == "open":
                        open_ports.append(
                            {
                                "port": pnum,
                                "protocol": proto,
                                "state": pdata["state"],
                                "service": pdata.get("name", ""),
                                "version": pdata.get("version", ""),
                            }
                        )

            hosts_data.append({"ip": host_ip, "ports": open_ports})
            total_ports += len(open_ports)

            await self._persist_ports(session, host_ip, open_ports)

        return {
            "module": self.metadata.name,
            "status": "success",
            "assets_found": len(hosts_data),
            "details": {
                "target": target,
                "scan_type": scan_type,
                "hosts_scanned": len(hosts_data),
                "total_open_ports": total_ports,
                "hosts": hosts_data,
            },
        }

    @staticmethod
    async def _persist_ports(
        session: AsyncSession, ip: str, open_ports: list[dict[str, Any]]
    ) -> None:
        """Create/update Port records for an asset, ignoring duplicates."""
        # Find asset by IP
        result = await session.execute(select(Asset).where(Asset.ip == ip))
        asset = result.scalar_one_or_none()

        if asset is None:
            # Create a minimal asset record if not found (port scan ran before discovery)
            asset = Asset(ip=ip, is_active=True)
            session.add(asset)
            await session.flush()  # populate asset.id

        for p in open_ports:
            # Upsert port: update service/version if exists
            result2 = await session.execute(
                select(Port).where(
                    Port.asset_id == asset.id,
                    Port.port_number == p["port"],
                    Port.protocol == p["protocol"],
                )
            )
            existing = result2.scalar_one_or_none()
            if existing:
                existing.state = p["state"]
                existing.service_name = p.get("service") or existing.service_name
                existing.version = p.get("version") or existing.version
            else:
                session.add(
                    Port(
                        asset_id=asset.id,
                        port_number=p["port"],
                        protocol=p["protocol"],
                        state=p["state"],
                        service_name=p.get("service"),
                        version=p.get("version"),
                    )
                )
