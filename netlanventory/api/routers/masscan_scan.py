"""Masscan fast port scanner router — agentless network reconnaissance.

Masscan can scan millions of hosts per second, making it ideal for large
network ranges (/16+) where nmap would be too slow.

100% agentless — runs locally, scans remote network ports.
Requires the `masscan` binary on the NetLanVentory server (and root/CAP_NET_RAW).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import shutil
import uuid
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_current_active_user, get_db
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.port import Port

logger = get_logger(__name__)

router = APIRouter(prefix="/masscan", tags=["masscan"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
UserDep = Annotated[object, Depends(get_current_active_user)]

MASSCAN_BINARY = "masscan"
MASSCAN_TIMEOUT = 300  # 5 minutes default


def _validate_masscan_target(target: str) -> None:
    """Reject any target that is not a comma-separated list of IPs/CIDRs.

    Refuses hostnames (masscan would resolve them, opening DNS-based SSRF),
    refuses ranges with non-numeric chars, and refuses targets pointing at
    loopback/link-local. Public ranges and RFC1918 are allowed.
    """
    if not target or len(target) > 1024:
        raise HTTPException(status_code=400, detail="Invalid target length")
    parts = [p.strip() for p in target.split(",") if p.strip()]
    if not parts:
        raise HTTPException(status_code=400, detail="Empty target")
    for part in parts:
        try:
            net = ipaddress.ip_network(part, strict=False)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid target '{part}': must be IP or CIDR",
            ) from exc
        if net.is_loopback or net.is_link_local or net.is_multicast or net.is_reserved:
            raise HTTPException(
                status_code=400,
                detail=f"Refusing forbidden range '{part}' (loopback/link-local/multicast/reserved)",
            )


def _validate_masscan_ports(ports: str) -> None:
    """Reject port strings that contain anything other than digits, comma, dash."""
    if not ports or len(ports) > 512:
        raise HTTPException(status_code=400, detail="Invalid ports length")
    allowed = set("0123456789,-")
    if any(c not in allowed for c in ports):
        raise HTTPException(status_code=400, detail="Invalid ports format")


class MasscanTriggerOut(BaseModel):
    status: str
    message: str
    target: str
    ports: str
    rate: int


class MasscanResultOut(BaseModel):
    target: str
    hosts_found: int
    ports_found: int
    new_assets: int
    scan_duration_seconds: float | None = None


@router.post("", response_model=MasscanTriggerOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("3/minute")
async def trigger_masscan(
    request: Request,
    target: str,
    background_tasks: BackgroundTasks,
    db: DbDep,
    _user: UserDep,
    ports: str = Query(
        default="21-23,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,6379,8080,8443,8888,9200,27017",
        description="Port range (masscan format)",
    ),
    rate: int = Query(default=10000, ge=100, le=1000000, description="Packets per second"),
) -> MasscanTriggerOut:
    """Launch a masscan fast port scan. Runs locally — agentless.

    Masscan is ideal for scanning large CIDR ranges (/16+) quickly.
    Discovered hosts and ports are upserted into the asset/port database.
    """
    if not shutil.which(MASSCAN_BINARY):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="masscan binary not found. Install with: apt install masscan",
        )

    _validate_masscan_target(target)
    _validate_masscan_ports(ports)

    background_tasks.add_task(_run_masscan, target=target, ports=ports, rate=rate)
    return MasscanTriggerOut(
        status="pending",
        message="Masscan scan queued",
        target=target,
        ports=ports,
        rate=rate,
    )


async def _run_masscan(target: str, ports: str, rate: int) -> None:
    """Run masscan and upsert discovered hosts/ports."""
    from netlanventory.core.database import get_session_factory

    start = datetime.now(timezone.utc)

    cmd = [
        MASSCAN_BINARY,
        target,
        "-p", ports,
        "--rate", str(rate),
        "--open",
        "-oJ", "/dev/stdout",  # JSON to stdout
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=MASSCAN_TIMEOUT
            )
        except TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.warning("Masscan timed out", target=target)
            return
    except Exception as exc:
        logger.error("Masscan subprocess error", target=target, error=str(exc))
        return

    # Parse masscan JSON output
    # Masscan outputs one JSON object per line (NDJSON-like), wrapped in [ ]
    hosts: dict[str, list[dict]] = {}  # ip -> [{port, proto}]

    if stdout_bytes:
        raw = stdout_bytes.decode("utf-8", errors="replace").strip()
        # Masscan JSON: array of objects, but may have trailing comma issues
        # Clean up: remove trailing commas before ]
        raw = raw.rstrip().rstrip(",")
        if not raw.startswith("["):
            raw = "[" + raw + "]"

        try:
            entries = json.loads(raw)
            for entry in entries:
                ip = entry.get("ip", "")
                if not ip:
                    continue
                for port_info in entry.get("ports", []):
                    port_num = port_info.get("port")
                    proto = port_info.get("proto", "tcp")
                    port_status = port_info.get("status", "open")
                    if port_num and port_status == "open":
                        hosts.setdefault(ip, []).append({
                            "port": port_num,
                            "protocol": proto,
                            "state": "open",
                        })
        except json.JSONDecodeError as exc:
            logger.warning("Masscan JSON parse error", error=str(exc))

    elapsed = (datetime.now(timezone.utc) - start).total_seconds()

    # Upsert into database
    factory = get_session_factory()
    new_assets = 0
    total_ports = sum(len(p) for p in hosts.values())

    async with factory() as session:
        for ip, port_list in hosts.items():
            # Find or create asset
            asset = (await session.execute(
                select(Asset).where(Asset.ip == ip)
            )).scalar_one_or_none()

            if not asset:
                asset = Asset(ip=ip, is_active=True, discovery_source="masscan")
                session.add(asset)
                await session.flush()
                new_assets += 1

            # Update last_seen
            asset.last_seen = datetime.now(timezone.utc)
            asset.is_active = True

            # Upsert ports
            for p in port_list:
                existing = (await session.execute(
                    select(Port).where(
                        Port.asset_id == asset.id,
                        Port.port_number == p["port"],
                        Port.protocol == p["protocol"],
                    )
                )).scalar_one_or_none()

                if existing:
                    existing.state = p["state"]
                else:
                    session.add(Port(
                        asset_id=asset.id,
                        port_number=p["port"],
                        protocol=p["protocol"],
                        state=p["state"],
                    ))

        await session.commit()

    logger.info(
        "Masscan complete",
        target=target,
        hosts=len(hosts),
        ports=total_ports,
        new_assets=new_assets,
        duration=round(elapsed, 1),
    )
