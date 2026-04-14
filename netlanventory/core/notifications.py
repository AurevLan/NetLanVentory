"""Notification / webhook dispatch.

Loads active NotificationConfig rows for a given event and POSTs a signed
JSON payload to each configured webhook URL.

Signature: X-NLV-Signature: sha256=<HMAC-SHA256-hex>
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import httpx

from netlanventory.core.database import get_session_factory
from netlanventory.core.logging import get_logger

if TYPE_CHECKING:
    from netlanventory.models.asset import Asset
    from netlanventory.models.asset_cve import AssetCve
    from netlanventory.models.cve import Cve

logger = get_logger(__name__)


def _sign_payload(secret: str, body: bytes) -> str:
    """Return HMAC-SHA256 hex digest of body using secret."""
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


async def send_notification(event: str, payload: dict) -> None:
    """Send webhook notifications for the given event to all enabled configs.

    This function is designed to be called as a fire-and-forget background
    coroutine — failures are logged but do not raise.
    """
    from sqlalchemy import select

    from netlanventory.models.notification_config import NotificationConfig

    factory = get_session_factory()
    try:
        async with factory() as session:
            result = await session.execute(
                select(NotificationConfig).where(NotificationConfig.enabled.is_(True))
            )
            configs = result.scalars().all()
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to load notification configs", error=str(exc))
        return

    if not configs:
        return

    body_dict = {
        "event": event,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    body_bytes = json.dumps(body_dict, default=str).encode()

    async with httpx.AsyncClient(timeout=10) as client:
        for config in configs:
            events = config.events or []
            if event not in events:
                continue
            if not config.url:
                continue

            headers = {
                "Content-Type": "application/json",
                "X-NLV-Event": event,
            }
            if config.secret:
                sig = _sign_payload(config.secret, body_bytes)
                headers["X-NLV-Signature"] = f"sha256={sig}"

            try:
                resp = await client.post(config.url, content=body_bytes, headers=headers)
                logger.info(
                    "Webhook sent",
                    event=event,
                    config_id=str(config.id),
                    status_code=resp.status_code,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "Webhook delivery failed",
                    event=event,
                    config_id=str(config.id),
                    error=str(exc),
                )


async def notify_cve_critical(asset: "Asset", cve: "Cve") -> None:
    """Fire a 'cve_critical' notification event."""
    await send_notification(
        "cve_critical",
        {
            "asset_id": str(asset.id),
            "asset_ip": asset.ip,
            "asset_name": asset.name,
            "cve_id": cve.cve_id,
            "severity": cve.severity,
            "cvss_score": cve.cvss_score,
            "description": (cve.description or "")[:500],
        },
    )


async def notify_sla_breach(asset: "Asset", cve_link: "AssetCve") -> None:
    """Fire a 'sla_breach' notification event."""
    await send_notification(
        "sla_breach",
        {
            "asset_id": str(asset.id),
            "asset_ip": asset.ip,
            "asset_name": asset.name,
            "asset_cve_id": str(cve_link.id),
            "cve_id": str(cve_link.cve_id),
            "sla_deadline": cve_link.sla_deadline.isoformat() if cve_link.sla_deadline else None,
        },
    )


async def notify_critical_cves_for_asset(
    factory,
    asset_id: object,
    source_filter: str | None = None,
    log_label: str = "",
) -> None:
    """Query critical CVEs for an asset and send a notification for each.

    If *source_filter* is given, only CVEs whose source contains that string
    are notified (e.g. ``"nuclei"`` or ``"ssh"``).
    """
    from sqlalchemy import select
    from netlanventory.models.asset import Asset
    from netlanventory.models.asset_cve import AssetCve
    from netlanventory.models.cve import Cve

    try:
        async with factory() as session:
            q = (
                select(AssetCve, Asset, Cve)
                .join(Asset, AssetCve.asset_id == Asset.id)
                .join(Cve, AssetCve.cve_id == Cve.id)
                .where(
                    AssetCve.asset_id == asset_id,
                    Cve.severity == "Critical",
                )
            )
            if source_filter:
                q = q.where(AssetCve.source.contains(source_filter))
            rows = (await session.execute(q)).all()
            for _link, asset, cve in rows:
                await notify_cve_critical(asset, cve)
    except Exception as exc:  # noqa: BLE001
        label = f" ({log_label})" if log_label else ""
        logger.warning(f"Failed to send critical CVE notifications{label}", error=str(exc))


async def notify_port_change(
    asset: "Asset",
    added_ports: list[int],
    removed_ports: list[int],
) -> None:
    """Fire a 'port_change' notification event."""
    await send_notification(
        "port_change",
        {
            "asset_id": str(asset.id),
            "asset_ip": asset.ip,
            "asset_name": asset.name,
            "added_ports": added_ports,
            "removed_ports": removed_ports,
        },
    )


async def broadcast_in_app_event(event_type: str, payload: dict) -> None:
    """Push an event to all connected SSE clients (in-app real-time notification)."""
    try:
        from netlanventory.api.routers.events import broadcast_event
        await broadcast_event(event_type, payload)
    except Exception as exc:  # noqa: BLE001
        logger.debug("SSE broadcast failed", error=str(exc))


async def notify_new_asset_detected(asset: "Asset") -> None:
    """Notify that a new asset was discovered (passive/LDAP/cloud)."""
    payload = {
        "asset_id": str(asset.id),
        "asset_ip": asset.ip,
        "asset_name": asset.name,
        "discovery_source": getattr(asset, "discovery_source", "unknown"),
    }
    await send_notification("new_asset", payload)
    await broadcast_in_app_event("new_asset", {**payload, "level": "info", "message": f"New asset discovered: {asset.ip or asset.name or str(asset.id)[:8]}"})


async def notify_new_critical_asset(asset: "Asset") -> None:
    """Notify that a new high/critical asset was just discovered."""
    payload = {
        "asset_id": str(asset.id),
        "asset_ip": asset.ip,
        "asset_name": asset.name,
        "criticality": asset.criticality,
        "discovery_source": getattr(asset, "discovery_source", "unknown"),
    }
    await send_notification("new_critical_asset", payload)
    await broadcast_in_app_event(
        "notification",
        {
            **payload,
            "level": "critical",
            "message": f"New {asset.criticality} asset discovered: {asset.ip or asset.name or str(asset.id)[:8]}",
        },
    )


async def notify_scan_done(
    scan_id: str,
    target: str,
    status: str,
    modules: list[str],
    assets_found: int = 0,
) -> None:
    """Fire a 'scan_done' notification event."""
    payload = {
        "scan_id": scan_id,
        "target": target,
        "status": status,
        "modules": modules,
        "assets_found": assets_found,
    }
    await send_notification("scan_done", payload)
    await broadcast_in_app_event(
        "notification",
        {
            **payload,
            "level": "info" if status == "completed" else "warning",
            "message": f"Scan {status}: {target} ({', '.join(modules)})",
        },
    )


async def notify_ssh_profile_failed(
    profile_name: str,
    asset_ip: str,
    error: str,
) -> None:
    """Fire an 'ssh_profile_failed' notification when an SSH profile test fails."""
    payload = {
        "profile_name": profile_name,
        "asset_ip": asset_ip,
        "error": error,
    }
    await send_notification("ssh_profile_failed", payload)
    await broadcast_in_app_event(
        "notification",
        {
            **payload,
            "level": "warning",
            "message": f"SSH profile '{profile_name}' failed on {asset_ip}: {error}",
        },
    )


async def notify_ioc_match(
    asset: "Asset",
    ioc_indicator: str,
    ioc_type: str,
    ioc_severity: str,
    ioc_source: str,
    match_type: str,
) -> None:
    """Fire an 'ioc_match' notification when an asset matches a threat IOC."""
    payload = {
        "asset_id": str(asset.id),
        "asset_ip": asset.ip,
        "asset_name": asset.name,
        "ioc_indicator": ioc_indicator,
        "ioc_type": ioc_type,
        "ioc_severity": ioc_severity,
        "ioc_source": ioc_source,
        "match_type": match_type,
    }
    await send_notification("ioc_match", payload)
    await broadcast_in_app_event(
        "notification",
        {
            **payload,
            "level": "critical" if ioc_severity in ("critical", "high") else "warning",
            "message": f"IOC match: {asset.ip or asset.name} matched {ioc_type} indicator '{ioc_indicator}' from {ioc_source}",
        },
    )
