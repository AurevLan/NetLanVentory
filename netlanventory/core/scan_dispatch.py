"""Dispatch a single (asset, module) priority into a real scan.

Used by the smart-scheduler drain loop in ``core.scheduler`` when the
``smart_scheduler_queue_enabled`` setting is on (innovation #5). Each handler
builds the module's report row, launches the existing background runner
fire-and-forget, and returns ``True``. A handler returns ``False`` when the
asset is not eligible for that module (no SSH credentials, no open web port,
no IP, tool not installed) so the caller can *defer* the priority row instead
of resetting its cooldown — an ineligible asset must not hot-loop the queue.

The report row is created in the *caller's* session; the caller commits before
the runner opens its own session to fetch the row by id. This mirrors exactly
how the fixed-interval loops in ``core.scheduler`` launch scans.

Runners and report models are imported lazily inside each handler to avoid
import cycles (API routers import ``core``; ``core.scheduler`` imports this).
"""

from __future__ import annotations

import asyncio

from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset

logger = get_logger(__name__)

# Local copy of the web-port sets (kept here to avoid a scheduler↔dispatch
# import cycle). Used only to pick a single primary URL for header audits.
_WEB_PORTS_HTTPS = {443, 8443, 4443}
_WEB_PORTS_HTTP = {80, 8080, 8000, 3000, 8888}
_WEB_PORTS_ALL = _WEB_PORTS_HTTP | _WEB_PORTS_HTTPS


def _primary_web_url(asset: Asset) -> str | None:
    """Build one web URL (IP + first open web port, HTTPS preferred).

    Returns ``None`` when the asset has no IP or no open web port.
    """
    if not asset.ip:
        return None
    open_web = [
        p
        for p in (asset.ports or [])
        if p.state == "open" and p.port_number in _WEB_PORTS_ALL
    ]
    if not open_web:
        return None
    # Prefer HTTPS ports (sort puts HTTPS first: False < True).
    open_web.sort(key=lambda p: p.port_number not in _WEB_PORTS_HTTPS)
    port = open_web[0]
    scheme = "https" if port.port_number in _WEB_PORTS_HTTPS else "http"
    if (scheme == "http" and port.port_number == 80) or (
        scheme == "https" and port.port_number == 443
    ):
        return f"{scheme}://{asset.ip}"
    return f"{scheme}://{asset.ip}:{port.port_number}"


async def _dispatch_ssh_scan(session: AsyncSession, asset: Asset) -> bool:
    if not asset.has_ssh_credentials or not asset.ip:
        return False
    from netlanventory.api.routers.ssh_scan import _run_ssh_scan
    from netlanventory.models.ssh_scan_report import SshScanReport

    report = SshScanReport(asset_id=asset.id, status="pending")
    session.add(report)
    await session.flush()
    await session.refresh(report)
    asyncio.create_task(
        _run_ssh_scan(report_id=report.id, asset_id=asset.id),
        name=f"smart-ssh-{asset.id}-{report.id}",
    )
    return True


async def _dispatch_trivy_docker(session: AsyncSession, asset: Asset) -> bool:
    if not asset.has_ssh_credentials or not asset.ip:
        return False
    import shutil

    from netlanventory.api.routers.trivy_docker_scan import (
        TRIVY_BINARY,
        _run_trivy_docker_scan,
    )

    if not shutil.which(TRIVY_BINARY):
        return False
    from netlanventory.models.trivy_docker_report import TrivyDockerReport

    report = TrivyDockerReport(asset_id=asset.id, status="pending")
    session.add(report)
    await session.flush()
    await session.refresh(report)
    asyncio.create_task(
        _run_trivy_docker_scan(report_id=report.id, asset_id=asset.id),
        name=f"smart-trivy-{asset.id}-{report.id}",
    )
    return True


async def _dispatch_nuclei(session: AsyncSession, asset: Asset) -> bool:
    if not asset.ip:
        return False
    from netlanventory.api.routers.nuclei import (
        _build_nuclei_targets_and_tags,
        _run_nuclei_scan,
    )
    from netlanventory.models.nuclei_report import NucleiReport

    targets, tags = _build_nuclei_targets_and_tags(asset)
    if not targets:
        return False
    report = NucleiReport(asset_id=asset.id, status="pending", targets=targets, tags=tags)
    session.add(report)
    await session.flush()
    await session.refresh(report)
    asyncio.create_task(
        _run_nuclei_scan(
            report_id=report.id, asset_id=asset.id, targets=targets, tags=tags
        ),
        name=f"smart-nuclei-{asset.id}-{report.id}",
    )
    return True


async def _dispatch_headers_audit(session: AsyncSession, asset: Asset) -> bool:
    url = _primary_web_url(asset)
    if not url:
        return False
    from netlanventory.api.routers.headers_audit import _run_headers_audit
    from netlanventory.models.headers_audit_report import HeadersAuditReport

    report = HeadersAuditReport(asset_id=asset.id, status="pending", target_url=url)
    session.add(report)
    await session.flush()
    await session.refresh(report)
    asyncio.create_task(
        _run_headers_audit(
            report_id=report.id,
            asset_id=asset.id,
            target_url=url,
            active_zap_scan=False,
        ),
        name=f"smart-headers-{asset.id}-{report.id}",
    )
    return True


# module name → dispatcher. Keys must match the modules recomputed by
# core.scheduler._maybe_recompute_scan_priorities.
_DISPATCHERS = {
    "ssh_scan": _dispatch_ssh_scan,
    "trivy_docker": _dispatch_trivy_docker,
    "nuclei": _dispatch_nuclei,
    "headers_audit": _dispatch_headers_audit,
}

SUPPORTED_MODULES = frozenset(_DISPATCHERS)


async def dispatch_module(session: AsyncSession, asset: Asset, module: str) -> bool:
    """Launch ``module``'s scan for ``asset``.

    Returns ``True`` if a scan was launched, ``False`` if the asset is not
    eligible for this module (caller should defer, not reset, the priority).
    """
    handler = _DISPATCHERS.get(module)
    if handler is None:
        logger.warning("smart_dispatch_unknown_module", module=module)
        return False
    return await handler(session, asset)
