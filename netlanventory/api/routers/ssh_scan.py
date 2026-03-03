"""SSH CVE scan router — trigger and retrieve SSH-based vulnerability scans.

Flow for POST (trigger):
  1. Validate asset has SSH credentials configured
  2. Create SshScanReport (status=pending)
  3. Return 202 immediately
  4. Background task: connect via asyncssh, detect OS, fetch packages,
     lookup CVEs via OSV.dev (+ NVD fallback), persist AssetCve rows.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Annotated

import asyncssh
import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from netlanventory.core.cve_enrichment import enrich_cves
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_current_active_user, get_db
from netlanventory.core.config import get_settings
from netlanventory.core.crypto import decrypt
from netlanventory.core.database import get_session_factory
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve
from netlanventory.models.ssh_scan_report import SshScanReport
from netlanventory.schemas.ssh_scan import SshScanReportOut

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/ssh-scan", tags=["ssh-scan"])

DbDep = Annotated[AsyncSession, Depends(get_db)]

# Max 2 simultaneous SSH connections
_ssh_semaphore: asyncio.Semaphore | None = None


def _get_ssh_semaphore() -> asyncio.Semaphore:
    global _ssh_semaphore
    if _ssh_semaphore is None:
        _ssh_semaphore = asyncio.Semaphore(2)
    return _ssh_semaphore


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", response_model=SshScanReportOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
async def trigger_ssh_scan(
    request: Request,
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DbDep,
    _current_user: Annotated[object, Depends(get_current_active_user)],
) -> SshScanReport:
    """Launch an SSH-based CVE scan against an asset (async, 202 Accepted)."""
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    if not asset.ip:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Asset has no IP address"
        )
    if not asset.ssh_password_enc and not asset.ssh_private_key_enc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No SSH credentials configured for this asset. "
                   "Add a password or private key via the Details tab.",
        )

    report = SshScanReport(asset_id=asset_id, status="pending")
    db.add(report)
    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(_run_ssh_scan, report_id=report.id, asset_id=asset_id)
    logger.info("SSH scan queued", report_id=str(report.id), asset_id=str(asset_id))

    return report


@router.get("", response_model=list[SshScanReportOut])
async def list_ssh_reports(
    asset_id: uuid.UUID,
    db: DbDep,
    _current_user: Annotated[object, Depends(get_current_active_user)],
) -> list[SshScanReport]:
    """List SSH scan reports for an asset (newest first)."""
    result = await db.execute(
        select(SshScanReport)
        .where(SshScanReport.asset_id == asset_id)
        .order_by(SshScanReport.created_at.desc())
    )
    return list(result.scalars().all())


@router.get("/{report_id}", response_model=SshScanReportOut)
async def get_ssh_report(
    asset_id: uuid.UUID,
    report_id: uuid.UUID,
    db: DbDep,
    _current_user: Annotated[object, Depends(get_current_active_user)],
) -> SshScanReport:
    """Get a specific SSH scan report."""
    result = await db.execute(
        select(SshScanReport).where(
            SshScanReport.id == report_id,
            SshScanReport.asset_id == asset_id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


# ── Background scan task ─────────────────────────────────────────────────────


async def _run_ssh_scan(report_id: uuid.UUID, asset_id: uuid.UUID) -> None:
    """Background task: SSH into the asset, detect packages, lookup CVEs."""
    factory = get_session_factory()

    # Phase 1 — SSH connection + CVE persistence (holds the semaphore)
    cve_ids_to_enrich: list[str] = []
    async with _get_ssh_semaphore():
        async with factory() as session:
            report = (
                await session.execute(select(SshScanReport).where(SshScanReport.id == report_id))
            ).scalar_one()
            asset = (
                await session.execute(select(Asset).where(Asset.id == asset_id))
            ).scalar_one()

            report.status = "running"
            await session.flush()

            try:
                ssh_kwargs = _build_ssh_kwargs(asset)
                host = asset.ip
                port = asset.ssh_port or 22
                user = asset.ssh_user or "root"

                async with asyncssh.connect(
                    host,
                    port=port,
                    username=user,
                    known_hosts=None,
                    **ssh_kwargs,
                ) as conn:
                    os_type, ecosystem = await _detect_os(conn)
                    packages = await _get_packages(conn, os_type)

                cve_data = await _lookup_cves_osv(packages, ecosystem)

                settings = get_settings()
                if settings.nvd_api_key:
                    resolved = {p for p, cves in cve_data.items() if cves}
                    unresolved = [p for p in packages if p[0] not in resolved]
                    if unresolved:
                        nvd_data = await _lookup_cves_nvd(unresolved, settings.nvd_api_key)
                        for pkg_name, cves in nvd_data.items():
                            cve_data.setdefault(pkg_name, []).extend(cves)

                cve_count = await _persist_ssh_cves(session, asset_id, packages, cve_data)

                # Collect CVE IDs for enrichment (runs after semaphore release)
                for vuln_list in cve_data.values():
                    for vuln in vuln_list:
                        candidates = (
                            [vuln.get("id", "")]
                            + vuln.get("aliases", [])
                            + vuln.get("upstream", [])
                        )
                        cve_ids_to_enrich.extend(v for v in candidates if v)

                report.status = "completed"
                report.os_type = os_type
                report.packages_found = len(packages)
                report.cves_found = cve_count

            except (asyncssh.DisconnectError, asyncssh.PermissionDenied, OSError) as exc:
                logger.warning("SSH scan failed", asset_id=str(asset_id), error=str(exc))
                report.status = "failed"
                report.error_msg = str(exc)
            except Exception as exc:  # noqa: BLE001
                logger.error("SSH scan unexpected error", asset_id=str(asset_id), error=str(exc))
                report.status = "failed"
                report.error_msg = f"Unexpected error: {exc}"

            await session.commit()
    # Semaphore released — other scans can now start

    # Phase 2 — CVE enrichment (independent session, no semaphore held)
    if cve_ids_to_enrich:
        settings = get_settings()
        async with factory() as session:
            await enrich_cves(session, cve_ids_to_enrich, nvd_api_key=settings.nvd_api_key)
            await session.commit()


def _build_ssh_kwargs(asset: Asset) -> dict:
    """Build asyncssh connect kwargs from decrypted asset credentials."""
    kwargs: dict = {}
    if asset.ssh_password_enc:
        kwargs["password"] = decrypt(asset.ssh_password_enc)
    if asset.ssh_private_key_enc:
        key_data = decrypt(asset.ssh_private_key_enc)
        kwargs["client_keys"] = [asyncssh.import_private_key(key_data)]
    return kwargs


async def _detect_os(conn: asyncssh.SSHClientConnection) -> tuple[str, str]:
    """Return (os_type, osv_ecosystem) by reading /etc/os-release."""
    try:
        result = await conn.run("cat /etc/os-release 2>/dev/null", check=False)
        text = result.stdout or ""
    except Exception:
        return "unknown", "Linux"

    os_id = ""
    version_id = ""
    for line in text.splitlines():
        if line.startswith("ID="):
            os_id = line.split("=", 1)[1].strip().strip('"').lower()
        elif line.startswith("VERSION_ID="):
            version_id = line.split("=", 1)[1].strip().strip('"')

    if os_id in ("debian",):
        major = version_id.split(".")[0] if version_id else ""
        return "debian", f"Debian:{major}" if major else "Debian"
    if os_id in ("ubuntu",):
        return "ubuntu", f"Ubuntu:{version_id}" if version_id else "Ubuntu"
    if os_id in ("alpine",):
        major_minor = ".".join(version_id.split(".")[:2]) if version_id else ""
        return "alpine", f"Alpine:{major_minor}" if major_minor else "Alpine"
    if os_id in ("rhel", "centos", "fedora", "rocky", "almalinux"):
        return "rhel", "Red Hat"

    return "unknown", "Linux"


async def _get_packages(
    conn: asyncssh.SSHClientConnection, os_type: str
) -> list[tuple[str, str]]:
    """Return list of (package_name, version) tuples."""
    if os_type in ("debian", "ubuntu"):
        cmd = "dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null"
        sep = "\t"
    elif os_type == "alpine":
        cmd = "apk info -v 2>/dev/null"
        sep = None  # alpine format: name-version (split on last -)
    elif os_type == "rhel":
        cmd = "rpm -qa --queryformat '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null"
        sep = "\t"
    else:
        return []

    result = await conn.run(cmd, check=False)
    packages: list[tuple[str, str]] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        if sep:
            parts = line.split(sep, 1)
            if len(parts) == 2:
                packages.append((parts[0], parts[1]))
        else:
            # Alpine: last hyphen separates name from version
            idx = line.rfind("-")
            if idx > 0:
                packages.append((line[:idx], line[idx + 1:]))
    return packages


async def _lookup_cves_osv(
    packages: list[tuple[str, str]], ecosystem: str
) -> dict[str, list[dict]]:
    """Query OSV.dev /v1/querybatch for the full package list.

    Returns {package_name: [vuln_dict, ...]}
    """
    if not packages:
        return {}

    results: dict[str, list[dict]] = {}
    batch_size = 1000

    async with httpx.AsyncClient(timeout=30) as client:
        for i in range(0, len(packages), batch_size):
            batch = packages[i : i + batch_size]
            queries = [
                {"package": {"name": name, "version": version, "ecosystem": ecosystem}}
                for name, version in batch
            ]
            try:
                resp = await client.post(
                    "https://api.osv.dev/v1/querybatch",
                    json={"queries": queries},
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                logger.warning("OSV querybatch failed", error=str(exc))
                continue

            for (name, _version), result in zip(batch, data.get("results", [])):
                vulns = result.get("vulns", [])
                if vulns:
                    results[name] = vulns

    return results


async def _lookup_cves_nvd(
    packages: list[tuple[str, str]], api_key: str
) -> dict[str, list[dict]]:
    """Fallback CVE lookup via NVD NIST API for unresolved packages."""
    results: dict[str, list[dict]] = {}
    headers = {"apiKey": api_key} if api_key else {}

    async with httpx.AsyncClient(timeout=30, headers=headers) as client:
        for name, _version in packages[:50]:  # cap to avoid rate limits
            try:
                resp = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"keywordSearch": name, "resultsPerPage": 10},
                )
                resp.raise_for_status()
                items = resp.json().get("vulnerabilities", [])
                if items:
                    results[name] = [
                        {
                            "id": v["cve"]["id"],
                            "summary": (
                                v["cve"]
                                .get("descriptions", [{}])[0]
                                .get("value", "")
                            ),
                        }
                        for v in items
                    ]
            except Exception as exc:
                logger.warning("NVD lookup failed", package=name, error=str(exc))

    return results


async def _persist_ssh_cves(
    session: AsyncSession,
    asset_id: uuid.UUID,
    packages: list[tuple[str, str]],
    cve_data: dict[str, list[dict]],
) -> int:
    """Upsert CVE rows and link them to the asset. Returns count of CVEs linked.

    Each call represents a fresh SSH scan: existing "ssh" source entries for this
    asset are cleared first so the result always reflects the current scan state.
    Multi-source links (e.g. "zap,ssh") have "ssh" removed from their source list
    rather than being deleted outright.
    """
    # ── Clear previous SSH findings for this asset ────────────────────────────
    existing_all = (
        await session.execute(
            select(AssetCve).where(AssetCve.asset_id == asset_id)
        )
    ).scalars().all()
    for link in existing_all:
        sources = [s for s in (link.source or "").split(",") if s and s != "ssh"]
        if not sources:
            await session.delete(link)
        else:
            link.source = ",".join(sources)
    await session.flush()

    version_map = {name: ver for name, ver in packages}
    cve_count = 0
    now = datetime.now(timezone.utc)

    for pkg_name, vulns in cve_data.items():
        pkg_version = version_map.get(pkg_name, "")
        for vuln in vulns:
            # OSV returns {id, aliases, summary, ...}; NVD fallback returns {id, summary}
            cve_id = vuln.get("id", "")
            if not cve_id:
                continue

            # Resolve actual CVE ID (OSV may use GHSA-... or UBUNTU-CVE-... as primary)
            aliases: list[str] = vuln.get("aliases", [])
            upstream: list[str] = vuln.get("upstream", [])
            cve_ids = [cve_id] + aliases + upstream
            real_cve = next((a for a in cve_ids if a.startswith("CVE-")), cve_id)

            # Extract fixed version from OSV affected ranges
            fixed_version: str | None = _osv_fixed_version(vuln, pkg_version)

            # Upsert Cve row — create or enrich existing
            new_severity = _osv_severity(vuln)
            new_description = vuln.get("summary", "") or ""
            cve_row = (
                await session.execute(select(Cve).where(Cve.cve_id == real_cve))
            ).scalar_one_or_none()
            if not cve_row:
                cve_row = Cve(
                    cve_id=real_cve,
                    description=new_description,
                    severity=new_severity,
                    cvss_score=None,
                )
                session.add(cve_row)
                await session.flush()
            else:
                # Enrich fields that were previously unknown or empty
                if (not cve_row.severity or cve_row.severity == "Unknown") and new_severity != "Unknown":
                    cve_row.severity = new_severity
                if not cve_row.description and new_description:
                    cve_row.description = new_description

            # Upsert AssetCve link — append "ssh" to sources if already exists
            existing = (
                await session.execute(
                    select(AssetCve).where(
                        AssetCve.asset_id == asset_id,
                        AssetCve.cve_id == cve_row.id,
                    )
                )
            ).scalar_one_or_none()
            if existing:
                sources = [s for s in (existing.source or "").split(",") if s]
                if "ssh" not in sources:
                    existing.source = ",".join(sources + ["ssh"])
                    cve_count += 1
                # Enrich link fields that were previously missing
                if not existing.fixed_version and fixed_version:
                    existing.fixed_version = fixed_version
                if not existing.package_name and pkg_name:
                    existing.package_name = pkg_name
                if not existing.package_version and pkg_version:
                    existing.package_version = pkg_version
            else:
                link = AssetCve(
                    asset_id=asset_id,
                    cve_id=cve_row.id,
                    source="ssh",
                    package_name=pkg_name,
                    package_version=pkg_version,
                    fixed_version=fixed_version,
                    discovered_at=now,
                )
                session.add(link)
                cve_count += 1

    await session.flush()
    return cve_count


def _osv_fixed_version(vuln: dict, installed_version: str) -> str | None:
    """Extract the fixed version from OSV affected ranges for the installed package version.

    OSV structure: affected[].ranges[].events = [{"introduced": "0"}, {"fixed": "x.y.z"}]
    We return the first fixed version we find across all affected entries.
    """
    for affected in (vuln.get("affected") or []):
        for rng in (affected.get("ranges") or []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            for event in (rng.get("events") or []):
                fv = event.get("fixed")
                if fv:
                    return fv
    return None


def _osv_severity(vuln: dict) -> str:
    """Map OSV severity to our internal scale (Critical/High/Medium/Low/Unknown).

    OSV severity entries come in two forms:
    - Text label: {"type": "Ubuntu", "score": "medium"} — used by distro advisories
    - CVSS vector: {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..."} — not a number
    We prefer text labels; CVSS vectors require a full parser so we skip them.
    """
    _TEXT_MAP = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "negligible": "Low",
        "unimportant": "Low",
    }
    for entry in (vuln.get("severity") or []):
        score = entry.get("score", "").lower()
        if score in _TEXT_MAP:
            return _TEXT_MAP[score]
    return "Unknown"
