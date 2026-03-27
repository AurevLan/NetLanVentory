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
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import actor_from_user, get_current_active_user, get_db
from netlanventory.core.audit import log_action
from netlanventory.core.config import get_settings
from netlanventory.core.crypto import decrypt
from netlanventory.core.database import get_session_factory
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.core.quota import check_and_increment_quota
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve
from netlanventory.models.ssh_scan_report import SshScanReport
from netlanventory.schemas.ssh_scan import SshScanDiffOut, SshScanReportOut

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
    # Quota check
    quota_ok = await check_and_increment_quota(
        db,
        user_id=_current_user.id,
        quota_limit=getattr(_current_user, "scan_quota_per_day", None),
    )
    if not quota_ok:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Daily scan quota exceeded",
        )

    result = await db.execute(
        select(Asset).where(Asset.id == asset_id).options(selectinload(Asset.ssh_profile))
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    if not asset.ip:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Asset has no IP address"
        )
    if not asset.has_ssh_credentials:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No SSH credentials configured for this asset. "
                   "Add a password or private key, or link an SSH profile.",
        )

    report = SshScanReport(asset_id=asset_id, status="pending")
    db.add(report)
    await db.flush()

    actor = actor_from_user(_current_user)
    await log_action(
        db,
        user=actor,
        action="ssh_scan.trigger",
        resource_type="asset",
        resource_id=str(asset_id),
    )

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


# NOTE: diff endpoint uses a separate prefix to avoid conflicts with /{report_id}
_diff_router = APIRouter(prefix="/assets/{asset_id}/ssh-scans", tags=["ssh-scan"])


@_diff_router.get("", response_model=list[SshScanReportOut])
async def list_ssh_scan_history(
    asset_id: uuid.UUID,
    db: DbDep,
    _current_user: Annotated[object, Depends(get_current_active_user)],
) -> list[SshScanReport]:
    """List all SSH scan reports for an asset (newest first)."""
    result = await db.execute(
        select(SshScanReport)
        .where(SshScanReport.asset_id == asset_id)
        .order_by(SshScanReport.created_at.desc())
    )
    return list(result.scalars().all())


@_diff_router.get("/diff", response_model=SshScanDiffOut)
async def diff_ssh_scans(
    asset_id: uuid.UUID,
    scan_a: uuid.UUID,
    scan_b: uuid.UUID,
    db: DbDep,
    _current_user: Annotated[object, Depends(get_current_active_user)],
) -> dict:
    """Compare two SSH scan reports for an asset.

    Returns CVEs that are new in B (not in A), resolved in A (not in B),
    and common to both. Uses discovered_at timestamps to approximate
    which CVEs were present at each scan point.
    """
    # Validate both reports belong to this asset
    res_a = await db.execute(
        select(SshScanReport).where(
            SshScanReport.id == scan_a,
            SshScanReport.asset_id == asset_id,
        )
    )
    report_a = res_a.scalar_one_or_none()
    if not report_a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan A not found")

    res_b = await db.execute(
        select(SshScanReport).where(
            SshScanReport.id == scan_b,
            SshScanReport.asset_id == asset_id,
        )
    )
    report_b = res_b.scalar_one_or_none()
    if not report_b:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan B not found")

    # Ensure A is the earlier scan, B is the later scan
    time_a = report_a.created_at
    time_b = report_b.created_at
    if time_a > time_b:
        report_a, report_b = report_b, report_a
        time_a, time_b = time_b, time_a

    # Load all SSH CVEs for this asset with their cve data
    cves_result = await db.execute(
        select(AssetCve)
        .where(AssetCve.asset_id == asset_id)
        .options(selectinload(AssetCve.cve))
    )
    all_cves = cves_result.scalars().all()
    ssh_cves = [c for c in all_cves if "ssh" in (c.source or "")]

    def _cve_item(link: AssetCve) -> dict:
        cve = link.cve
        return {
            "cve_id": cve.cve_id if cve else str(link.cve_id),
            "severity": cve.severity if cve else None,
            "cvss_score": cve.cvss_score if cve else None,
            "package_name": link.package_name,
            "package_version": link.package_version,
        }

    # CVEs discovered before or at scan_a's time = present in A
    # CVEs discovered after scan_a but before or at scan_b's time = new in B
    # CVEs in A that are no longer present = resolved (approximated: not in current set)
    # Since we can't truly reconstruct historical state without per-report storage,
    # we use discovered_at to approximate.

    tz_a = time_a.replace(tzinfo=timezone.utc) if time_a.tzinfo is None else time_a
    tz_b = time_b.replace(tzinfo=timezone.utc) if time_b.tzinfo is None else time_b

    cves_in_a: list[AssetCve] = []
    cves_new_in_b: list[AssetCve] = []

    for link in ssh_cves:
        disc = link.discovered_at
        if disc.tzinfo is None:
            disc = disc.replace(tzinfo=timezone.utc)
        if disc <= tz_a:
            cves_in_a.append(link)
        elif disc <= tz_b:
            cves_new_in_b.append(link)
        # CVEs discovered after B are not in either scan

    # Currently present CVE IDs (to detect resolved ones)
    current_cve_ids = {link.cve_id for link in ssh_cves}
    # Resolved: in A but not currently present
    resolved = [link for link in cves_in_a if link.cve_id not in current_cve_ids]
    # Common: in A and still present
    common = [link for link in cves_in_a if link.cve_id in current_cve_ids]

    return {
        "new_cves": [_cve_item(c) for c in cves_new_in_b],
        "resolved_cves": [_cve_item(c) for c in resolved],
        "common_cves": [_cve_item(c) for c in common],
    }


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
                await session.execute(
                    select(Asset).where(Asset.id == asset_id).options(selectinload(Asset.ssh_profile))
                )
            ).scalar_one()

            report.status = "running"
            await session.flush()

            try:
                ssh_kwargs = _build_ssh_kwargs(asset)
                host = asset.ip
                port = asset.ssh_port or (asset.ssh_profile.ssh_port if asset.ssh_profile else None) or 22
                user = asset.ssh_user or (asset.ssh_profile.ssh_user if asset.ssh_profile else None) or "root"

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

            # Update ssh_last_auto_scan_at if ssh_auto_scan_enabled
            if asset.ssh_auto_scan_enabled:
                asset.ssh_last_auto_scan_at = datetime.now(timezone.utc)

            await session.commit()
    # Semaphore released — other scans can now start

    # Phase 2 — CVE enrichment (independent session, no semaphore held)
    if cve_ids_to_enrich:
        settings = get_settings()
        async with factory() as session:
            await enrich_cves(session, cve_ids_to_enrich, nvd_api_key=settings.nvd_api_key)
            await session.commit()

    # Phase 3 — Fire critical CVE notifications
    from netlanventory.core.notifications import notify_critical_cves_for_asset
    await notify_critical_cves_for_asset(factory, asset_id, log_label="ssh")


def _build_ssh_kwargs(asset: Asset) -> dict:
    """Build asyncssh connect kwargs from decrypted credentials.

    Per-asset credentials take full priority over the linked profile. Only when
    both ssh_password_enc and ssh_private_key_enc are absent does the profile
    provide the credentials.
    """
    kwargs: dict = {}

    # Resolve credential source: per-asset first, profile as fallback
    password_enc = asset.ssh_password_enc
    key_enc = asset.ssh_private_key_enc
    if not password_enc and not key_enc and asset.ssh_profile:
        password_enc = asset.ssh_profile.ssh_password_enc
        key_enc = asset.ssh_profile.ssh_private_key_enc

    if password_enc:
        kwargs["password"] = decrypt(password_enc)
    if key_enc:
        key_data = decrypt(key_enc)
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

            for (name, version), result in zip(batch, data.get("results", [])):
                vulns = result.get("vulns", [])
                # Only keep vulns that have version-specific data for this package.
                # OSV sometimes returns historical entries with no affected ranges
                # (empty affected list), which match on package name alone and cause
                # false positives on up-to-date systems.
                filtered = [v for v in vulns if _osv_vuln_is_version_specific(v, name, version)]
                if filtered:
                    results[name] = filtered

    return results


def _osv_vuln_is_version_specific(vuln: dict, pkg_name: str, installed_version: str) -> bool:
    """Return True only if OSV has concrete version data showing this package version is affected.

    Rejects entries that have no affected list (matched by name alone) or that have
    affected entries without version ranges or explicit version lists.
    """
    affected = vuln.get("affected") or []
    if not affected:
        return False  # No version data at all — historical ghost entry

    for a in affected:
        # Check explicit versions list first (fastest path)
        explicit_versions: list[str] = a.get("versions") or []
        if installed_version in explicit_versions:
            return True

        # Check ECOSYSTEM or SEMVER ranges with events
        for rng in (a.get("ranges") or []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            events = rng.get("events") or []
            fixed = next((e.get("fixed") for e in events if e.get("fixed")), None)
            if fixed:
                # Range is concrete: there is a known fixed version.
                # The installed version is affected if it's < fixed.
                return not _is_version_fixed(installed_version, fixed)
            # Range has introduced/limit but no fixed — still affected (no patch)
            introduced = next((e.get("introduced") for e in events if e.get("introduced")), None)
            if introduced:
                return True  # Vulnerable with no fix yet

    return False  # No usable version data found


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
    # Load all existing AssetCve links for this asset.
    existing_all = (
        await session.execute(
            select(AssetCve).where(AssetCve.asset_id == asset_id)
        )
    ).scalars().all()
    # Collect IDs that need deletion (multi-source links only lose "ssh").
    # Use a bulk DELETE to avoid triggering lazy-load of back_populates on delete.
    ids_to_delete: list[uuid.UUID] = []
    for link in existing_all:
        sources = [s for s in (link.source or "").split(",") if s and s != "ssh"]
        if not sources:
            ids_to_delete.append(link.id)
        else:
            link.source = ",".join(sources)
    if ids_to_delete:
        await session.execute(
            sa_delete(AssetCve).where(AssetCve.id.in_(ids_to_delete))
        )
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

            # Resolve actual CVE ID (OSV may use GHSA-... or DEBIAN-CVE-... as primary)
            aliases: list[str] = vuln.get("aliases", [])
            upstream: list[str] = vuln.get("upstream", [])
            cve_ids = [cve_id] + aliases + upstream
            real_cve = next((a for a in cve_ids if a.startswith("CVE-")), None)
            if real_cve is None:
                # Distro-prefixed IDs like DEBIAN-CVE-2016-1585 → CVE-2016-1585
                import re as _re
                for candidate in cve_ids:
                    m = _re.search(r"CVE-\d{4}-\d+", candidate)
                    if m:
                        real_cve = m.group(0)
                        break
                else:
                    real_cve = cve_id  # Keep original as last resort

            # Extract fixed version from OSV affected ranges
            fixed_version: str | None = _osv_fixed_version(vuln, pkg_version)

            # Skip if the package is already at or past the fixed version (patched)
            if fixed_version and pkg_version and _is_version_fixed(pkg_version, fixed_version):
                logger.debug(
                    "Skipping patched CVE",
                    cve=real_cve,
                    package=pkg_name,
                    installed=pkg_version,
                    fixed=fixed_version,
                )
                continue

            # Upsert Cve row — create or enrich existing
            new_severity = _osv_severity(vuln)
            new_score = _osv_cvss_score(vuln)
            new_description = vuln.get("summary", "") or ""
            cve_row = (
                await session.execute(select(Cve).where(Cve.cve_id == real_cve))
            ).scalar_one_or_none()
            if not cve_row:
                cve_row = Cve(
                    cve_id=real_cve,
                    description=new_description,
                    severity=new_severity,
                    cvss_score=new_score,
                )
                session.add(cve_row)
                await session.flush()
            else:
                # Enrich fields that were previously unknown or empty
                if (not cve_row.severity or cve_row.severity == "Unknown") and new_severity != "Unknown":
                    cve_row.severity = new_severity
                if not cve_row.description and new_description:
                    cve_row.description = new_description
                if cve_row.cvss_score is None and new_score is not None:
                    cve_row.cvss_score = new_score

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


def _is_version_fixed(installed: str, fixed: str) -> bool:
    """Return True if the installed version is >= fixed version (i.e. already patched).

    Uses dpkg version comparison for Debian-style versions (handles epochs and ~).
    Falls back to naive string comparison for other ecosystems.
    """
    try:
        import subprocess
        result = subprocess.run(
            ["dpkg", "--compare-versions", installed, "ge", fixed],
            capture_output=True,
        )
        return result.returncode == 0
    except Exception:
        pass
    # Naive fallback: strip epoch and compare
    def _strip_epoch(v: str) -> str:
        return v.split(":", 1)[-1] if ":" in v else v
    try:
        from packaging.version import Version
        return Version(_strip_epoch(installed)) >= Version(_strip_epoch(fixed))
    except Exception:
        return False


def _cvss3_base_score(vector: str) -> float | None:
    """Compute the CVSS v3.x base score from a vector string.

    Implements the CVSS 3.1 base score formula from the FIRST specification.
    Returns None if the vector cannot be parsed.
    """
    import math
    _AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    _AC  = {"L": 0.77, "H": 0.44}
    _UI  = {"N": 0.85, "R": 0.62}
    _CIA = {"N": 0.00, "L": 0.22, "H": 0.56}
    _PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
    _PR_C = {"N": 0.85, "L": 0.50, "H": 0.50}
    try:
        # Strip "CVSS:3.x/" prefix
        parts = vector.split("/")
        metrics: dict[str, str] = {}
        for part in parts[1:]:
            if ":" in part:
                k, v = part.split(":", 1)
                metrics[k] = v
        scope = metrics.get("S", "U")
        av = _AV[metrics["AV"]]
        ac = _AC[metrics["AC"]]
        pr = (_PR_C if scope == "C" else _PR_U)[metrics["PR"]]
        ui = _UI[metrics["UI"]]
        c  = _CIA[metrics["C"]]
        i  = _CIA[metrics["I"]]
        a  = _CIA[metrics["A"]]
        iss = 1 - (1 - c) * (1 - i) * (1 - a)
        if iss == 0:
            return 0.0
        if scope == "U":
            isc = 6.42 * iss
        else:
            isc = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        esc = 8.22 * av * ac * pr * ui
        raw = isc + esc if scope == "U" else 1.08 * (isc + esc)
        return math.ceil(min(raw, 10.0) * 10) / 10
    except (KeyError, IndexError, ValueError, ZeroDivisionError):
        return None


def _osv_cvss_score(vuln: dict) -> float | None:
    """Extract a numeric CVSS base score from an OSV vulnerability entry."""
    for entry in (vuln.get("severity") or []):
        s = entry.get("score", "")
        if s.startswith("CVSS:"):
            score = _cvss3_base_score(s)
            if score is not None:
                return score
    return None


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Unknown"


def _osv_severity(vuln: dict) -> str:
    """Map OSV severity to our internal scale (Critical/High/Medium/Low/Unknown).

    Priority:
    1. Text labels (distro advisories): {"type": "Ubuntu", "score": "medium"}
    2. CVSS vector strings: {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..."}
       → compute base score, then map to severity bucket
    """
    _TEXT_MAP = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "negligible": "Low",
        "unimportant": "Low",
    }
    cvss_vector: str | None = None
    for entry in (vuln.get("severity") or []):
        score_str = entry.get("score", "")
        # Text label
        if score_str.lower() in _TEXT_MAP:
            return _TEXT_MAP[score_str.lower()]
        # CVSS vector
        if score_str.startswith("CVSS:"):
            cvss_vector = score_str
    if cvss_vector:
        score = _cvss3_base_score(cvss_vector)
        if score is not None:
            return _severity_from_score(score)
    return "Unknown"
