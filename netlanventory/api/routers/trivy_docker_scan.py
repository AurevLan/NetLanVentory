"""Trivy Docker scan router — scan container images on a remote host via SSH socket forwarding.

Flow for POST (trigger):
  1. Validate asset has SSH credentials (per-asset or profile)
  2. Create TrivyDockerReport (status=pending) → return 202
  3. Background task:
     a. SSH connect with existing credentials
     b. Check Docker is available + list running containers
     c. Forward /var/run/docker.sock over SSH to a local temp socket
     d. Run `trivy image --docker-host unix://SOCK --format json` for each unique image
     e. Parse Trivy JSON, persist CVEs in AssetCve (source="trivy")
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Annotated

import asyncssh
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netlanventory.api.dependencies import actor_from_user, get_current_active_user, get_db
from netlanventory.core.audit import log_action
from netlanventory.core.crypto import decrypt
from netlanventory.core.cve_enrichment import enrich_cves
from netlanventory.core.database import get_session_factory
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import get_logger
from netlanventory.core.quota import check_and_increment_quota
from netlanventory.models.asset import Asset
from netlanventory.models.asset_cve import AssetCve
from netlanventory.models.cve import Cve
from netlanventory.models.trivy_docker_report import TrivyDockerReport
from netlanventory.schemas.trivy_docker import TrivyDockerReportOut

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/trivy-docker", tags=["trivy-docker"])

DbDep = Annotated[AsyncSession, Depends(get_db)]

# Max 1 concurrent Trivy scan (each scan may run several `trivy image` calls)
_trivy_semaphore: asyncio.Semaphore | None = None

TRIVY_BINARY = "trivy"
TRIVY_TIMEOUT = 300  # seconds per image


def _get_trivy_semaphore() -> asyncio.Semaphore:
    global _trivy_semaphore
    if _trivy_semaphore is None:
        _trivy_semaphore = asyncio.Semaphore(1)
    return _trivy_semaphore


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", response_model=TrivyDockerReportOut, status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
async def trigger_trivy_docker_scan(
    request: Request,
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DbDep,
    _current_user: Annotated[object, Depends(get_current_active_user)],
) -> TrivyDockerReport:
    """Trigger a Trivy container scan via SSH Docker socket forwarding."""
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

    if not shutil.which(TRIVY_BINARY):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Trivy binary not found: {TRIVY_BINARY!r}. "
                   "Ensure it is installed in the container.",
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
            detail="No SSH credentials configured. Add credentials or link an SSH profile.",
        )

    report = TrivyDockerReport(asset_id=asset_id, status="pending")
    db.add(report)
    await db.flush()

    actor = actor_from_user(_current_user)
    await log_action(
        db,
        user=actor,
        action="trivy_docker_scan.trigger",
        resource_type="asset",
        resource_id=str(asset_id),
    )

    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(_run_trivy_docker_scan, report_id=report.id, asset_id=asset_id)
    logger.info("Trivy Docker scan queued", report_id=str(report.id), asset_id=str(asset_id))

    return report


@router.get("", response_model=list[TrivyDockerReportOut])
async def list_trivy_docker_reports(
    asset_id: uuid.UUID,
    db: DbDep,
    _current_user: Annotated[object, Depends(get_current_active_user)],
) -> list[TrivyDockerReport]:
    """List Trivy Docker scan reports for an asset (newest first)."""
    result = await db.execute(
        select(TrivyDockerReport)
        .where(TrivyDockerReport.asset_id == asset_id)
        .order_by(TrivyDockerReport.created_at.desc())
    )
    return list(result.scalars().all())


@router.get("/{report_id}", response_model=TrivyDockerReportOut)
async def get_trivy_docker_report(
    asset_id: uuid.UUID,
    report_id: uuid.UUID,
    db: DbDep,
    _current_user: Annotated[object, Depends(get_current_active_user)],
) -> TrivyDockerReport:
    """Get a specific Trivy Docker scan report."""
    result = await db.execute(
        select(TrivyDockerReport).where(
            TrivyDockerReport.id == report_id,
            TrivyDockerReport.asset_id == asset_id,
        )
    )
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


# ── Background task ───────────────────────────────────────────────────────────


async def _run_trivy_docker_scan(report_id: uuid.UUID, asset_id: uuid.UUID) -> None:
    """Connect via SSH, forward the Docker socket, scan each image with Trivy."""
    factory = get_session_factory()
    cve_ids_to_enrich: list[str] = []

    async with _get_trivy_semaphore():
        async with factory() as session:
            report = await _fetch_report(session, report_id)
            if not report:
                return

            asset = (
                await session.execute(
                    select(Asset)
                    .where(Asset.id == asset_id)
                    .options(selectinload(Asset.ssh_profile))
                )
            ).scalar_one()

            report.status = "running"
            await session.flush()

            local_sock_path: str | None = None

            try:
                # ── Resolve SSH credentials ────────────────────────────────
                ssh_kwargs = _build_ssh_kwargs(asset)
                host = asset.ip
                port = (
                    asset.ssh_port
                    or (asset.ssh_profile.ssh_port if asset.ssh_profile else None)
                    or 22
                )
                user = (
                    asset.ssh_user
                    or (asset.ssh_profile.ssh_user if asset.ssh_profile else None)
                    or "root"
                )

                async with asyncssh.connect(
                    host,
                    port=port,
                    username=user,
                    known_hosts=None,
                    **ssh_kwargs,
                ) as conn:

                    # ── Check Docker availability ──────────────────────────
                    docker_check = await conn.run(
                        "docker info --format '{{.ServerVersion}}' 2>/dev/null", check=False
                    )
                    if docker_check.returncode != 0 or not docker_check.stdout.strip():
                        raise RuntimeError(
                            "Docker n'est pas disponible ou accessible sur cette machine. "
                            "Vérifiez que Docker est installé et que l'utilisateur SSH "
                            "a accès au socket Docker (groupe docker ou root)."
                        )

                    # ── List running containers ────────────────────────────
                    containers_result = await conn.run(
                        "docker ps --format '{{.Image}}' 2>/dev/null", check=False
                    )
                    raw_images = [
                        line.strip()
                        for line in (containers_result.stdout or "").splitlines()
                        if line.strip()
                    ]
                    if not raw_images:
                        report.status = "completed"
                        report.containers_found = 0
                        report.images_scanned = 0
                        report.cves_found = 0
                        report.error_msg = "Aucun conteneur en cours d'exécution."
                        await session.commit()
                        return

                    # Deduplicate images preserving order
                    unique_images: list[str] = list(dict.fromkeys(raw_images))
                    report.containers_found = len(raw_images)
                    await session.flush()

                    logger.info(
                        "Trivy scan: containers found",
                        report_id=str(report_id),
                        containers=len(raw_images),
                        unique_images=len(unique_images),
                    )

                    # ── Forward remote Docker socket to local temp path ────
                    sock_fd, local_sock_path = tempfile.mkstemp(
                        prefix="trivy-docker-", suffix=".sock"
                    )
                    os.close(sock_fd)
                    os.unlink(local_sock_path)  # asyncssh needs the path free to create it

                    listener = await conn.forward_local_path(
                        local_sock_path, "/var/run/docker.sock"
                    )

                    try:
                        # ── Clear existing trivy findings ONCE before scanning ──
                        existing_links = (
                            await session.execute(
                                select(AssetCve).where(AssetCve.asset_id == asset_id)
                            )
                        ).scalars().all()
                        for link in existing_links:
                            sources = [s for s in (link.source or "").split(",") if s and s != "trivy"]
                            if not sources:
                                await session.delete(link)
                            else:
                                link.source = ",".join(sources)
                        await session.flush()
                        # Expire identity map so deleted objects are gone from session cache
                        session.expire_all()

                        # ── Run Trivy per unique image ─────────────────────
                        total_cve_count = 0
                        images_scanned = 0
                        # Track CVE rows created in this scan to avoid duplicate queries
                        cve_row_cache: dict[str, object] = {}

                        for image in unique_images:
                            cve_count, new_cve_ids = await _scan_image_with_trivy(
                                session, asset_id, image, local_sock_path, cve_row_cache
                            )
                            total_cve_count += cve_count
                            images_scanned += 1
                            cve_ids_to_enrich.extend(new_cve_ids)

                        report.status = "completed"
                        report.images_scanned = images_scanned
                        report.cves_found = total_cve_count

                    finally:
                        listener.close()

            except (asyncssh.DisconnectError, asyncssh.PermissionDenied, OSError) as exc:
                logger.warning(
                    "Trivy SSH connection failed", asset_id=str(asset_id), error=str(exc)
                )
                report.status = "failed"
                report.error_msg = str(exc)
            except RuntimeError as exc:
                logger.warning("Trivy scan error", asset_id=str(asset_id), error=str(exc))
                report.status = "failed"
                report.error_msg = str(exc)
            except Exception as exc:
                logger.error(
                    "Trivy scan unexpected error", asset_id=str(asset_id), error=str(exc)
                )
                report.status = "failed"
                report.error_msg = f"Unexpected error: {exc}"
            finally:
                if local_sock_path and os.path.exists(local_sock_path):
                    try:
                        os.unlink(local_sock_path)
                    except OSError:
                        pass

            # Update trivy_last_auto_scan_at if trivy_auto_scan_enabled
            if asset.trivy_auto_scan_enabled:
                from datetime import datetime, timezone as _tz
                asset.trivy_last_auto_scan_at = datetime.now(_tz.utc)

            await session.commit()

    # Phase 2 — CVE enrichment (outside semaphore)
    if cve_ids_to_enrich:
        from netlanventory.core.config import get_settings
        settings = get_settings()
        async with factory() as session:
            await enrich_cves(
                session, list(set(cve_ids_to_enrich)), nvd_api_key=settings.nvd_api_key
            )
            await session.commit()


async def _scan_image_with_trivy(
    session: AsyncSession,
    asset_id: uuid.UUID,
    image: str,
    sock_path: str,
    cve_row_cache: dict | None = None,
) -> tuple[int, list[str]]:
    """Run `trivy image` against a single image via the forwarded Docker socket.

    Returns (cve_count, list_of_cve_ids_for_enrichment).
    """
    # Validate Docker image name to prevent command injection
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]*(?::[a-zA-Z0-9._-]+)?$", image):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Docker image name",
        )

    cmd = [
        TRIVY_BINARY,
        "image",
        "--docker-host", f"unix://{sock_path}",
        "--format", "json",
        "--quiet",
        "--no-progress",
        "--scanners", "vuln",
        image,
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=TRIVY_TIMEOUT
            )
        except TimeoutError:
            proc.kill()
            await proc.communicate()
            logger.warning("Trivy image scan timed out", image=image)
            return 0, []

        if not stdout_bytes:
            return 0, []

        try:
            data = json.loads(stdout_bytes.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            logger.warning("Trivy JSON parse error", image=image)
            return 0, []

    except Exception as exc:
        logger.warning("Trivy subprocess error", image=image, error=str(exc))
        return 0, []

    return await _persist_trivy_cves(session, asset_id, image, data, cve_row_cache or {})


async def _persist_trivy_cves(
    session: AsyncSession,
    asset_id: uuid.UUID,
    image: str,
    trivy_data: dict,
    cve_row_cache: dict,
) -> tuple[int, list[str]]:
    """Parse Trivy JSON output and upsert CVE rows + AssetCve links.

    The caller is responsible for clearing existing trivy entries ONCE before
    calling this function for the first image. This function should NOT clear
    entries itself — doing so per-image causes SQLAlchemy identity-map conflicts
    when the same CVE appears across multiple images.

    cve_row_cache is a dict keyed by cve_id string, mapping to (Cve, AssetCve|None)
    to avoid redundant DB queries across images.

    Returns (cve_count, cve_ids_for_enrichment).
    """
    cve_count = 0
    cve_ids_to_enrich: list[str] = []
    now = datetime.now(timezone.utc)

    for result_block in trivy_data.get("Results") or []:
        for vuln in result_block.get("Vulnerabilities") or []:
            cve_id = vuln.get("VulnerabilityID", "")
            if not cve_id:
                continue

            pkg_name = vuln.get("PkgName", "")
            installed_version = vuln.get("InstalledVersion", "")
            fixed_version = vuln.get("FixedVersion") or None
            severity = _map_severity(vuln.get("Severity", ""))
            description = vuln.get("Title") or vuln.get("Description") or ""
            cvss_score: float | None = _extract_cvss(vuln)

            # Upsert Cve row — use cache to avoid redundant queries per image
            if cve_id in cve_row_cache:
                cve_row = cve_row_cache[cve_id]
            else:
                cve_row = (
                    await session.execute(select(Cve).where(Cve.cve_id == cve_id))
                ).scalars().first()
                if not cve_row:
                    cve_row = Cve(
                        cve_id=cve_id,
                        severity=severity,
                        description=description,
                        cvss_score=cvss_score,
                    )
                    session.add(cve_row)
                    await session.flush()
                else:
                    if (not cve_row.severity or cve_row.severity == "Unknown") and severity != "Unknown":
                        cve_row.severity = severity
                    if not cve_row.description and description:
                        cve_row.description = description
                    if cve_row.cvss_score is None and cvss_score is not None:
                        cve_row.cvss_score = cvss_score
                cve_row_cache[cve_id] = cve_row

            # Upsert AssetCve link — use cache key to avoid duplicate creation
            link_cache_key = f"{asset_id}:{cve_row.id}"
            if link_cache_key in cve_row_cache:
                existing_link = cve_row_cache[link_cache_key]
            else:
                existing_link = (
                    await session.execute(
                        select(AssetCve).where(
                            AssetCve.asset_id == asset_id,
                            AssetCve.cve_id == cve_row.id,
                        )
                    )
                ).scalars().first()
                cve_row_cache[link_cache_key] = existing_link

            if existing_link:
                sources = [s for s in (existing_link.source or "").split(",") if s]
                if "trivy" not in sources:
                    existing_link.source = ",".join(sources + ["trivy"])
                    cve_count += 1
                if not existing_link.fixed_version and fixed_version:
                    existing_link.fixed_version = fixed_version
                if not existing_link.package_name and pkg_name:
                    existing_link.package_name = pkg_name
                if not existing_link.package_version and installed_version:
                    existing_link.package_version = installed_version
            else:
                link = AssetCve(
                    asset_id=asset_id,
                    cve_id=cve_row.id,
                    source="trivy",
                    package_name=f"{image}:{pkg_name}" if pkg_name else image,
                    package_version=installed_version,
                    fixed_version=fixed_version,
                    discovered_at=now,
                )
                session.add(link)
                await session.flush()
                cve_row_cache[link_cache_key] = link
                cve_count += 1

            if cve_id.startswith("CVE-"):
                cve_ids_to_enrich.append(cve_id)

    await session.flush()
    return cve_count, cve_ids_to_enrich


# ── Helpers ───────────────────────────────────────────────────────────────────


def _build_ssh_kwargs(asset: Asset) -> dict:
    """Build asyncssh connect kwargs — per-asset creds take priority over profile."""
    kwargs: dict = {}
    password_enc = asset.ssh_password_enc
    key_enc = asset.ssh_private_key_enc
    if not password_enc and not key_enc and asset.ssh_profile:
        password_enc = asset.ssh_profile.ssh_password_enc
        key_enc = asset.ssh_profile.ssh_private_key_enc
    if password_enc:
        kwargs["password"] = decrypt(password_enc)
    if key_enc:
        kwargs["client_keys"] = [asyncssh.import_private_key(decrypt(key_enc))]
    return kwargs


def _map_severity(raw: str) -> str:
    return {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "NEGLIGIBLE": "Low",
        "UNKNOWN": "Unknown",
    }.get(raw.upper(), "Unknown")


def _extract_cvss(vuln: dict) -> float | None:
    """Extract the highest CVSS score from Trivy vulnerability data."""
    try:
        cvss = vuln.get("CVSS") or {}
        scores = [
            v.get("V3Score") or v.get("V2Score")
            for v in cvss.values()
            if isinstance(v, dict)
        ]
        valid = [float(s) for s in scores if s is not None]
        return max(valid) if valid else None
    except (TypeError, ValueError):
        return None


async def _fetch_report(
    session: AsyncSession, report_id: uuid.UUID
) -> TrivyDockerReport | None:
    result = await session.execute(
        select(TrivyDockerReport).where(TrivyDockerReport.id == report_id)
    )
    return result.scalar_one_or_none()
