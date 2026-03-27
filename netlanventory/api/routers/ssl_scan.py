"""SSL/TLS scan router — inspect certificates and TLS configuration of assets."""

from __future__ import annotations

import ssl
import socket
import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_current_active_user, get_db
from netlanventory.core.database import get_session_factory
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset
from netlanventory.models.ssl_scan_report import SslScanReport

logger = get_logger(__name__)

router = APIRouter(prefix="/assets/{asset_id}/ssl-scan", tags=["ssl-scan"])
_expiring_router = APIRouter(tags=["ssl-scan"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
AuthDep = Annotated[object, Depends(get_current_active_user)]


# ── Pydantic schemas ──────────────────────────────────────────────────────────


class SslScanReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    asset_id: uuid.UUID
    host: str | None
    port: int
    status: str | None
    subject: str | None
    issuer: str | None
    valid_from: datetime | None
    valid_to: datetime | None
    days_remaining: int | None
    protocol_version: str | None
    cipher_suite: str | None
    issues: list | None
    raw_data: dict | None
    created_at: datetime


# ── SSL inspection logic (stdlib only) ───────────────────────────────────────


def _inspect_certificate(host: str, port: int) -> dict:
    """Connect via SSL/TLS to host:port and return inspection data.

    Uses only Python stdlib (ssl, socket). Returns a dict with all fields
    or raises on connection errors.
    """
    ctx = ssl.create_default_context()
    # Allow self-signed certs to gather info even if invalid
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    issues: list[str] = []

    with socket.create_connection((host, port), timeout=10) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert(binary_form=False) or {}
            cipher_info = ssock.cipher()  # (name, protocol, bits)
            protocol = ssock.version() or ""

    # Parse subject / issuer
    def _parse_dn(dn_tuples) -> str:
        if not dn_tuples:
            return ""
        parts = []
        for rdn in dn_tuples:
            for k, v in rdn:
                parts.append(f"{k}={v}")
        return ", ".join(parts)

    subject = _parse_dn(cert.get("subject", ()))
    issuer = _parse_dn(cert.get("issuer", ()))

    # Parse validity dates (format: 'Jan  1 00:00:00 2024 GMT')
    def _parse_cert_date(s: str) -> datetime | None:
        for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
            try:
                return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None

    valid_from = _parse_cert_date(cert.get("notBefore", ""))
    valid_to = _parse_cert_date(cert.get("notAfter", ""))

    now = datetime.now(timezone.utc)
    days_remaining: int | None = None
    if valid_to:
        delta = valid_to - now
        days_remaining = delta.days

    # Determine status
    scan_status = "valid"
    if valid_to and valid_to < now:
        scan_status = "expired"
        issues.append("Certificate has expired")
    elif days_remaining is not None and days_remaining <= 30:
        scan_status = "expiring"
        issues.append(f"Certificate expires in {days_remaining} days")

    # Protocol checks
    deprecated_protocols = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLS 1", "TLS 1.1"}
    proto_clean = protocol.replace("v", " ") if protocol else ""
    if any(p in protocol for p in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")):
        issues.append(f"Deprecated protocol in use: {protocol}")

    # Weak cipher checks
    cipher_name = cipher_info[0] if cipher_info else ""
    cipher_bits = cipher_info[2] if cipher_info else 0
    if cipher_bits and cipher_bits < 128:
        issues.append(f"Weak cipher key length: {cipher_bits} bits")
    weak_cipher_keywords = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5")
    for kw in weak_cipher_keywords:
        if kw in cipher_name.upper():
            issues.append(f"Weak cipher suite: {cipher_name}")
            break

    # Verify hostname
    try:
        ctx2 = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as s2:
            with ctx2.wrap_socket(s2, server_hostname=host):
                pass  # succeeded — cert is valid for this hostname
    except ssl.SSLCertVerificationError as e:
        issues.append(f"Certificate validation failed: {e.reason}")
        if scan_status == "valid":
            scan_status = "invalid"

    raw_data = {
        "subject_raw": cert.get("subject"),
        "issuer_raw": cert.get("issuer"),
        "san": cert.get("subjectAltName"),
        "serial_number": cert.get("serialNumber"),
        "version": cert.get("version"),
        "cipher": cipher_info,
    }

    return {
        "status": scan_status,
        "subject": subject,
        "issuer": issuer,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "days_remaining": days_remaining,
        "protocol_version": protocol,
        "cipher_suite": cipher_name,
        "issues": issues,
        "raw_data": raw_data,
    }


# ── Background task ───────────────────────────────────────────────────────────


async def _run_ssl_scan(report_id: uuid.UUID, asset_id: uuid.UUID, host: str, port: int) -> None:
    """Background task: perform SSL inspection and persist results."""
    import asyncio

    factory = get_session_factory()
    async with factory() as session:
        report = (
            await session.execute(
                select(SslScanReport).where(SslScanReport.id == report_id)
            )
        ).scalar_one_or_none()
        if not report:
            return

        try:
            # Run blocking SSL inspection in a thread pool
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, _inspect_certificate, host, port)
            report.status = result["status"]
            report.subject = result["subject"]
            report.issuer = result["issuer"]
            report.valid_from = result["valid_from"]
            report.valid_to = result["valid_to"]
            report.days_remaining = result["days_remaining"]
            report.protocol_version = result["protocol_version"]
            report.cipher_suite = result["cipher_suite"]
            report.issues = result["issues"]
            report.raw_data = result["raw_data"]
        except (OSError, ssl.SSLError, socket.timeout, ConnectionRefusedError) as exc:
            report.status = "error"
            report.issues = [str(exc)]
            logger.warning("SSL scan failed", host=host, port=port, error=str(exc))
        except Exception as exc:  # noqa: BLE001
            report.status = "error"
            report.issues = [f"Unexpected error: {exc}"]
            logger.error("SSL scan unexpected error", host=host, port=port, error=str(exc))

        await session.commit()


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.post("", response_model=SslScanReportOut, status_code=status.HTTP_202_ACCEPTED)
async def trigger_ssl_scan(
    asset_id: uuid.UUID,
    background_tasks: BackgroundTasks,
    db: DbDep,
    _auth: AuthDep,
    port: int = Query(default=443, ge=1, le=65535),
) -> SslScanReport:
    """Launch an SSL/TLS certificate inspection for an asset (async, 202 Accepted)."""
    asset = (
        await db.execute(select(Asset).where(Asset.id == asset_id))
    ).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    host = asset.hostname or asset.ip
    if not host:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Asset has neither hostname nor IP address",
        )

    report = SslScanReport(asset_id=asset_id, host=host, port=port, status="pending")
    db.add(report)
    await db.flush()
    await db.commit()
    await db.refresh(report)

    background_tasks.add_task(
        _run_ssl_scan, report_id=report.id, asset_id=asset_id, host=host, port=port
    )
    logger.info("SSL scan queued", report_id=str(report.id), host=host, port=port)
    return report


@router.get("", response_model=list[SslScanReportOut])
async def list_ssl_reports(
    asset_id: uuid.UUID,
    db: DbDep,
    _auth: AuthDep,
) -> list[SslScanReport]:
    """List SSL scan reports for an asset (newest first)."""
    result = await db.execute(
        select(SslScanReport)
        .where(SslScanReport.asset_id == asset_id)
        .order_by(SslScanReport.created_at.desc())
    )
    return list(result.scalars().all())


@router.get("/{report_id}", response_model=SslScanReportOut)
async def get_ssl_report(
    asset_id: uuid.UUID,
    report_id: uuid.UUID,
    db: DbDep,
    _auth: AuthDep,
) -> SslScanReport:
    """Get a specific SSL scan report."""
    report = (
        await db.execute(
            select(SslScanReport).where(
                SslScanReport.id == report_id,
                SslScanReport.asset_id == asset_id,
            )
        )
    ).scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    return report


@_expiring_router.get("/ssl/expiring", response_model=list[SslScanReportOut])
async def list_expiring_certs(
    db: DbDep,
    _auth: AuthDep,
    days: int = Query(default=30, ge=1, le=365),
) -> list[SslScanReport]:
    """List the most recent SSL report per asset where the cert expires within N days."""
    from sqlalchemy import func as sqlfunc, and_

    # Get the latest report per asset
    subq = (
        select(
            SslScanReport.asset_id,
            sqlfunc.max(SslScanReport.created_at).label("latest"),
        )
        .group_by(SslScanReport.asset_id)
        .subquery()
    )
    result = await db.execute(
        select(SslScanReport)
        .join(
            subq,
            and_(
                SslScanReport.asset_id == subq.c.asset_id,
                SslScanReport.created_at == subq.c.latest,
            ),
        )
        .where(SslScanReport.days_remaining.isnot(None))
        .where(SslScanReport.days_remaining <= days)
        .order_by(SslScanReport.days_remaining)
    )
    return list(result.scalars().all())
