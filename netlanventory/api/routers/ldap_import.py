"""LDAP/AD import router — import Active Directory computers as assets."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db
from netlanventory.core.config import get_settings
from netlanventory.core.logging import get_logger
from netlanventory.models.asset import Asset

try:
    from ldap3 import ALL, SUBTREE, Connection, Server
    from ldap3.core.exceptions import LDAPException
    _ldap3_available = True
except ImportError:
    _ldap3_available = False

logger = get_logger(__name__)
router = APIRouter(prefix="/ldap", tags=["ldap"])

DbDep = Annotated[AsyncSession, Depends(get_db)]


class LdapTestResult(BaseModel):
    success: bool
    message: str
    server: str | None = None
    base_dn: str | None = None


class LdapImportResult(BaseModel):
    imported: int
    updated: int
    skipped: int
    errors: list[str]


def _get_ldap_connection():
    """Return an ldap3 Connection or raise HTTPException."""
    if not _ldap3_available:
        raise HTTPException(status_code=501, detail="ldap3 not installed. Run: pip install netlanventory[ldap]")

    settings = get_settings()
    if not settings.ldap_url:
        raise HTTPException(status_code=400, detail="LDAP_URL not configured")

    try:
        server = Server(settings.ldap_url, get_info=ALL)
        conn = Connection(
            server,
            user=settings.ldap_bind_dn,
            password=settings.ldap_bind_password,
            auto_bind=True,
        )
        return conn, server
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"LDAP connection failed: {exc}") from exc


@router.get("/test", response_model=LdapTestResult)
async def test_ldap_connection() -> LdapTestResult:
    """Test LDAP/AD connectivity with the configured credentials."""
    if not _ldap3_available:
        return LdapTestResult(success=False, message="ldap3 not installed")

    settings = get_settings()
    if not settings.ldap_url:
        return LdapTestResult(success=False, message="LDAP_URL not configured")

    try:
        conn, server = _get_ldap_connection()
        conn.unbind()
        return LdapTestResult(
            success=True,
            message="Connection successful",
            server=settings.ldap_url,
            base_dn=settings.ldap_base_dn,
        )
    except HTTPException as exc:
        return LdapTestResult(success=False, message=exc.detail)


@router.post("/import", response_model=LdapImportResult)
async def import_from_ldap(db: DbDep) -> LdapImportResult:
    """Import active computer accounts from Active Directory."""
    conn, _ = _get_ldap_connection()
    settings = get_settings()

    if not settings.ldap_base_dn:
        raise HTTPException(status_code=400, detail="LDAP_BASE_DN not configured")

    # LDAP filter: active computer objects only
    ldap_filter = "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

    try:
        conn.search(
            search_base=settings.ldap_base_dn,
            search_filter=ldap_filter,
            search_scope=SUBTREE,
            attributes=["dNSHostName", "cn", "operatingSystem", "lastLogonTimestamp", "ipv4Address"],
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"LDAP search failed: {exc}") from exc
    finally:
        conn.unbind()

    entries = conn.entries
    imported = 0
    updated = 0
    skipped = 0
    errors: list[str] = []

    for entry in entries:
        try:
            hostname = str(entry.dNSHostName) if entry.dNSHostName else None
            cn = str(entry.cn) if entry.cn else None
            os_info = str(entry.operatingSystem) if hasattr(entry, "operatingSystem") and entry.operatingSystem else None

            if not hostname and not cn:
                skipped += 1
                continue

            # Check existing asset
            existing = None
            if hostname:
                result = await db.execute(select(Asset).where(Asset.hostname == hostname))
                existing = result.scalar_one_or_none()

            if existing:
                existing.name = existing.name or cn
                if os_info and not existing.os_name:
                    existing.os_name = os_info
                await db.flush()
                updated += 1
            else:
                asset = Asset(
                    hostname=hostname,
                    name=cn,
                    os_name=os_info,
                    discovery_source="ldap",
                    criticality="medium",
                    is_active=True,
                )
                db.add(asset)
                await db.flush()
                imported += 1

        except Exception as exc:  # noqa: BLE001
            errors.append(f"Error processing {entry.cn}: {exc}")
            logger.warning("LDAP import entry error", entry=str(entry.cn), error=str(exc))

    await db.commit()
    logger.info("LDAP import completed", imported=imported, updated=updated, skipped=skipped)

    return LdapImportResult(imported=imported, updated=updated, skipped=skipped, errors=errors[:20])
