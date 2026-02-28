"""Admin router — OIDC provider config and auth settings (admin only)."""

from __future__ import annotations

from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.api.dependencies import get_db, require_admin
from netlanventory.core.config import get_settings
from netlanventory.core.logging import get_logger
from netlanventory.models.global_settings import GlobalSettings
from netlanventory.models.oidc_provider import OidcProvider
from netlanventory.schemas.admin import (
    AuthSettingsOut,
    GlobalSettingsOut,
    GlobalSettingsUpdate,
    OidcProviderOut,
    OidcProviderUpdate,
    OidcTestResult,
)

router = APIRouter(prefix="/admin", tags=["admin"])
logger = get_logger(__name__)

DbDep = Annotated[AsyncSession, Depends(get_db)]
AdminDep = Annotated[object, Depends(require_admin)]


# ── Auth settings (read-only from env) ───────────────────────────────────────

@router.get("/auth-settings", response_model=AuthSettingsOut,
            dependencies=[Depends(require_admin)])
async def get_auth_settings() -> AuthSettingsOut:
    s = get_settings()
    return AuthSettingsOut(
        jwt_algorithm=s.jwt_algorithm,
        jwt_access_token_expire_minutes=s.jwt_access_token_expire_minutes,
        oidc_enabled_in_env=s.oidc_enabled,
    )


# ── OIDC provider config ──────────────────────────────────────────────────────

async def _get_or_create_provider(db: AsyncSession) -> OidcProvider:
    result = await db.execute(select(OidcProvider).limit(1))
    provider = result.scalar_one_or_none()
    if not provider:
        provider = OidcProvider()
        db.add(provider)
        await db.flush()
        await db.refresh(provider)
    return provider


@router.get("/oidc", response_model=OidcProviderOut,
            dependencies=[Depends(require_admin)])
async def get_oidc_config(db: DbDep) -> OidcProviderOut:
    provider = await _get_or_create_provider(db)
    return OidcProviderOut.from_orm_masked(provider)


@router.put("/oidc", response_model=OidcProviderOut,
            dependencies=[Depends(require_admin)])
async def update_oidc_config(payload: OidcProviderUpdate, db: DbDep) -> OidcProviderOut:
    provider = await _get_or_create_provider(db)

    provider.name = payload.name
    provider.enabled = payload.enabled
    provider.issuer_url = payload.issuer_url
    provider.client_id = payload.client_id
    provider.scopes = payload.scopes
    provider.auto_create_users = payload.auto_create_users
    provider.default_role = payload.default_role

    # None = keep existing; explicit value (incl. "") = overwrite
    if payload.client_secret is not None:
        provider.client_secret = payload.client_secret or None

    await db.flush()
    await db.refresh(provider)
    logger.info("OIDC config updated", issuer=provider.issuer_url, enabled=provider.enabled)
    return OidcProviderOut.from_orm_masked(provider)


@router.post("/oidc/test", response_model=OidcTestResult,
             dependencies=[Depends(require_admin)])
async def test_oidc_connection(db: DbDep) -> OidcTestResult:
    """Fetch the OIDC discovery document to verify the provider is reachable."""
    provider = await _get_or_create_provider(db)

    if not provider.issuer_url:
        return OidcTestResult(success=False, message="Issuer URL is not configured.")

    issuer = provider.issuer_url.rstrip("/")
    discovery_url = f"{issuer}/.well-known/openid-configuration"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(discovery_url)
            resp.raise_for_status()
            doc = resp.json()
    except httpx.TimeoutException:
        return OidcTestResult(
            success=False,
            message=f"Connection timed out fetching {discovery_url}",
            discovery_url=discovery_url,
        )
    except Exception as exc:
        return OidcTestResult(
            success=False,
            message=str(exc),
            discovery_url=discovery_url,
        )

    endpoints = {k: doc.get(k) for k in (
        "authorization_endpoint", "token_endpoint",
        "userinfo_endpoint", "jwks_uri",
    )}
    return OidcTestResult(
        success=True,
        message=f"Provider '{doc.get('issuer', issuer)}' is reachable.",
        discovery_url=discovery_url,
        endpoints=endpoints,
    )


# ── Global ZAP auto-scan settings ────────────────────────────────────────────

async def _get_or_create_global_settings(db: AsyncSession) -> GlobalSettings:
    result = await db.execute(select(GlobalSettings).where(GlobalSettings.id == 1))
    settings_row = result.scalar_one_or_none()
    if not settings_row:
        settings_row = GlobalSettings(id=1)
        db.add(settings_row)
        await db.flush()
        await db.refresh(settings_row)
    return settings_row


@router.get("/zap-settings", response_model=GlobalSettingsOut,
            dependencies=[Depends(require_admin)])
async def get_zap_settings(db: DbDep) -> GlobalSettingsOut:
    """Return global ZAP auto-scan configuration."""
    row = await _get_or_create_global_settings(db)
    return GlobalSettingsOut.model_validate(row)


@router.put("/zap-settings", response_model=GlobalSettingsOut,
            dependencies=[Depends(require_admin)])
async def update_zap_settings(payload: GlobalSettingsUpdate, db: DbDep) -> GlobalSettingsOut:
    """Update global ZAP auto-scan configuration."""
    row = await _get_or_create_global_settings(db)
    row.zap_auto_scan_enabled = payload.zap_auto_scan_enabled
    row.zap_scan_interval_minutes = payload.zap_scan_interval_minutes
    await db.flush()
    await db.refresh(row)
    logger.info(
        "ZAP auto-scan settings updated",
        enabled=row.zap_auto_scan_enabled,
        interval=row.zap_scan_interval_minutes,
    )
    return GlobalSettingsOut.model_validate(row)
