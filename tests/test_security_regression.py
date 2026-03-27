"""Comprehensive security regression tests for the v0.10.0 audit.

Covers: security headers, authentication enforcement, input validation,
password strength, config security, JWT token security, and crypto helpers.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import jwt as pyjwt
import pytest

from netlanventory.core.auth import (
    create_access_token,
    decode_access_token,
    validate_password_strength,
)
from netlanventory.core.config import Settings
from netlanventory.core.crypto import decrypt, encrypt

# Re-use the shared UNKNOWN_UUID from conftest
UNKNOWN_UUID = "00000000-0000-0000-0000-000000000000"


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  1. Security Headers                                                       ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


@pytest.mark.asyncio
async def test_csp_header_present(client):
    """Content-Security-Policy header contains a per-request nonce."""
    r = await client.get("/api/v1/assets")
    csp = r.headers.get("content-security-policy", "")
    assert "nonce-" in csp, f"CSP missing nonce: {csp}"


@pytest.mark.asyncio
async def test_hsts_header_present(client):
    """Strict-Transport-Security header is set."""
    r = await client.get("/api/v1/assets")
    hsts = r.headers.get("strict-transport-security", "")
    assert "max-age=" in hsts


@pytest.mark.asyncio
async def test_x_content_type_options(client):
    """X-Content-Type-Options must be 'nosniff'."""
    r = await client.get("/api/v1/assets")
    assert r.headers.get("x-content-type-options") == "nosniff"


@pytest.mark.asyncio
async def test_x_frame_options_deny(client):
    """X-Frame-Options must be DENY to prevent clickjacking."""
    r = await client.get("/api/v1/assets")
    assert r.headers.get("x-frame-options") == "DENY"


@pytest.mark.asyncio
async def test_referrer_policy(client):
    """Referrer-Policy header must be present."""
    r = await client.get("/api/v1/assets")
    assert r.headers.get("referrer-policy"), "Missing Referrer-Policy header"


@pytest.mark.asyncio
async def test_permissions_policy(client):
    """Permissions-Policy header must be present."""
    r = await client.get("/api/v1/assets")
    pp = r.headers.get("permissions-policy", "")
    assert pp, "Missing Permissions-Policy header"
    assert "geolocation=()" in pp


@pytest.mark.asyncio
async def test_cross_origin_headers(client):
    """Cross-Origin-Embedder-Policy (via COOP) and Cross-Origin-Resource-Policy headers present."""
    r = await client.get("/api/v1/assets")
    assert r.headers.get("cross-origin-opener-policy") == "same-origin"
    assert r.headers.get("cross-origin-resource-policy") == "same-origin"


@pytest.mark.asyncio
async def test_api_cache_control(client):
    """API responses must include Cache-Control: no-store to prevent sensitive data caching."""
    r = await client.get("/api/v1/assets")
    cc = r.headers.get("cache-control", "")
    assert "no-store" in cc, f"Cache-Control missing no-store: {cc}"


@pytest.mark.asyncio
async def test_csp_no_unsafe_inline_scripts(client):
    """CSP script-src must NOT contain 'unsafe-inline' (nonce replaces it)."""
    r = await client.get("/api/v1/assets")
    csp = r.headers.get("content-security-policy", "")
    # Extract the script-src directive
    for directive in csp.split(";"):
        if "script-src" in directive:
            assert "'unsafe-inline'" not in directive, (
                f"script-src must not contain 'unsafe-inline': {directive}"
            )
            break


@pytest.mark.asyncio
async def test_csp_frame_ancestors_none(client):
    """CSP must contain frame-ancestors 'none' to prevent framing."""
    r = await client.get("/api/v1/assets")
    csp = r.headers.get("content-security-policy", "")
    assert "frame-ancestors 'none'" in csp, f"Missing frame-ancestors 'none' in CSP: {csp}"


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  2. Authentication Enforcement                                             ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


@pytest.mark.asyncio
async def test_protected_endpoints_require_auth(anon_client):
    """Unauthenticated requests to protected endpoints must get 401."""
    for path in ("/api/v1/assets", "/api/v1/scans", "/api/v1/cves"):
        r = await anon_client.get(path)
        assert r.status_code == 401, f"GET {path} should be 401 for anon, got {r.status_code}"


@pytest.mark.asyncio
async def test_admin_endpoints_reject_regular_user(user_client):
    """Regular users must get 403 on admin-only endpoints."""
    for path in ("/api/v1/admin/zap-settings", "/api/v1/users"):
        r = await user_client.get(path)
        assert r.status_code == 403, f"GET {path} should be 403 for user, got {r.status_code}"


@pytest.mark.asyncio
async def test_login_endpoint_is_public(anon_client):
    """POST /api/v1/auth/login is accessible without auth (returns 401 for bad creds, not 403)."""
    r = await anon_client.post(
        "/api/v1/auth/login",
        data={"username": "nobody", "password": "wrong"},
    )
    assert r.status_code == 401, (
        f"Login with bad creds should return 401, got {r.status_code}"
    )


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  3. Input Validation                                                       ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


@pytest.mark.asyncio
async def test_asset_create_invalid_json(client):
    """POST /api/v1/assets with malformed JSON body must return 422."""
    r = await client.post(
        "/api/v1/assets",
        content=b"{not-valid-json}",
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_asset_id_must_be_uuid(client):
    """GET /api/v1/assets/<non-uuid> must return 422."""
    r = await client.get("/api/v1/assets/not-a-uuid")
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_tag_name_validation(client, create_asset):
    """Tag names with special characters must be rejected (422)."""
    asset = await create_asset("10.50.0.1")
    asset_id = asset["id"]
    # The tag regex only allows [a-zA-Z0-9_\-\.]{1,64}
    r = await client.post(f"/api/v1/assets/{asset_id}/tags/invalid tag with spaces!")
    assert r.status_code == 422, (
        f"Invalid tag name should be rejected with 422, got {r.status_code}"
    )


@pytest.mark.asyncio
async def test_dns_fqdn_required(client, create_asset):
    """POST /api/v1/assets/{id}/dns with empty body must return 422."""
    asset = await create_asset("10.50.0.2")
    asset_id = asset["id"]
    r = await client.post(
        f"/api/v1/assets/{asset_id}/dns",
        json={},
    )
    assert r.status_code == 422


@pytest.mark.asyncio
async def test_scan_target_required(client):
    """POST /api/v1/scans with empty body must return 422."""
    r = await client.post("/api/v1/scans", json={})
    assert r.status_code == 422


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  4. Password Strength (unit tests)                                         ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


def test_password_too_short():
    """Passwords shorter than 12 characters must be rejected."""
    with pytest.raises(ValueError, match="at least"):
        validate_password_strength("Sh0rt!ab")


def test_password_no_uppercase():
    """Passwords without uppercase letters must be rejected."""
    with pytest.raises(ValueError, match="uppercase"):
        validate_password_strength("alllowercase1!xx")


def test_password_no_digit():
    """Passwords without any digit must be rejected."""
    with pytest.raises(ValueError, match="digit"):
        validate_password_strength("NoDigitsHere!!xx")


def test_password_no_special():
    """Passwords without special characters must be rejected."""
    with pytest.raises(ValueError, match="special"):
        validate_password_strength("NoSpecial123Char")


def test_password_valid():
    """A strong password must pass without exception."""
    validate_password_strength("MyStr0ng!Pass")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  5. Config Security                                                        ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


def test_default_secrets_blocked_in_production():
    """Default jwt_secret_key with app_debug=False must raise ValueError."""
    with pytest.raises(ValueError, match="SECURITY"):
        Settings(
            jwt_secret_key="change-me-jwt-secret",
            secret_key="change-me-in-production",
            admin_password="changeme",
            app_debug=False,
        )


def test_default_secrets_allowed_in_debug():
    """Default secrets with app_debug=True must NOT raise (dev convenience)."""
    s = Settings(
        jwt_secret_key="change-me-jwt-secret",
        secret_key="change-me-in-production",
        admin_password="changeme",
        app_debug=True,
    )
    assert s.app_debug is True


def test_cors_default_not_wildcard():
    """Default CORS origins must not include the wildcard '*'."""
    s = Settings(
        jwt_secret_key="real-secret-key-1234567890",
        secret_key="real-secret-key-0987654321",
        admin_password="RealAdm1n!Pass",
        app_debug=False,
    )
    assert "*" not in s.cors_allowed_origins, (
        f"CORS must not default to wildcard: {s.cors_allowed_origins}"
    )


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  6. JWT Token Security (unit tests)                                        ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


def _make_settings_env():
    """Return env overrides for a known test secret."""
    return {
        "JWT_SECRET_KEY": "test-jwt-secret-key-for-unit-tests",
        "SECRET_KEY": "test-secret-key-for-unit-tests",
        "ADMIN_PASSWORD": "TestAdm1n!Pass",
        "APP_DEBUG": "false",
    }


def test_jwt_contains_required_claims():
    """Access token must contain sub, exp, iss, and role claims."""
    env = _make_settings_env()
    with patch.dict(os.environ, env, clear=False):
        from netlanventory.core.config import get_settings
        get_settings.cache_clear()
        try:
            token = create_access_token(user_id="user-123", role="admin")
            settings = get_settings()
            decoded = pyjwt.decode(
                token,
                settings.jwt_secret_key,
                algorithms=[settings.jwt_algorithm],
                options={"verify_exp": False},
            )
            for claim in ("sub", "exp", "iss", "role"):
                assert claim in decoded, f"Missing claim: {claim}"
            assert decoded["sub"] == "user-123"
            assert decoded["role"] == "admin"
            assert decoded["iss"] == "netlanventory"
        finally:
            get_settings.cache_clear()


def test_jwt_expired_token_rejected():
    """An expired token must raise HTTPException (401)."""
    env = _make_settings_env()
    with patch.dict(os.environ, env, clear=False):
        from fastapi import HTTPException
        from netlanventory.core.config import get_settings
        get_settings.cache_clear()
        try:
            settings = get_settings()
            expired_payload = {
                "sub": "user-expired",
                "role": "user",
                "iss": "netlanventory",
                "exp": datetime.now(timezone.utc) - timedelta(hours=1),
            }
            token = pyjwt.encode(
                expired_payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
            )
            with pytest.raises(HTTPException) as exc_info:
                decode_access_token(token)
            assert exc_info.value.status_code == 401
        finally:
            get_settings.cache_clear()


def test_jwt_invalid_token_rejected():
    """Garbage token must raise HTTPException (401)."""
    env = _make_settings_env()
    with patch.dict(os.environ, env, clear=False):
        from fastapi import HTTPException
        from netlanventory.core.config import get_settings
        get_settings.cache_clear()
        try:
            with pytest.raises(HTTPException) as exc_info:
                decode_access_token("not.a.valid.jwt.token")
            assert exc_info.value.status_code == 401
        finally:
            get_settings.cache_clear()


def test_jwt_wrong_issuer_rejected():
    """A token with wrong issuer must raise HTTPException (401)."""
    env = _make_settings_env()
    with patch.dict(os.environ, env, clear=False):
        from fastapi import HTTPException
        from netlanventory.core.config import get_settings
        get_settings.cache_clear()
        try:
            settings = get_settings()
            bad_payload = {
                "sub": "user-wrong-iss",
                "role": "user",
                "iss": "evil-issuer",
                "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            }
            token = pyjwt.encode(
                bad_payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm
            )
            with pytest.raises(HTTPException) as exc_info:
                decode_access_token(token)
            assert exc_info.value.status_code == 401
        finally:
            get_settings.cache_clear()


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  7. Crypto (unit tests)                                                    ║
# ╚══════════════════════════════════════════════════════════════════════════════╝


def test_encrypt_decrypt_roundtrip():
    """Encrypting then decrypting must return the original value."""
    env = _make_settings_env()
    with patch.dict(os.environ, env, clear=False):
        from netlanventory.core.config import get_settings
        get_settings.cache_clear()
        try:
            original = "ssh-private-key-content-here"
            ciphertext = encrypt(original)
            assert ciphertext != original
            assert decrypt(ciphertext) == original
        finally:
            get_settings.cache_clear()


def test_different_inputs_different_ciphertexts():
    """Two different plaintexts must produce different ciphertexts."""
    env = _make_settings_env()
    with patch.dict(os.environ, env, clear=False):
        from netlanventory.core.config import get_settings
        get_settings.cache_clear()
        try:
            ct_a = encrypt("a")
            ct_b = encrypt("b")
            assert ct_a != ct_b
        finally:
            get_settings.cache_clear()
