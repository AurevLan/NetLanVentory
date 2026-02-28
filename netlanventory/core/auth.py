"""Authentication helpers: password hashing and JWT management.

Local auth flow:
    1. POST /api/v1/auth/login (OAuth2 form) → verify password → issue JWT
    2. Every protected endpoint validates Authorization: Bearer <jwt>

OIDC connector hook (future):
    To enable OIDC login:
    1. Set OIDC_ENABLED=true, OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET
    2. Add GET /api/v1/auth/oidc/authorize  → redirect to provider
    3. Add GET /api/v1/auth/oidc/callback   → exchange code, fetch userinfo,
       upsert User(auth_provider="oidc", provider_sub=<sub>), then call
       create_access_token() to issue a local JWT — same downstream flow.
    4. Optionally validate provider JWTs directly via JWKS (see stub below).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import HTTPException, status

from netlanventory.core.config import get_settings


# ── Password helpers ─────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


# ── JWT helpers ───────────────────────────────────────────────────────────────

def create_access_token(user_id: str, role: str, provider: str = "local") -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    payload = {
        "sub": user_id,
        "role": role,
        "provider": provider,   # "local" | "oidc" — kept for OIDC passthrough
        "iat": now,
        "exp": expire,
        "iss": "netlanventory",
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    settings = get_settings()
    try:
        return jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
            options={"require": ["sub", "exp", "iss"]},
            issuer="netlanventory",
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── OIDC stub (future) ────────────────────────────────────────────────────────

# async def validate_oidc_token(id_token: str) -> dict:
#     """Fetch JWKS from OIDC provider and validate the ID token.
#
#     Returns the decoded claims dict (sub, email, name, …).
#     Raises HTTPException(401) on invalid token.
#     """
#     settings = get_settings()
#     # Use python-jose or joserfc to fetch JWKS and verify signature
#     ...
