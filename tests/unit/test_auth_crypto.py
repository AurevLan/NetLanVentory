"""Unit tests for auth (password hashing, JWT) and crypto (Fernet encryption) modules.

These tests do not require a database or HTTP client — they exercise the
pure functions in netlanventory.core.auth and netlanventory.core.crypto.
"""

from __future__ import annotations

import os

# Set environment variables BEFORE importing application modules so the
# Settings validator accepts the non-default secrets without raising.
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-unit-tests")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-for-tests")
os.environ.setdefault("ADMIN_PASSWORD", "Test1234!@#$")
os.environ.setdefault("APP_DEBUG", "true")

from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest
from fastapi import HTTPException

from netlanventory.core.auth import (
    create_access_token,
    decode_access_token,
    hash_password,
    validate_password_strength,
    verify_password,
)
from netlanventory.core.crypto import decrypt, encrypt


# ── Password Hashing ────────────────────────────────────────────────────────


def test_hash_password_returns_string():
    """hash_password returns a str (bcrypt hash)."""
    result = hash_password("test")
    assert isinstance(result, str)


def test_verify_password_correct():
    """verify_password returns True for the correct password."""
    hashed = hash_password("correct-password")
    assert verify_password("correct-password", hashed) is True


def test_verify_password_wrong():
    """verify_password returns False for an incorrect password."""
    hashed = hash_password("correct-password")
    assert verify_password("wrong-password", hashed) is False


def test_hash_password_unique():
    """Two calls to hash_password with the same input produce different hashes (salt)."""
    h1 = hash_password("same")
    h2 = hash_password("same")
    assert h1 != h2


# ── Password Strength Validation ────────────────────────────────────────────


def test_validate_password_strength_valid():
    """A strong password passes without raising."""
    validate_password_strength("MyStr0ng!Pass")


def test_validate_password_strength_too_short():
    """A short password raises ValueError."""
    with pytest.raises(ValueError, match="at least"):
        validate_password_strength("Sh0rt!")


def test_validate_password_strength_no_uppercase():
    """A password with no uppercase letters raises ValueError."""
    with pytest.raises(ValueError):
        validate_password_strength("alllowercase1!")


def test_validate_password_strength_no_lowercase():
    """A password with no lowercase letters raises ValueError."""
    with pytest.raises(ValueError):
        validate_password_strength("ALLUPPERCASE1!")


def test_validate_password_strength_no_digit():
    """A password with no digits raises ValueError."""
    with pytest.raises(ValueError):
        validate_password_strength("NoDigitsHere!")


def test_validate_password_strength_no_special():
    """A password with no special characters raises ValueError."""
    with pytest.raises(ValueError):
        validate_password_strength("NoSpecial1234")


# ── JWT Token Management ────────────────────────────────────────────────────


def test_create_and_decode_token():
    """create_access_token then decode_access_token round-trips correctly."""
    token = create_access_token(user_id="user-123", role="admin")
    payload = decode_access_token(token)
    assert payload["sub"] == "user-123"
    assert payload["role"] == "admin"
    assert payload["iss"] == "netlanventory"


def test_token_has_required_claims():
    """Decoded token contains sub, exp, iss, and role claims."""
    token = create_access_token(user_id="user-456", role="user")
    payload = decode_access_token(token)
    for claim in ("sub", "exp", "iss", "role"):
        assert claim in payload, f"Missing claim: {claim}"


def test_token_expired_raises():
    """An expired token causes decode_access_token to raise HTTPException(401)."""
    token = pyjwt.encode(
        {
            "sub": "test",
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),
            "iss": "netlanventory",
        },
        os.environ["JWT_SECRET_KEY"],
        algorithm="HS256",
    )
    with pytest.raises(HTTPException) as exc_info:
        decode_access_token(token)
    assert exc_info.value.status_code == 401


def test_token_invalid_raises():
    """A garbage token causes decode_access_token to raise HTTPException(401)."""
    with pytest.raises(HTTPException) as exc_info:
        decode_access_token("garbage")
    assert exc_info.value.status_code == 401


# ── Encryption ──────────────────────────────────────────────────────────────


def test_encrypt_decrypt_roundtrip():
    """encrypt then decrypt returns the original plaintext."""
    plaintext = "hello"
    ciphertext = encrypt(plaintext)
    assert decrypt(ciphertext) == plaintext


def test_different_plaintexts_different_ciphertexts():
    """Different plaintexts produce different ciphertexts."""
    assert encrypt("a") != encrypt("b")


def test_decrypt_invalid_ciphertext_raises():
    """Decrypting invalid ciphertext raises an exception."""
    with pytest.raises(Exception):
        decrypt("not-valid")
