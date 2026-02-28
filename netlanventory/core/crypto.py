"""Symmetric encryption helpers for sensitive stored values (SSH credentials, etc.).

Uses Fernet (AES-128-CBC + HMAC-SHA256) with a key derived from `settings.secret_key`
via SHA-256 → base64-urlsafe.  The same key is always derived deterministically so values
encrypted in one process can be decrypted in another, as long as SECRET_KEY stays the same.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet

from netlanventory.core.config import get_settings


def _get_fernet() -> Fernet:
    """Derive a Fernet instance from the application secret key."""
    raw = get_settings().secret_key.encode()
    digest = hashlib.sha256(raw).digest()
    key = base64.urlsafe_b64encode(digest)
    return Fernet(key)


def encrypt(value: str) -> str:
    """Encrypt *value* and return the ciphertext as a UTF-8 string."""
    return _get_fernet().encrypt(value.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """Decrypt *ciphertext* and return the original plaintext string."""
    return _get_fernet().decrypt(ciphertext.encode()).decode()
