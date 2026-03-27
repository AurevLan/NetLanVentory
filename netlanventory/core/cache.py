"""Optional Redis cache layer.

Falls back gracefully if redis is not installed or REDIS_URL is not set.
Callers should always check: ``if cache: await cache_set(...)``.
"""

from __future__ import annotations

import json
from typing import Any

from netlanventory.core.logging import get_logger

logger = get_logger(__name__)

try:
    import redis.asyncio as aioredis  # type: ignore[import]
    _redis_available = True
except ImportError:
    aioredis = None  # type: ignore[assignment]
    _redis_available = False

_client: Any = None
_initialized = False


async def get_cache() -> Any:
    """Return a connected Redis client, or None if unavailable."""
    global _client, _initialized
    if _initialized:
        return _client

    _initialized = True

    if not _redis_available:
        logger.debug("Redis not installed — cache disabled")
        return None

    from netlanventory.core.config import get_settings
    settings = get_settings()

    if not settings.redis_url:
        logger.debug("REDIS_URL not set — cache disabled")
        return None

    try:
        _client = aioredis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=2,
        )
        await _client.ping()
        logger.info("Redis cache connected", url=settings.redis_url)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Redis unavailable — cache disabled", error=str(exc))
        _client = None

    return _client


async def cache_get(key: str) -> str | None:
    """Return cached string value or None on miss/error."""
    cache = await get_cache()
    if cache is None:
        return None
    try:
        return await cache.get(key)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Cache get error", key=key, error=str(exc))
        return None


async def cache_set(key: str, value: str, ttl: int = 60) -> None:
    """Store a string value with TTL (seconds)."""
    cache = await get_cache()
    if cache is None:
        return
    try:
        await cache.setex(key, ttl, value)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Cache set error", key=key, error=str(exc))


async def cache_set_json(key: str, value: Any, ttl: int = 60) -> None:
    """Serialize value to JSON and store with TTL."""
    await cache_set(key, json.dumps(value, default=str), ttl)


async def cache_get_json(key: str) -> Any:
    """Return deserialized JSON value or None on miss/error."""
    raw = await cache_get(key)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


async def cache_invalidate(key: str) -> None:
    """Delete a single cache key."""
    cache = await get_cache()
    if cache is None:
        return
    try:
        await cache.delete(key)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Cache delete error", key=key, error=str(exc))


async def cache_invalidate_prefix(prefix: str) -> None:
    """Delete all keys with the given prefix (uses SCAN to avoid blocking)."""
    cache = await get_cache()
    if cache is None:
        return
    try:
        async for key in cache.scan_iter(f"{prefix}*"):
            await cache.delete(key)
    except Exception as exc:  # noqa: BLE001
        logger.debug("Cache prefix-invalidate error", prefix=prefix, error=str(exc))


async def cache_ping() -> bool:
    """Return True if Redis is reachable."""
    cache = await get_cache()
    if cache is None:
        return False
    try:
        await cache.ping()
        return True
    except Exception:
        return False
