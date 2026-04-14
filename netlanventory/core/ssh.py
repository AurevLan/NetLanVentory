"""SSH connection helper with retry/backoff for rate-limited sshd servers."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

import asyncssh

from netlanventory.core.logging import get_logger

logger = get_logger(__name__)

_MAX_RETRIES = 5
_BACKOFF_BASE = 3  # seconds


@asynccontextmanager
async def ssh_connect(
    host: str,
    port: int = 22,
    username: str = "root",
    retries: int = _MAX_RETRIES,
    **kwargs,
) -> AsyncIterator[asyncssh.SSHClientConnection]:
    """Wrapper around asyncssh.connect with retry on transient failures.

    Handles ConnectionLost / ConnectionResetError that sshd raises when
    MaxStartups is exceeded.
    """
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            async with asyncssh.connect(
                host, port=port, username=username, known_hosts=None, **kwargs
            ) as conn:
                yield conn
                return
        except (ConnectionError, asyncssh.ConnectionLost, OSError) as exc:
            last_exc = exc
            if attempt < retries:
                delay = _BACKOFF_BASE * attempt
                logger.warning(
                    "SSH connect failed, retrying",
                    host=host,
                    port=port,
                    attempt=attempt,
                    delay=delay,
                    error=str(exc),
                )
                await asyncio.sleep(delay)
            else:
                raise
