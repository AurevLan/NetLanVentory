"""Simple async circuit breaker.

Wraps external service calls (ZAP, Nuclei, OSV, NVD) to prevent cascading
failures when a dependency becomes unreachable.

States
------
CLOSED   — normal operation; calls pass through
OPEN     — failure threshold exceeded; calls are short-circuited immediately
HALF_OPEN — timeout elapsed; one probe call allowed to test recovery

Usage
-----
    cb = CircuitBreaker("zap", failure_threshold=5, timeout_seconds=60)

    async with cb:
        resp = await httpx_client.get(...)

Or as a decorator::

    @cb.wrap
    async def _call_zap() -> dict:
        ...
"""

from __future__ import annotations

import asyncio
import time
from enum import Enum, auto
from typing import Callable, TypeVar

from netlanventory.core.logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T")


class _State(Enum):
    CLOSED = auto()
    OPEN = auto()
    HALF_OPEN = auto()


class CircuitBreakerOpen(Exception):
    """Raised when the circuit is open and the call is rejected."""


class CircuitBreaker:
    """Async circuit breaker with configurable threshold and timeout."""

    def __init__(
        self,
        name: str,
        failure_threshold: int = 5,
        timeout_seconds: float = 60.0,
    ) -> None:
        self.name = name
        self.failure_threshold = failure_threshold
        self.timeout_seconds = timeout_seconds

        self._state = _State.CLOSED
        self._failure_count = 0
        self._last_failure_time: float = 0.0
        self._lock = asyncio.Lock()

    @property
    def state(self) -> str:
        return self._state.name

    async def _check_state(self) -> None:
        """Raise CircuitBreakerOpen if the circuit is open, or transition to HALF_OPEN."""
        async with self._lock:
            if self._state == _State.OPEN:
                elapsed = time.monotonic() - self._last_failure_time
                if elapsed >= self.timeout_seconds:
                    logger.info("Circuit half-open — probing", name=self.name)
                    self._state = _State.HALF_OPEN
                else:
                    raise CircuitBreakerOpen(
                        f"Circuit '{self.name}' is OPEN "
                        f"(retry in {self.timeout_seconds - elapsed:.0f}s)"
                    )

    async def _on_success(self) -> None:
        async with self._lock:
            if self._state != _State.CLOSED:
                logger.info("Circuit closed", name=self.name)
            self._state = _State.CLOSED
            self._failure_count = 0

    async def _on_failure(self, exc: BaseException) -> None:
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if self._failure_count >= self.failure_threshold or self._state == _State.HALF_OPEN:
                if self._state != _State.OPEN:
                    logger.warning(
                        "Circuit opened",
                        name=self.name,
                        failures=self._failure_count,
                        error=str(exc),
                    )
                self._state = _State.OPEN

    async def __aenter__(self) -> "CircuitBreaker":
        await self._check_state()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> bool:  # type: ignore[override]
        if exc_type is None:
            await self._on_success()
        elif exc_type is not CircuitBreakerOpen:
            await self._on_failure(exc_val)
        return False  # don't suppress exceptions

    def wrap(self, fn: Callable[..., "asyncio.Future[T]"]) -> Callable[..., "asyncio.Future[T]"]:
        """Decorator: run an async function inside this circuit breaker."""
        import functools

        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
            async with self:
                return await fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]


# Global named breakers — lazy initialised on first use
_breakers: dict[str, CircuitBreaker] = {}


def get_breaker(
    name: str,
    failure_threshold: int = 5,
    timeout_seconds: float = 60.0,
) -> CircuitBreaker:
    """Return a shared CircuitBreaker for the given service name."""
    if name not in _breakers:
        _breakers[name] = CircuitBreaker(
            name=name,
            failure_threshold=failure_threshold,
            timeout_seconds=timeout_seconds,
        )
    return _breakers[name]
