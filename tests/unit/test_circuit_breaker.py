"""Tests for the circuit breaker pattern."""

import asyncio

import pytest

from netlanventory.core.circuit_breaker import CircuitBreaker, CircuitBreakerOpen


@pytest.fixture
def breaker():
    return CircuitBreaker("test", failure_threshold=3, timeout_seconds=0.5)


@pytest.mark.asyncio
async def test_breaker_closed_by_default(breaker):
    """Breaker starts in CLOSED state and allows calls."""
    assert breaker.state == "CLOSED"

    async with breaker:
        pass  # should not raise


@pytest.mark.asyncio
async def test_breaker_opens_after_threshold(breaker):
    """Breaker transitions to OPEN after enough failures."""
    for _ in range(3):
        with pytest.raises(ValueError):
            async with breaker:
                raise ValueError("simulated failure")

    assert breaker.state == "OPEN"

    with pytest.raises(CircuitBreakerOpen):
        async with breaker:
            pass


@pytest.mark.asyncio
async def test_breaker_half_open_after_timeout(breaker):
    """Breaker transitions to HALF_OPEN after timeout, then CLOSED on success."""
    for _ in range(3):
        with pytest.raises(ValueError):
            async with breaker:
                raise ValueError("simulated failure")

    assert breaker.state == "OPEN"

    # Wait for timeout to elapse
    await asyncio.sleep(0.7)

    # State is still OPEN (transition happens on next __aenter__)
    # A successful call should transition through HALF_OPEN → CLOSED
    async with breaker:
        pass

    assert breaker.state == "CLOSED"


@pytest.mark.asyncio
async def test_breaker_records_failures(breaker):
    """Breaker tracks failure count."""
    assert breaker._failure_count == 0

    with pytest.raises(RuntimeError):
        async with breaker:
            raise RuntimeError("fail")

    assert breaker._failure_count == 1


@pytest.mark.asyncio
async def test_breaker_resets_on_success(breaker):
    """Successful call resets the failure counter."""
    with pytest.raises(RuntimeError):
        async with breaker:
            raise RuntimeError("fail")

    assert breaker._failure_count == 1

    async with breaker:
        pass

    assert breaker._failure_count == 0
