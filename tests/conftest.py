"""pytest fixtures shared across all tests.

Provides:
- In-memory SQLite engine with full schema
- Async DB session (function-scoped, isolated)
- HTTPX AsyncClient wired to FastAPI with mocked auth
- Fake admin / regular user fixtures
- Asset creation helper
"""

from __future__ import annotations

import os
import uuid

# ── Environment for Settings validation ──────────────────────────────────────
# Must be set BEFORE any import of netlanventory.core.config (Settings).
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-conftest")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret-key-for-conftest")
os.environ.setdefault("ADMIN_PASSWORD", "Test1234!@#$")
os.environ.setdefault("APP_DEBUG", "true")
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# ── SQLite compatibility shim ─────────────────────────────────────────────────
# Models use PostgreSQL JSONB. SQLite (used in tests) doesn't support JSONB.
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler  # noqa: E402


def _visit_JSONB(self, type_, **kw):  # type: ignore[no-untyped-def]
    return self.visit_JSON(type_, **kw)


SQLiteTypeCompiler.visit_JSONB = _visit_JSONB  # type: ignore[attr-defined]
# ─────────────────────────────────────────────────────────────────────────────

from netlanventory.models.base import Base
from netlanventory.models.user import User

# Use SQLite in-memory for tests — no PostgreSQL required.
TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

# ── Fake users ───────────────────────────────────────────────────────────────

_FAKE_ADMIN = User(
    id=uuid.uuid4(),
    email="admin@test.local",
    username="testadmin",
    hashed_password=None,
    role="admin",
    is_active=True,
    auth_provider="local",
)

_FAKE_USER = User(
    id=uuid.uuid4(),
    email="user@test.local",
    username="testuser",
    hashed_password=None,
    role="user",
    is_active=True,
    auth_provider="local",
)

_FAKE_DISABLED = User(
    id=uuid.uuid4(),
    email="disabled@test.local",
    username="disabled",
    hashed_password=None,
    role="user",
    is_active=False,
    auth_provider="local",
)


# ── Core fixtures ────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def engine():
    """Create a fresh in-memory SQLite engine per test function."""
    eng = create_async_engine(
        TEST_DB_URL,
        echo=False,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def db_session(engine):
    """Yield an async session bound to the test engine."""
    factory = async_sessionmaker(engine, expire_on_commit=False, autoflush=True)
    async with factory() as session:
        yield session


def _make_app_and_client_factory(engine, auth_user):
    """Build a FastAPI app with overridden DB and auth dependencies."""
    from netlanventory.api.app import create_app
    from netlanventory.api.dependencies import get_current_active_user, get_db

    app = create_app()
    factory = async_sessionmaker(engine, expire_on_commit=False, autoflush=True)

    async def override_db():
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def override_auth():
        return auth_user

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_active_user] = override_auth
    return app


@pytest_asyncio.fixture
async def client(engine):
    """HTTPX async test client authenticated as admin."""
    app = _make_app_and_client_factory(engine, _FAKE_ADMIN)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


@pytest_asyncio.fixture
async def user_client(engine):
    """HTTPX async test client authenticated as regular user (non-admin)."""
    app = _make_app_and_client_factory(engine, _FAKE_USER)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


@pytest_asyncio.fixture
async def anon_client(engine):
    """HTTPX async test client with NO auth (tests unauthenticated access)."""
    from netlanventory.api.app import create_app
    from netlanventory.api.dependencies import get_db

    app = create_app()
    factory = async_sessionmaker(engine, expire_on_commit=False, autoflush=True)

    async def override_db():
        async with factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_db
    # Do NOT override auth → endpoints will require real Bearer token

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


# ── Helper fixtures ──────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def create_asset(client):
    """Factory fixture to create assets. Returns async callable(ip, **kwargs) → asset dict."""
    _counter = 0

    async def _create(ip: str | None = None, **kwargs: Any) -> dict:
        nonlocal _counter
        _counter += 1
        if ip is None:
            ip = f"10.99.0.{_counter}"
        payload = {"ip": ip, **kwargs}
        r = await client.post("/api/v1/assets", json=payload)
        assert r.status_code == 201, f"Failed to create asset: {r.text}"
        return r.json()

    return _create


UNKNOWN_UUID = "00000000-0000-0000-0000-000000000000"
"""A UUID guaranteed to not exist in the test database."""
