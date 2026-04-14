"""Integration test fixtures — async SQLAlchemy session with PostgreSQL.

Falls back to SQLite in-memory if PostgreSQL is not available, allowing
tests to run in CI without a database server.
"""

from __future__ import annotations

import os
import uuid
from typing import AsyncGenerator
from unittest.mock import AsyncMock, patch

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from netlanventory.models.base import Base
from netlanventory.models.user import User

# Use TEST_DATABASE_URL or fall back to SQLite async
_DB_URL = os.getenv("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

_FAKE_ADMIN = User(
    id=uuid.uuid4(),
    email="admin@test.local",
    username="testadmin",
    hashed_password=None,
    role="admin",
    is_active=True,
    auth_provider="local",
)


@pytest_asyncio.fixture(scope="session")
async def engine():
    """Create a test database engine, create all tables, then drop on teardown."""
    eng = create_async_engine(_DB_URL, echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await eng.dispose()


@pytest_asyncio.fixture
async def db_session(engine) -> AsyncGenerator[AsyncSession, None]:
    """Provide a transactional database session that rolls back after each test."""
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def client(engine) -> AsyncGenerator[AsyncClient, None]:
    """Provide an HTTPX AsyncClient wired to the FastAPI app with test DB and mocked auth."""
    import netlanventory.core.database as db_mod
    from netlanventory.api.app import create_app
    from netlanventory.api.dependencies import get_current_active_user, get_db

    test_factory = async_sessionmaker(engine, expire_on_commit=False)

    async def _override_get_db():
        async with test_factory() as session:
            yield session

    async def _override_auth():
        return _FAKE_ADMIN

    # Patch the global engine/session_factory so lifespan helpers
    # (_bootstrap_admin, _reset_orphaned_scans) use the test SQLite DB
    # instead of attempting to connect to PostgreSQL with pool_size kwargs.
    # Also patch close_engine to prevent disposing the shared test engine.
    old_engine = db_mod._engine
    old_factory = db_mod._session_factory
    db_mod._engine = engine
    db_mod._session_factory = test_factory
    try:
        with patch.object(db_mod, "close_engine", new_callable=AsyncMock):
            app = create_app()
            app.dependency_overrides[get_db] = _override_get_db
            app.dependency_overrides[get_current_active_user] = _override_auth

            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as ac:
                yield ac
    finally:
        db_mod._engine = old_engine
        db_mod._session_factory = old_factory
