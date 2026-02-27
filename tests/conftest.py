"""pytest fixtures shared across all tests."""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from netlanventory.models.base import Base

# Use SQLite in-memory for tests — no PostgreSQL required.
# Each test function gets its own fresh DB to avoid cross-test pollution.
TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


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


@pytest_asyncio.fixture
async def client(engine):
    """HTTPX async test client wired to the FastAPI app with a test DB."""
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

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac
