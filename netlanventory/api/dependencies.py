"""FastAPI dependency providers."""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from netlanventory.core.database import get_session_factory
from netlanventory.core.registry import ModuleRegistry, get_registry


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield a database session for the duration of a request."""
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def get_module_registry() -> ModuleRegistry:
    """Return the global module registry (already discovered)."""
    return get_registry()
