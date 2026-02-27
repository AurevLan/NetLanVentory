"""FastAPI application factory with lifespan management."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from netlanventory.api.routers import assets, modules, scans
from netlanventory.core.config import get_settings
from netlanventory.core.database import close_engine, get_engine
from netlanventory.core.logging import configure_logging, get_logger
from netlanventory.core.registry import get_registry

logger = get_logger(__name__)

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    configure_logging()
    settings = get_settings()
    logger.info("Starting NetLanVentory", debug=settings.app_debug)

    # Warm up DB connection pool
    get_engine()

    # Discover and register modules
    registry = get_registry()
    logger.info("Modules ready", modules=registry.names())

    yield

    # Cleanup
    await close_engine()
    logger.info("NetLanVentory stopped")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="NetLanVentory",
        description="Modular network scanning and inventory API",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # CORS (permissive for local dashboard)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # API routers
    api_prefix = "/api/v1"
    app.include_router(assets.router, prefix=api_prefix)
    app.include_router(scans.router, prefix=api_prefix)
    app.include_router(modules.router, prefix=api_prefix)

    # Serve static dashboard if the directory exists
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

        @app.get("/", include_in_schema=False)
        async def serve_dashboard() -> FileResponse:
            return FileResponse(STATIC_DIR / "index.html")

    @app.get("/health", tags=["health"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": "0.1.0"}

    return app


app = create_app()
