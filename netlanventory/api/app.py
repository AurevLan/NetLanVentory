"""FastAPI application factory with lifespan management."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.base import BaseHTTPMiddleware

from netlanventory.api.routers import assets, modules, scans
from netlanventory.api.routers import admin as admin_router
from netlanventory.api.routers import auth as auth_router
from netlanventory.api.routers import cves as cves_router
from netlanventory.api.routers import dns as dns_router
from netlanventory.api.routers import nuclei as nuclei_router
from netlanventory.api.routers import ssh_scan as ssh_scan_router
from netlanventory.api.routers import users as users_router
from netlanventory.api.routers import zap as zap_router
from netlanventory.core.auth import hash_password
from netlanventory.core.config import get_settings
from netlanventory.core.database import close_engine, get_engine, get_session_factory
from netlanventory.core.limiter import limiter
from netlanventory.core.logging import configure_logging, get_logger
from netlanventory.core.registry import get_registry
from netlanventory.core.scheduler import scheduler_loop

logger = get_logger(__name__)

STATIC_DIR = Path(__file__).parent / "static"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject ANSSI-recommended security headers into every response."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        response = await call_next(request)
        h = response.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["X-XSS-Protection"] = "0"
        h["Referrer-Policy"] = "strict-origin-when-cross-origin"
        h["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        h["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
        return response


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

    # Bootstrap: create default admin if no users exist
    await _bootstrap_admin(settings)

    # Check Nuclei binary availability
    import shutil
    nuclei_bin = settings.nuclei_binary
    if shutil.which(nuclei_bin):
        logger.info("Nuclei binary found", path=shutil.which(nuclei_bin))
    else:
        logger.warning(
            "Nuclei binary not found",
            binary=nuclei_bin,
            hint="Ensure 'nuclei' is installed in the container PATH to use Nuclei scanning.",
        )

    # Reset orphaned scans left in running/pending state from a previous crash
    await _reset_orphaned_scans()

    # Start ZAP auto-scan scheduler
    _sched_task = asyncio.create_task(scheduler_loop(), name="zap-scheduler")

    yield

    # Stop scheduler
    _sched_task.cancel()
    try:
        await _sched_task
    except asyncio.CancelledError:
        pass

    # Cleanup
    await close_engine()
    logger.info("NetLanVentory stopped")


async def _reset_orphaned_scans() -> None:
    """Mark running/pending scans as failed on startup (background tasks don't survive restarts)."""
    from sqlalchemy import update
    from netlanventory.models.nuclei_report import NucleiReport
    from netlanventory.models.ssh_scan_report import SshScanReport
    from netlanventory.core.database import get_session_factory

    factory = get_session_factory()
    async with factory() as session:
        for model in (NucleiReport, SshScanReport):
            result = await session.execute(
                update(model)
                .where(model.status.in_(["running", "pending"]))
                .values(status="failed", error_msg="Interrupted by app restart")
            )
            if result.rowcount:
                logger.warning(
                    "Reset orphaned scans",
                    model=model.__tablename__,
                    count=result.rowcount,
                )
        await session.commit()


async def _bootstrap_admin(settings) -> None:
    """Create the default admin account on first start (no users in DB)."""
    from sqlalchemy import func, select

    from netlanventory.models.user import User

    factory = get_session_factory()
    async with factory() as session:
        count = (await session.execute(select(func.count()).select_from(User))).scalar_one()
        if count == 0:
            admin = User(
                email=settings.admin_email,
                username="admin",
                hashed_password=hash_password(settings.admin_password),
                role="admin",
                is_active=True,
                auth_provider="local",
            )
            session.add(admin)
            await session.commit()
            logger.info(
                "Bootstrap admin created",
                email=settings.admin_email,
                hint="Change the default password immediately!",
            )


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="NetLanVentory",
        description="Modular network scanning and inventory API",
        version="0.6.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Rate limiter state + 429 handler
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Security headers (added first = runs outermost in LIFO middleware stack)
    app.add_middleware(SecurityHeadersMiddleware)

    # CORS — allow_credentials must NOT be combined with allow_origins=["*"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from fastapi import Depends

    from netlanventory.api.dependencies import get_current_active_user

    # API routers
    api_prefix = "/api/v1"

    # Auth & users — auth/login is public; other auth routes self-guard
    app.include_router(auth_router.router, prefix=api_prefix)
    app.include_router(users_router.router, prefix=api_prefix)
    app.include_router(admin_router.router, prefix=api_prefix)

    # All data routers require a valid session
    _auth = [Depends(get_current_active_user)]
    app.include_router(assets.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(scans.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(modules.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(zap_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(dns_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(ssh_scan_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(nuclei_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(cves_router.router, prefix=api_prefix, dependencies=_auth)

    # Serve static dashboard if the directory exists
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

        @app.get("/", include_in_schema=False)
        async def serve_dashboard() -> FileResponse:
            return FileResponse(STATIC_DIR / "index.html")

    @app.get("/health", tags=["health"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": "0.6.0"}

    return app


app = create_app()
