"""FastAPI application factory with lifespan management."""

from __future__ import annotations

import asyncio
import secrets
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
from netlanventory.api.routers import audit as audit_router
from netlanventory.api.routers import sessions as sessions_router
from netlanventory.api.routers import ssh_profiles as ssh_profiles_router
from netlanventory.api.routers import trivy_docker_scan as trivy_docker_router
from netlanventory.api.routers import tags as tags_router
from netlanventory.api.routers import ack as ack_router
from netlanventory.api.routers import dashboard as dashboard_router
from netlanventory.api.routers import quota as quota_router
from netlanventory.api.routers import auth as auth_router
from netlanventory.api.routers import cves as cves_router
from netlanventory.api.routers import dns as dns_router
from netlanventory.api.routers import nuclei as nuclei_router
from netlanventory.api.routers import ssh_scan as ssh_scan_router
from netlanventory.api.routers import users as users_router
from netlanventory.api.routers import zap as zap_router
from netlanventory.api.routers import import_export as import_export_router
from netlanventory.api.routers import epss as epss_router
from netlanventory.api.routers import kev as kev_router
from netlanventory.api.routers import exploits as exploits_router
from netlanventory.api.routers import sla as sla_router
from netlanventory.api.routers import ssl_scan as ssl_scan_router
from netlanventory.api.routers import notifications as notif_router
from netlanventory.api.routers import baseline as baseline_router
from netlanventory.api.routers import reports as reports_router
from netlanventory.api.routers import exploit_validation as exploit_validation_router
from netlanventory.api.routers import testssl as testssl_router
from netlanventory.api.routers import ssh_audit as ssh_audit_router
from netlanventory.api.routers import default_creds as default_creds_router
from netlanventory.api.routers import full_audit as full_audit_router
from netlanventory.api.routers import remediation as remediation_router
from netlanventory.api.routers import priority_matrix as priority_matrix_router
from netlanventory.api.routers import hardening as hardening_router
from netlanventory.api.routers import headers_audit as headers_audit_router
from netlanventory.api.routers import msf_validation as msf_validation_router
from netlanventory.api.routers import topology as topology_router
from netlanventory.api.routers import timeline as timeline_router
from netlanventory.api.routers import events as events_router
from netlanventory.api.routers import search as search_router
from netlanventory.api.routers import executive as executive_router
from netlanventory.api.routers import ldap_import as ldap_router
from netlanventory.api.routers import cloud_import as cloud_router
from netlanventory.api.routers import threat_intel as threat_intel_router
from netlanventory.api.routers import compliance as compliance_router
from netlanventory.api.routers import ansible as ansible_router
from netlanventory.api.routers import tickets as tickets_router
from netlanventory.api.routers import saved_filters as saved_filters_router
from netlanventory.api.routers import scheduled_reports as scheduled_reports_router
from netlanventory.api.routers import scheduled_scans as scheduled_scans_router
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
    """Inject ANSSI-recommended security headers into every response.

    Security improvements (v0.10.0):
    - CSP nonce for inline scripts (eliminates 'unsafe-inline' for scripts)
    - Strict-Transport-Security (HSTS) header
    - Cross-Origin headers (COEP, COOP, CORP)
    - Cache-Control for API responses
    """

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        # Generate a per-request nonce for CSP
        nonce = secrets.token_urlsafe(32)
        request.state.csp_nonce = nonce

        response = await call_next(request)
        h = response.headers

        # Core security headers
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["X-XSS-Protection"] = "0"
        h["Referrer-Policy"] = "strict-origin-when-cross-origin"
        h["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), "
            "usb=(), bluetooth=(), payment=()"
        )

        # HSTS — enforce HTTPS (1 year, include subdomains)
        h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Cross-origin isolation
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        h["Cross-Origin-Resource-Policy"] = "same-origin"

        # Content Security Policy
        # NOTE: 'unsafe-inline' is required for script-src because the dashboard
        # uses hundreds of inline onclick handlers. A nonce CANNOT coexist with
        # unsafe-inline (browsers ignore unsafe-inline when a nonce is present).
        # TODO: migrate all onclick="" to addEventListener() then switch to nonce-only.
        h["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' fonts.googleapis.com; "
            "font-src 'self' fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self' cdn.jsdelivr.net; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "object-src 'none'"
        )

        # Prevent caching of API responses with sensitive data
        if request.url.path.startswith("/api/"):
            h["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            h["Pragma"] = "no-cache"

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

    # Check external binary availability
    import shutil
    for binary, hint in [
        (settings.nuclei_binary, "Ensure 'nuclei' is installed in the container PATH."),
        (settings.testssl_binary, "Install testssl.sh for deep TLS auditing."),
        (settings.ssh_audit_binary, "Install ssh-audit (pip install ssh-audit) for SSH config auditing."),
        ("nmap", "Install nmap for port scanning and default credential testing."),
    ]:
        if shutil.which(binary):
            logger.info("Binary found", binary=binary, path=shutil.which(binary))
        else:
            logger.warning("Binary not found", binary=binary, hint=hint)

    # Reset orphaned scans left in running/pending state from a previous crash
    await _reset_orphaned_scans()

    # Start ZAP auto-scan scheduler
    _sched_task = asyncio.create_task(scheduler_loop(), name="zap-scheduler")

    # Start passive ARP/DHCP discovery if enabled
    if settings.passive_discovery_enabled:
        from netlanventory.core.passive_discovery import start_passive_listener
        asyncio.create_task(
            start_passive_listener(settings.passive_interface),
            name="passive-discovery",
        )
        logger.info("Passive discovery started", interface=settings.passive_interface)

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
    from netlanventory.models.trivy_docker_report import TrivyDockerReport
    from netlanventory.models.testssl_report import TestsslReport
    from netlanventory.models.ssh_audit_report import SshAuditReport
    from netlanventory.models.default_creds_report import DefaultCredsReport
    from netlanventory.models.full_audit_job import FullAuditJob
    from netlanventory.models.hardening_report import HardeningReport
    from netlanventory.models.headers_audit_report import HeadersAuditReport
    from netlanventory.models.msf_validation_report import MsfValidationReport
    from netlanventory.core.database import get_session_factory

    factory = get_session_factory()
    async with factory() as session:
        for model in (
            NucleiReport, SshScanReport, TrivyDockerReport, TestsslReport,
            SshAuditReport, DefaultCredsReport, FullAuditJob,
            HardeningReport, HeadersAuditReport, MsfValidationReport,
        ):
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
        version="0.11.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # Rate limiter state + 429 handler
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Security headers (added first = runs outermost in LIFO middleware stack)
    app.add_middleware(SecurityHeadersMiddleware)

    # CORS — restrict to configured origins only (never wildcard in production)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
        expose_headers=["X-Request-Id"],
        max_age=3600,
    )

    from fastapi import Depends

    from netlanventory.api.dependencies import get_current_active_user

    # API routers
    api_prefix = "/api/v1"

    # Auth & users — auth/login is public; other auth routes self-guard
    app.include_router(auth_router.router, prefix=api_prefix)
    app.include_router(users_router.router, prefix=api_prefix)
    app.include_router(admin_router.router, prefix=api_prefix)
    app.include_router(audit_router.router, prefix=api_prefix)
    app.include_router(sessions_router.router, prefix=api_prefix)
    app.include_router(ssh_profiles_router.router, prefix=api_prefix)

    # All data routers require a valid session
    _auth = [Depends(get_current_active_user)]
    app.include_router(assets.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(scans.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(modules.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(zap_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(dns_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(ssh_scan_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(ssh_scan_router._diff_router, prefix=api_prefix, dependencies=_auth)
    app.include_router(nuclei_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(trivy_docker_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(tags_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(ack_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(ack_router.bulk_ack_router, prefix=api_prefix, dependencies=_auth)
    app.include_router(dashboard_router.router, prefix=api_prefix)
    app.include_router(quota_router.router, prefix=api_prefix)
    app.include_router(cves_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(import_export_router.router, prefix=api_prefix, dependencies=_auth)

    # New feature routers (0.7.0)
    app.include_router(epss_router.router, prefix=api_prefix)  # auth handled by require_admin
    app.include_router(kev_router.router, prefix=api_prefix)   # auth handled by require_admin
    app.include_router(exploits_router.router, prefix=api_prefix)  # auth handled by require_admin
    app.include_router(sla_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(ssl_scan_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(ssl_scan_router._expiring_router, prefix=api_prefix, dependencies=_auth)
    app.include_router(notif_router.router, prefix=api_prefix)  # auth handled by require_admin
    app.include_router(baseline_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(reports_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(exploit_validation_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(testssl_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(ssh_audit_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(default_creds_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(full_audit_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(remediation_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(remediation_router.workflow_router, prefix=api_prefix, dependencies=_auth)

    # New feature routers (0.8.0) — security audit suite
    app.include_router(priority_matrix_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(hardening_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(hardening_router.lynis_router, prefix=api_prefix, dependencies=_auth)
    app.include_router(headers_audit_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(msf_validation_router.router, prefix=api_prefix, dependencies=_auth)

    # New feature routers (0.9.0) — 360° vision
    app.include_router(topology_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(timeline_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(events_router.router, prefix=api_prefix)  # auth via query param token
    app.include_router(search_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(executive_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(ldap_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(cloud_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(threat_intel_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(compliance_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(ansible_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(tickets_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(saved_filters_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(scheduled_reports_router.router, prefix=api_prefix, dependencies=_auth)
    app.include_router(scheduled_scans_router.router, prefix=api_prefix, dependencies=_auth)

    # Serve static dashboard if the directory exists
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

        @app.get("/", include_in_schema=False)
        async def serve_dashboard() -> FileResponse:
            return FileResponse(STATIC_DIR / "index.html")

    @app.get("/health", tags=["health"])
    async def health() -> dict:
        import shutil
        from netlanventory.core.cache import cache_ping

        checks: dict[str, str] = {}

        # Database
        try:
            from sqlalchemy import text
            factory = get_session_factory()
            async with factory() as session:
                await session.execute(text("SELECT 1"))
            checks["db"] = "ok"
        except Exception:  # noqa: BLE001
            checks["db"] = "error"

        # Redis (optional)
        checks["redis"] = "ok" if await cache_ping() else "unavailable"

        # ZAP
        try:
            import httpx
            zap_url = get_settings().zap_api_url or "http://localhost:8080"
            async with httpx.AsyncClient(timeout=2) as client:
                resp = await client.get(f"{zap_url}/JSON/core/view/version/")
                checks["zap"] = "ok" if resp.status_code == 200 else "error"
        except Exception:  # noqa: BLE001
            checks["zap"] = "unavailable"

        # Nuclei
        checks["nuclei"] = "ok" if shutil.which(get_settings().nuclei_binary) else "unavailable"

        overall = "ok" if all(v in ("ok", "unavailable") for v in checks.values()) else "degraded"
        return {"status": overall, "version": "0.9.0", "checks": checks}

    return app


app = create_app()
