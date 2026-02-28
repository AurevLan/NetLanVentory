"""Application configuration via Pydantic BaseSettings."""

import logging
from functools import lru_cache
from typing import Literal

from pydantic import Field, computed_field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_log = logging.getLogger(__name__)

_DEFAULT_SECRETS = {
    "jwt_secret_key": "change-me-jwt-secret",
    "secret_key": "change-me-in-production",
    "admin_password": "changeme",
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://netlv:netlv_secret@localhost:5432/netlanventory",
        description="Async PostgreSQL connection URL",
    )

    # Application
    app_host: str = Field(default="0.0.0.0")
    app_port: int = Field(default=8000)
    app_debug: bool = Field(default=False)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO"
    )

    # Security — general
    secret_key: str = Field(default="change-me-in-production")

    # JWT — local authentication
    jwt_secret_key: str = Field(default="change-me-jwt-secret")
    jwt_algorithm: str = Field(default="HS256")
    jwt_access_token_expire_minutes: int = Field(default=60)

    # Bootstrap admin (created on first start if no users exist)
    admin_email: str = Field(default="admin@localhost")
    admin_password: str = Field(default="changeme")

    # OIDC connector (future — set these to enable OIDC login)
    oidc_enabled: bool = Field(default=False)
    oidc_issuer: str | None = Field(default=None)
    oidc_client_id: str | None = Field(default=None)
    oidc_client_secret: str | None = Field(default=None)

    # CVE lookup
    nvd_api_key: str = Field(
        default="",
        description="NVD NIST API key for fallback CVE lookup (optional)",
    )

    # ZAP web scanner
    zap_api_url: str = Field(
        default="http://localhost:8080",
        description="Base URL of the OWASP ZAP REST API daemon",
    )
    zap_api_key: str = Field(
        default="",
        description="OWASP ZAP API key (empty string = API key disabled in ZAP)",
    )

    # CORS
    cors_allowed_origins: list[str] = Field(
        default=["*"],
        description="Allowed CORS origins (configure via CORS_ALLOWED_ORIGINS env var)",
    )

    # Scanning defaults
    scan_timeout: int = Field(default=300, description="Default scan timeout in seconds")
    max_concurrent_scans: int = Field(default=3, description="Max simultaneous scans")

    @computed_field
    @property
    def sync_database_url(self) -> str:
        """Synchronous DB URL (for Alembic migrations)."""
        return self.database_url.replace("+asyncpg", "")

    @model_validator(mode="after")
    def _warn_default_secrets(self) -> "Settings":
        """Emit a warning when production-dangerous default secrets are detected."""
        if not self.app_debug:
            for field, default in _DEFAULT_SECRETS.items():
                if getattr(self, field) == default:
                    _log.warning(
                        "Default secret detected for '%s' — change before deploying to production!",
                        field,
                    )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
