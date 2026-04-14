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

    # CORS — NEVER use ["*"] in production; set explicit origins
    cors_allowed_origins: list[str] = Field(
        default=["http://localhost:8443", "https://localhost:8443"],
        description="Allowed CORS origins (configure via CORS_ALLOWED_ORIGINS env var)",
    )

    # Nuclei scanner
    nuclei_binary: str = Field(
        default="nuclei",
        description="Path to the Nuclei binary (must be in PATH or absolute path)",
    )
    nuclei_templates_dir: str = Field(
        default="",
        description="Custom Nuclei templates directory (empty = default ~/.nuclei-templates)",
    )
    nuclei_rate_limit: int = Field(
        default=150,
        description="Nuclei requests per second rate limit",
    )
    nuclei_timeout: int = Field(
        default=30,
        description="Nuclei per-host timeout in seconds",
    )
    max_concurrent_nuclei_scans: int = Field(
        default=2,
        description="Max simultaneous Nuclei scans",
    )
    nuclei_scan_timeout: int = Field(
        default=1800,
        description="Overall Nuclei scan wall-clock timeout in seconds (default 30 min)",
    )

    # testssl.sh
    testssl_binary: str = Field(
        default="testssl.sh",
        description="Path to the testssl.sh binary (must be in PATH or absolute path)",
    )
    testssl_scan_timeout: int = Field(
        default=300,
        description="Overall testssl.sh scan wall-clock timeout in seconds (default 5 min)",
    )

    # ssh-audit (jtesta/ssh-audit)
    ssh_audit_binary: str = Field(
        default="ssh-audit",
        description="Path to the ssh-audit binary (must be in PATH or absolute path)",
    )

    # Scanning defaults
    scan_timeout: int = Field(default=300, description="Default scan timeout in seconds")
    max_concurrent_scans: int = Field(default=3, description="Max simultaneous ZAP scans")

    # Metasploit RPC (msfrpcd)
    msfrpc_host: str = Field(default="localhost", description="msfrpcd host")
    msfrpc_port: int = Field(default=55553, description="msfrpcd port")
    msfrpc_user: str = Field(default="msf", description="msfrpcd username")
    msfrpc_pass: str = Field(default="", description="msfrpcd password (empty = disabled)")
    msfrpc_ssl: bool = Field(default=True, description="Use SSL for msfrpcd connection")

    # Redis cache (optional)
    redis_url: str | None = Field(default=None, description="Redis URL for caching (e.g. redis://localhost:6379/0)")
    cache_ttl_seconds: int = Field(default=60, description="Default cache TTL in seconds")

    # SMTP (scheduled email reports, optional)
    smtp_host: str | None = Field(default=None, description="SMTP server hostname")
    smtp_port: int = Field(default=587, description="SMTP server port")
    smtp_user: str | None = Field(default=None, description="SMTP username")
    smtp_password: str | None = Field(default=None, description="SMTP password")
    smtp_from: str = Field(default="netlanventory@localhost", description="From address for sent emails")
    smtp_tls: bool = Field(default=True, description="Use STARTTLS for SMTP")

    # LDAP / Active Directory (optional)
    ldap_url: str | None = Field(default=None, description="LDAP server URL (e.g. ldap://dc.example.com)")
    ldap_bind_dn: str | None = Field(default=None, description="LDAP bind DN")
    ldap_bind_password: str | None = Field(default=None, description="LDAP bind password")
    ldap_base_dn: str | None = Field(default=None, description="LDAP base DN for computer search")

    # AWS (cloud asset discovery, optional)
    aws_region: str = Field(default="eu-west-1", description="AWS region for EC2 discovery")
    aws_access_key_id: str | None = Field(default=None, description="AWS access key ID")
    aws_secret_access_key: str | None = Field(default=None, description="AWS secret access key")

    # Azure (cloud asset discovery, optional)
    azure_subscription_id: str | None = Field(default=None, description="Azure subscription ID")
    azure_tenant_id: str | None = Field(default=None, description="Azure tenant ID")
    azure_client_id: str | None = Field(default=None, description="Azure service principal client ID")
    azure_client_secret: str | None = Field(default=None, description="Azure service principal client secret")

    # Threat Intelligence
    otx_api_key: str | None = Field(default=None, description="AlienVault OTX API key")

    # Passive discovery
    passive_discovery_enabled: bool = Field(default=False, description="Enable passive ARP/DHCP discovery")
    passive_interface: str = Field(default="eth0", description="Network interface for passive discovery")

    # Default daily scan (all active assets)
    default_scan_enabled: bool = Field(default=True, description="Enable default daily network scan of all active assets")
    default_scan_interval_hours: int = Field(default=24, description="Interval (hours) between default network scans")
    default_scan_modules: str = Field(
        default="arp_sweep,port_scanner,service_detector,os_fingerprint",
        description="Comma-separated modules for default scan",
    )

    # SSH profile auto-test
    ssh_profile_test_enabled: bool = Field(default=True, description="Enable automatic SSH profile connectivity testing")
    ssh_profile_test_interval_hours: int = Field(default=24, description="Interval (hours) between SSH profile tests")

    # Additional scanners (all agentless — run locally)
    nikto_binary: str = Field(default="nikto", description="Path to nikto binary")
    subfinder_binary: str = Field(default="subfinder", description="Path to subfinder binary")
    masscan_binary: str = Field(default="masscan", description="Path to masscan binary (requires root/CAP_NET_RAW)")
    masscan_default_rate: int = Field(default=10000, description="Default masscan packets/second rate")

    # Compensating Controls (innovation #2). Default OFF — opt-in after shadow validation.
    use_compensating_controls: bool = Field(
        default=False,
        description="Use effective severity (post-controls) in risk score computation",
    )

    @computed_field
    @property
    def sync_database_url(self) -> str:
        """Synchronous DB URL (for Alembic migrations)."""
        return self.database_url.replace("+asyncpg", "")

    @model_validator(mode="after")
    def _warn_default_secrets(self) -> "Settings":
        """Emit a warning or block startup when default secrets are used in production."""
        for field, default in _DEFAULT_SECRETS.items():
            if getattr(self, field) == default:
                if self.app_debug:
                    _log.warning(
                        "Default secret detected for '%s' — change before deploying!",
                        field,
                    )
                else:
                    raise ValueError(
                        f"SECURITY: Default value for '{field}' is forbidden in production. "
                        f"Set {field.upper()} environment variable to a strong random value."
                    )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
