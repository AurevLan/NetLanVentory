# Changelog

All notable changes to NetLanVentory are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [v0.3.0] — 2026-02-28

### Fixed
- **ZAP concurrency**: simultaneous scans no longer cause `IllegalThreadStateException` / `ConcurrentModificationException` — an `asyncio.Semaphore` now enforces `max_concurrent_scans` around every `_run_zap_scan` execution

### Added
- **HTTP security headers**: `SecurityHeadersMiddleware` injects `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`, and `Content-Security-Policy` on every response
- **Rate limiting** (`slowapi`): 10 req/min on `POST /auth/login`, 20 req/min on `POST /assets/{id}/zap`, 200 req/min global default — returns HTTP 429 on breach
- **ZAP API key**: `ZAP_API_KEY` config field propagated to all ZAP REST API calls
- **Secret detection**: logs a `WARNING` at startup when default secrets are used outside debug mode

### Changed
- **CORS**: removed `allow_credentials=True` (violates CORS spec when combined with `allow_origins=["*"]`); allowed origins configurable via `CORS_ALLOWED_ORIGINS` env var
- **JWT decode**: `sub`, `exp`, and `iss` claims are now required; issuer verified as `netlanventory`
- **Input validation**:
  - `target_url` uses `AnyHttpUrl` — rejects `ftp://`, `file://`, and other non-HTTP(S) schemes
  - Asset `ip` validated via `ipaddress.ip_address()`
  - Asset `mac` validated against `XX:XX:XX:XX:XX:XX` regex
  - Asset `ssh_port` constrained to 1–65535
  - `AssetDnsCreate.fqdn` validated against RFC-1123 hostname pattern
- **docker-compose**: `JWT_SECRET_KEY`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ZAP_API_KEY` now exposed as configurable env vars
- **Dependencies bumped**: `fastapi>=0.115.0`, `uvicorn>=0.32.0`, `sqlalchemy>=2.0.36`, `alembic>=1.14.0`, `pydantic>=2.10.0`, `pydantic-settings>=2.6.0`, `pyjwt>=2.10.0`, `bcrypt>=4.2.0`, `structlog>=24.4.0`, `scapy>=2.6.1`, `httpx>=0.28.0`, `asyncpg>=0.30.0`, `click>=8.1.8`, `rich>=13.9.4`, `anyio>=4.6.0`, `python-multipart>=0.0.12`, `email-validator>=2.2.0`
- **New dependency**: `slowapi>=0.1.9`

---

## [v0.2.0] — 2026-02-28

### Added
- **DNS management**: create and delete FQDN entries per asset (`/assets/{id}/dns`)
- **Editable asset fields**: inline edit modal for name, IP, MAC, SSH config, notes, device type, OS
- **CVE histogram**: risk summary chart (High / Medium / Low / Informational) on the Security tab
- **ZAP auto-scan scheduler**: configurable per-asset interval; background task fires scans automatically

---

## [v0.1.0] — 2026-02-27

### Added
- **Core project** implemented from scratch: FastAPI + PostgreSQL (async SQLAlchemy 2.0) + Click/Rich CLI
- **Network modules**: `arp_sweep`, `port_scanner`, `service_detector`, `os_fingerprint` — pluggable via `BaseModule` ABC
- **Docker Compose** stack: app, PostgreSQL, OWASP ZAP daemon, one-shot migration service
- **OWASP ZAP integration**: spider + passive scan, alert parsing, CVE extraction, technology detection
- **CVE tracking**: `Cve` + `AssetCve` models; severity mapping from ZAP risk levels
- **Local authentication**: bcrypt passwords, JWT (HS256) with OIDC-ready design
- **Administration panel**: user management, auth settings
- **Dashboard UI**: sidebar navigation, asset list, Security tab with ZAP reports and CVE display, Overview and Failles tabs

[v0.3.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.3.0
[v0.2.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.2.0
[v0.1.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.1.0
