# Changelog

All notable changes to NetLanVentory are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [v0.4.0] — 2026-02-28

### Added
- **SSH CVE scan**: connect to Linux assets via SSH (password **or** PEM private key) to audit installed packages and look up known CVEs
  - OSV.dev as primary source (batch up to 1000 packages/request, no API key required)
  - NVD NIST as optional fallback (`NVD_API_KEY` env var)
  - Supports Debian/Ubuntu (`dpkg`), RHEL/CentOS (`rpm`), Alpine (`apk`) package managers
  - Results persisted as `AssetCve` rows with `source="ssh"`, visible in the CVE table
  - Dedicated `SshScanReport` model tracks status, OS type, package count, and CVE count
  - API: `POST /api/v1/assets/{id}/ssh-scan`, `GET /api/v1/assets/{id}/ssh-scan`, `GET /api/v1/assets/{id}/ssh-scan/{report_id}`
  - Rate limit: 5 req/min per caller; max 2 concurrent SSH connections via semaphore
- **Encrypted SSH credentials**: `ssh_password` and `ssh_private_key` fields accepted on asset create/update; stored AES-encrypted (Fernet, key derived from `SECRET_KEY`); never returned in plain text
  - `AssetOut` exposes `has_ssh_password` and `has_ssh_key` boolean flags instead
  - Alembic migration `0006` adds `ssh_password_enc` and `ssh_private_key_enc` columns
  - Alembic migration `0007` creates the `ssh_scan_reports` table
- **ZAP auto-scan target visibility**: the Details tab in the asset modal now shows all URLs the scheduler would scan (IP × DNS names × web ports), computed client-side; displays time until next scheduled scan
- **Extensible "Sécurité" tab**: the old "Failles" tab is renamed and restructured
  - DAST section: existing OWASP ZAP content, unchanged
  - SSH section: trigger SSH package audit, view scan history and CVE count
  - Shared CVE table at the bottom aggregates all sources (ZAP + SSH)
  - Architecture is extensible for future SAST and other scan types
- **New dependencies**: `asyncssh>=2.14.0`, `cryptography>=42.0.0`
- **`NVD_API_KEY`** added to `docker-compose.yml` and `Settings`

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

[v0.4.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.4.0
[v0.3.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.3.0
[v0.2.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.2.0
[v0.1.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.1.0
