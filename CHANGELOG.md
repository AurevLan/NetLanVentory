# Changelog

All notable changes to NetLanVentory are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

---

## [v0.6.0] — 2026-03-03

### Added
- **Global CVE library** (`GET /api/v1/cves`, `GET /api/v1/cves/{id}`, `POST /api/v1/cves/enrich`)
  - Cross-asset CVE view: list all known CVEs with severity filter, free-text search, and pagination
  - Each CVE detail shows all affected assets and their package/version information
  - "Enrichir" button triggers a global background enrichment pass for CVEs still missing CVSS scores or descriptions
  - Sidebar navigation with CVE count badge; accessible via the shield icon
- **CVE fix version tracking** — `asset_cves.fixed_version` column stores the version that patches a given CVE (extracted from OSV `affected[].ranges[].events[fixed]`); shown as a "Version corrigée" column in the CVE table
- **Non-standard CVE ID support** — complete handling of Ubuntu / Debian advisory IDs throughout the stack:
  - `UBUNTU-CVE-YYYY-NNNNN` → looks up the canonical `CVE-YYYY-NNNNN` on OSV.dev; link routes to `ubuntu.com/security/`
  - `USN-XXXX-X` → queries OSV directly (OSV indexes Ubuntu Security Notices); link routes to `ubuntu.com/security/notices/`
  - `GHSA-XXXX-XXXX-XXXX` → queries OSV directly; link routes to `github.com/advisories/`
  - Standard `CVE-YYYY-NNNNN` IDs continue to link to NVD as before
  - `cves.cve_id` column widened to `VARCHAR(50)` (migration `0009`) to accommodate longer advisory IDs
- **Live CVE data updates** — all three scanners (ZAP, SSH, Nuclei) now update existing CVE rows in the database when they encounter a known ID; if severity, description, CVSS score, published date, or fixed version is missing, it is enriched on the next scan
- **Two-phase scan architecture** — CVE enrichment (OSV + NVD API calls) now runs *after* releasing the scan semaphore, so long enrichment passes (up to 6 min for 60 CVEs without NVD key) no longer block new scan requests
- **Stale-source cleanup** — SSH and Nuclei scanners now remove their previous CVE attributions at the start of each new scan, ensuring the CVE table reflects only current findings (no stale rows from old scans)

### Fixed
- **SSH scan `BackgroundTasks` lifecycle** — changed from `asyncio.create_task()` (task silently dies when the request scope ends) to FastAPI `BackgroundTasks.add_task()` with an explicit `db.commit()` before scheduling; SSH scans no longer get stuck in `pending` state after the first request
- **OSV severity parsing** — `_osv_severity()` previously called `float(score_str)` which always raised `ValueError` on CVSS vector strings returned by OSV; severity now correctly reads text labels (`"critical"`, `"high"`, `"medium"`, `"low"`) from the `{"type": "...", "score": "..."}` structure
- **NVD link for non-CVE advisory IDs** — clicking any advisory ID in the CVE table now routes to the correct upstream source via `cveUrl()` instead of always going to NVD (which returns 404 for `UBUNTU-CVE-*` / `USN-*`)
- **Scan polling race condition** — captured `const assetId = _modalAssetId` at poll-loop start; prevents cross-asset 404 errors when the user switches modals during a running scan (same fix applied to SSH and Nuclei pollers)

### Changed
- **Alembic migration `0009`** — `cves.cve_id` VARCHAR(20) → VARCHAR(50)
- **Alembic migration `0010`** — adds `asset_cves.fixed_version VARCHAR(100)`
- **CVE table column** — "Source" badges split by `,` and rendered as individual `<span>` pills; new "Version corrigée" column added
- **SSH test container** — removed `ssh-target` service and `Dockerfile.ssh-target` from the repository (was a development-only artefact, not needed in production)

### Security
- **Dependency audit** — all runtime dependencies verified up to date as of 2026-03-03 (fastapi 0.135.1, sqlalchemy 2.0.48, cryptography 46.0.5, pyjwt 2.10.1, asyncssh 2.20.0, httpx 0.28.1)
- **Known limitation (CSP)** — `script-src` still includes `'unsafe-inline'` due to inline `onclick` handlers in the dashboard HTML; migrating to `addEventListener`-based event binding is tracked as a future improvement (impact is low: the dashboard is served only to authenticated users)

---

## [v0.5.1] — 2026-03-02

### Fixed
- **Nuclei v3 output flag**: replace `-json` with `-jsonl` (flag renamed in Nuclei v3); the old flag caused silent failure (exit 0, empty stdout) resulting in zero findings
- **Scan polling race condition** (Nuclei & SSH): `_modalAssetId` could change between `await` calls in the polling loop when the user switched asset modals during a running scan, causing cross-asset HTTP 404 errors ("report not found"); fix captures the asset ID at scan start and guards the loop with `_modalAssetId === assetId`

---

## [v0.5.0] — 2026-03-02

### Added
- **Nuclei multi-protocol scanner**: scan assets with [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei) directly from the Sécurité tab
  - Targets are **auto-determined** from discovered open ports and services: HTTP/HTTPS, DNS, FTP, SMTP, SMB, MySQL, PostgreSQL, Redis, MongoDB, RDP — no manual URL required
  - DNS entries (FQDNs) are automatically included for web targets so virtual-host templates fire
  - API: `POST /api/v1/assets/{id}/nuclei`, `GET /api/v1/assets/{id}/nuclei`, `GET /api/v1/assets/{id}/nuclei/{report_id}`
  - Rate limit: 10 req/min; max 2 concurrent scans via semaphore (configurable via `MAX_CONCURRENT_NUCLEI_SCANS`)
  - `NucleiReport` model stores targets, tags, parsed findings (JSONL), risk summary, and CVE count
  - Alembic migration `0008` creates `nuclei_reports` table
- **Multi-source CVE tracking**: a CVE found by multiple scanners now appears as a single row in the CVE table with all sources listed (e.g. "zap + nuclei")
  - `asset_cves.source` column widened to `VARCHAR(50)` to hold comma-separated values
  - ZAP, SSH, and Nuclei persistence functions all use the same append-source pattern
- **Nuclei binary bundled** in Docker image via multi-stage build (`projectdiscovery/nuclei:latest`)
  - Nuclei templates persisted in a dedicated `nuclei_templates` Docker volume to avoid re-downloading on restart
  - Configurable via `NUCLEI_RATE_LIMIT`, `NUCLEI_TIMEOUT`, `MAX_CONCURRENT_NUCLEI_SCANS` env vars

### Changed
- **Docker**: bump base image `python:3.11-slim` → `python:3.14-slim`

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

[v0.6.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.6.0
[v0.5.1]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.5.1
[v0.5.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.5.0
[v0.4.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.4.0
[v0.3.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.3.0
[v0.2.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.2.0
[v0.1.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.1.0
