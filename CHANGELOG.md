# Changelog

All notable changes to NetLanVentory are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

---

## [v0.15.0] — 2026-06-17

### Added
- **#5 Smart re-scan scheduler — queue wiring (opt-in)** — the priority queue
  can now *drive* auto-scans, not just observe. With
  `smart_scheduler_queue_enabled=true`, a new scheduler task
  (`core/scheduler.py::_drain_priority_queue`) pops the most urgent
  `(asset, module)` rows (`pop_due_priorities`), dispatches the scan via the new
  `core/scan_dispatch.py` router (`ssh_scan`, `trivy_docker`, `nuclei`,
  `headers_audit`), then resets the row (`mark_scanned`) — with
  `force_stale_into_queue` as the hourly famine guard. Undispatchable assets
  (no SSH creds / no open web port) are pushed forward via the new
  `scan_priority.defer()` instead of hot-looping the queue. While the flag is
  on, the fixed-interval SSH and Trivy loops yield to the queue (ZAP, not a
  tracked module, stays on its fixed interval). **Default off** → behaviour is
  unchanged until explicitly enabled.

### Changed
- **Innovation roadmap status clarified** — two axes are explicitly marked as
  preview/observational rather than active, so no feature is left half-wired:
  - **#5 Smart re-scan scheduler** is observational *by default*; the
    `smart_scheduler_queue_enabled` flag (see Added above) opts into
    queue-driven scanning. Docstrings and the `/scheduler` API now describe
    both modes.
  - **#3 AI-triage** documented as disabled-by-default preview. `OLLAMA_BASE_URL`
    / `OLLAMA_MODEL` are now configurable via env (were hardcoded). Corrected
    earlier notes: output field is `top_factors` (not `reasoning`), and OpenAI
    is not implemented (Ollama + Anthropic only).

---

## [v0.14.0] — 2026-04-14

### Added — Innovation roadmap (5 axes)

- **#2 Compensating controls engine** (`netlanventory/core/compensating_controls.py`) — per-CVE effective severity computed from KEV clamp, criticality tag, firewall posture, privesc state, WAF headers, network isolation. Endpoints: `GET /assets/{id}/effective-severities`, `GET /assets/{id}/cves/{cve_id}/effective-severity`. Feature-flagged via `use_compensating_controls` + new `shadow_mode_compensating_controls` flag to log would-be downgrades for 2 weeks of validation before flipping.
- **#5 Smart re-scan scheduler** (`netlanventory/core/scan_priority.py`, migration 0054) — per-(asset, module) priority score with `max_age_hours` famine guard and cooldown. **V1 is observational**: scores are computed hourly and exposed read-only; they do not drive auto-scans yet (the fixed-interval loops still run). Queue wiring is reserved behind `smart_scheduler_queue_enabled`. Endpoints: `GET /scheduler/priorities`, `GET /scheduler/budget`, `POST /scheduler/priorities/{id}/{module}/boost`.
- **#1 Attack path graph engine** (`netlanventory/core/attack_paths.py`, migration 0053) — networkx-based reachability graph with V1 adjacency by `/24`. Persists top-N critical chains `(source → target, hops, total_weight)`. Endpoints: `GET /attack-paths/critical`, `GET /attack-paths/asset/{id}/{inbound,outbound}`, `POST /attack-paths/refresh`.
- **#3 AI-triage** (`netlanventory/core/ai_triage.py`, migration 0056) — **preview, disabled by default** (`AI_TRIAGE_ENABLED=false` → `503`). Ollama-first (RGPD), Anthropic optional. Prompt-versioned cache with `input_hash` and `cached_until`. Strict Pydantic validation of LLM output (`urgency`, `one_liner`, `top_factors`). Endpoint: `GET /triage/{cve_id}/asset/{id}`. Requires an LLM provider (+ Redis for the cost guard); see `.env.example`.
- **#8 Remediation workflow** (`netlanventory/core/remediation_workflow.py`, migration 0055) — full state machine `draft → dry_run_pending → dry_run_done → awaiting_approval → approved → running → succeeded|failed|healthcheck_failed → rolled_back`. 4-eyes approval, playbook HMAC signature, execution log. Endpoints under `/remediation/`.
- **Remediation worker container** (`remediation_worker/`) — out-of-process Ansible executor, profile `remediation` in compose, read-only FS, cap-drop ALL, SSH key via docker secret, polls API only (no DB access), healthcheck mandatory for `criticality:critical` jobs.
- **Innovation UI module** (`netlanventory/api/static/innovation.js`, 367 lines) — 5 dashboard sections (compensating controls, attack paths, scheduler priorities, remediation kanban, AI triage) rendered standalone without touching the 9k-line `app.js`.

### Fixed

- **Remediation enum PG collision** (migrations 0055/0056) — rename `remediation_status` → `remediation_job_status`, `create_type=False` + `values_callable`, avoids SQLAlchemy/Alembic double-creation of the PG enum type.
- **Remediation router serialization** — `_to_out(job)` now runs before `commit()` on all 7 endpoints; `commit()` expires ORM attributes so serialization must happen after `flush()` but before commit.
- **Hardening router** — fixed indentation so `lynis_index`/`warnings`/`suggestions` are populated in the `lynis_available` branch instead of being unreachable.
- **`database.get_engine`** — drops `pool_size`/`max_overflow` when `DATABASE_URL` starts with `sqlite`; StaticPool rejects those kwargs and broke any production engine path under the test container.
- **Scheduler test harness** — hoist `get_settings`, `get_session_factory`, `httpx`, `Scan`, `_run_scan`, `_download_epss_map` to module level so tests can patch them via `patch.object(sched, ...)`.

### Tests

- **180 new tests** covering the 5 innovation axes.
- Full suite: **564 passed, 7 skipped** (up from 384).

---

## [v0.13.0] — 2026-03-28

### Added
- **Internal audit suite** — 5 new SSH-based audit modules for comprehensive host security assessment
  - **Privileged access audit** (`POST /assets/{id}/privesc-audit`) — enumerates users, sudoers (NOPASSWD detection), SUID/SGID binaries (GTFOBins risk flagging), Linux capabilities, SSH authorized keys, world-writable sensitive files, empty-password and UID 0 accounts
  - **Firewall rules audit** (`POST /assets/{id}/firewall-audit`) — auto-detects backend (iptables/nftables/ufw/firewalld), analyses default chain policies, enumerates rules, flags risky exposed ports (MySQL, Redis, MongoDB, Docker API, etc.), correlates with listening services
  - **Rootkit detection** (`POST /assets/{id}/rootkit-audit`) — runs chkrootkit and rkhunter (if available), manual checks for hidden processes, hidden ports, suspicious files in /dev and /tmp, deleted executables, loaded kernel modules
  - **Docker daemon security** (`POST /assets/{id}/docker-bench`) — CIS Docker Benchmark checks: socket permissions, user namespace, inter-container communication, content trust, privileged containers, host PID/network sharing, logging driver, daemon.json analysis
  - **Auth log analysis** (`POST /assets/{id}/auth-log-audit`) — parses journalctl/auth.log/secure, detects brute-force attacks (>20 failed attempts/IP), tracks failed/successful logins by user and source, alerts on root login from external IPs
- **IOC ↔ Asset correlation** (`GET /threat-intel/correlations`) — matches all collected threat IOCs (OTX, abuse.ch) against active assets by IP and DNS domain; per-asset correlation endpoint; severity/type/source breakdown
- **Audit diff / comparison** (`GET /assets/{id}/audit-diff`) — compares two full-audit jobs (N vs N-1): CVE delta (new/resolved/persistent), risk score evolution, per-step comparison (testssl grade, ssh-audit issues, default creds), overall posture assessment (improved/degraded/unchanged)
- **STIX 2.1 export** (`GET /export/stix/assets/{id}`, `GET /export/stix/all`) — native JSON STIX bundle (no external dependency): assets as Infrastructure, CVEs as Vulnerability with NVD references, open ports as observed-data, IOC matches as Indicator; deterministic IDs for deduplication
- **Full audit pipeline extended** from 8 to 13 steps: port_scan → testssl → ssh_audit → default_creds → ssh_scan → nuclei → exploit_validation → **privesc_audit → firewall_audit → rootkit_audit → docker_bench → auth_log_audit** → risk_score
- **Risk scoring enriched** with 4 new penalty factors:
  - Privilege escalation paths: +10 to +22 points (NOPASSWD sudo, GTFOBins SUID, dangerous capabilities)
  - No active firewall: +15 points
  - Rootkit detected: +30 to +40 points (highest after default credentials)
  - Active brute-force: +5 to +13 points
- **109 new tests** (384 total, from 275) across 4 new test files:
  - `test_internal_audit_endpoints.py` — 20 smoke tests for all 5 internal audit POST/GET endpoints
  - `test_internal_audit_parsers.py` — 41 unit tests for all parsing helpers (passwd, sudoers, capabilities, iptables, ufw, ss, chkrootkit, rkhunter, lastlog, IP classification, risk analysis)
  - `test_risk_score_extended.py` — 25 tests for new risk penalties (privesc, firewall, rootkit, brute-force, combinations, backwards compatibility)
  - `test_transverse_features.py` — 13 tests for IOC correlation, audit diff, STIX export

### Database
- Migration 0051: creates `privesc_reports`, `firewall_reports`, `rootkit_reports`, `docker_bench_reports`, `auth_log_reports` tables; adds 5 FK columns to `full_audit_jobs`

---

## [v0.12.0] — 2026-03-28

### Added
- **Vision 360° RSSI** — complete executive dashboard overhaul for security teams
  - 6 KPIs: risk score, critical CVEs, open CVEs, MTTR, trend, forecast to zero
  - Risk gauge + remediation funnel (5 statuses) + performance metrics
  - Severity × criticality heatmap table
  - Velocity chart (CVEs resolved per week, 12 weeks)
  - Burndown chart (open CVEs per day, 30 days)
  - 30-day trend chart (new / resolved / cumulative open)
  - Top 8 risky assets + security coverage bars + SLA dashboard
- **Remediation workflow** — track CVE remediation lifecycle
  - Statuses: open → planned → in_progress → resolved | blocked
  - `PATCH /assets/{id}/cves/{link_id}/remediation` (status, assigned_to, due_date, note)
  - `GET /remediation/stats` — funnel counts, MTTR, per-assignee breakdown
  - `GET /remediation/board` — Kanban view (5 columns, 50 items each)
  - Kanban board toggle in the remediation panel
- **Persistent SLA configuration** — stored in PostgreSQL (was in-memory)
  - Pre-seeded: critical 3d, high 7d, medium 30d, low 90d
  - Survives restarts
- **KPI daily snapshots** — scheduler saves daily metrics for historical tracking
  - Assets, CVEs, MTTR, SLA breaches, risk score avg, scan coverage
- **Executive API enriched** (`GET /executive/summary`)
  - `mttr_hours`, `velocity`, `burndown`, `forecast_days_to_zero`
  - `heatmap`, `sla_metrics`, `remediation_funnel`
  - `total_assets`, `active_assets`
- **288 tests** (from 256) — new `test_api_rssi_360.py` (22 tests)
- **Slate Shield v5 design** — professional dark theme replacing SOC Nightwatch
  - Inter + JetBrains Mono typography, cyan #22d3ee accent
  - Warm slate backgrounds, clean borders, no overlay effects
  - Filled gradient buttons, rounded corners, high readability

### Fixed
- `apiFetch is not defined` — 10 calls replaced with `api()` (timeline, compliance, executive, threat-intel, search, reports)
- `resp.json is not a function` — 6 redundant `.json()` calls on already-parsed API responses
- Null guard on all v0.9.0 page loaders (timeline, executive, compliance, search, threat-intel)
- 14 duplicate JS functions removed (1,123 dead lines causing broken assets/scans)
- CSP nonce conflict — removed nonce (browsers ignore unsafe-inline when nonce present)
- DB migrations 0037-0049 applied (all API 500 errors)
- Docker: Trivy registry, ZAP healthcheck, .env permissions, font loading
- Scan re-run creates duplicate rows → now updates in place
- CSP tests updated to match reality (unsafe-inline required for onclick handlers)

### Changed
- Scans table: new "Planification" column with inline interval dropdown
- Re-run updates same scan row (clears old results, resets status)
- Recurring scans re-use same row (no child scan creation)
- Design: SOC Nightwatch (green) → Slate Shield (cyan), no radar grid overlay

### Database
- Migration 0048: `scans` — recurring, recurring_interval_hours, recurring_last_triggered_at, recurring_run_count
- Migration 0049: `asset_cves` — remediation_status, assigned_to, due_date, started_at, resolved_at, note; `sla_configs` table; `kpi_snapshots` table

---

## [v0.11.0] — 2026-03-27

### Added
- **Scan planification** — any completed scan can be set to auto-repeat at a configurable interval (1h, 6h, 12h, daily, weekly, monthly) directly from the Scans tab
  - Inline dropdown + "Planifier" button in the new "Planification" column
  - Active scans show green badge with interval, run count, and countdown to next execution
  - "Modifier" to change interval, "Arrêter" to disable
  - `PUT /api/v1/scans/{id}/recurring?recurring=true&interval_hours=24`
- **Re-run in place** — re-running a scan updates the same row instead of creating a new one; previous results are cleared and the scan is re-executed
- **Hash-based routing** — browser back/forward buttons now work; URLs are shareable (`/#/assets`, `/#/admin`, `/#/topology`, etc.)
- **SOC Nightwatch design v4** — cybersecurity-focused visual identity
  - Phosphor green (#00ff9d) accent, Rajdhani + Source Code Pro fonts
  - Radar grid overlay, pulsing login ring, glowing nav indicators
  - Threat-level semantic colors (red/amber/green/purple)

### Fixed
- **apiFetch undefined** — replaced 10 calls to non-existent `apiFetch()` with the project's `api()` helper (timeline, compliance, executive, threat-intel, search, reports)
- **resp.json() double parse** — `api()` already returns parsed JSON; removed 6 redundant `.json()` calls that caused "is not a function" errors
- **Null guards** — all v0.9.0 page loaders (timeline, executive, compliance, search, threat-intel) now handle null API responses gracefully
- **14 duplicate JS functions** — removed 1,123 lines of duplicate function declarations that overwrote working code (loadAssets, openAssetModal, loadCves, etc.)
- **CSP nonce conflict** — removed nonce from CSP (browsers ignore `unsafe-inline` when a nonce is present; HTML uses hundreds of `onclick` handlers)
- **DB migrations** — applied pending migrations 0037-0048 that caused all API 500 errors
- **Docker** — fixed Trivy image registry (`ghcr.io/aquasecurity/trivy`), ZAP healthcheck, `.env` permission with non-root user
- **Font loading** — moved Google Fonts from CSS `@import` to HTML `<link>` (CSP-compatible)

### Changed
- **Scans table** — new columns (Target, Modules, Status, Date, Assets, Planification, Actions), removed ID column
- **Re-run behavior** — resets existing scan in place instead of creating a new row (409 Conflict if already running)
- **Scheduler** — recurring scans re-use the same scan row; skips scans already in pending/running state

---

## [v0.10.0] — 2026-03-27

### Added
- **Complete test suite** — 256 tests (from ~75), covering security regression, all API endpoints, CRUD, scan smoke tests, admin endpoints, auth/crypto unit tests
- **Security regression test suite** (`test_security_regression.py`) — 32 tests verifying CSP/HSTS/CORS headers, auth enforcement, input validation, password strength (ANSSI R22), JWT security, encryption
- **Scan endpoint smoke tests** (`test_api_scan_endpoints.py`) — 40 tests covering all 12 scanner types (Nuclei, SSH, ZAP, Trivy, testssl, ssh-audit, default-creds, headers-audit, SSL, baseline, full-audit, exploit-validation)
- **Admin endpoint tests** (`test_api_admin.py`) — 23 tests for users CRUD, settings, OIDC, audit logs, SSH profiles, quota, sessions, notifications, compliance, EPSS, KEV, reports
- **Auth & crypto unit tests** (`unit/test_auth_crypto.py`) — password hashing, ANSSI R22 validation, JWT create/decode/expired/invalid, encrypt/decrypt roundtrip
- **Makefile** with `make recette` (full acceptance), `make test-security`, `make test-coverage`, `make lint`, `make audit`
- **Recette script** (`scripts/recette.sh`) — 6-phase non-regression script with `--quick`, `--security`, `--coverage` modes
- **CI/CD overhaul** — lint job (ruff + mypy), test job (Python 3.11 + 3.12 with coverage), dependency security audit (pip-audit + bandit)
- **Ruff security rules** — added `S` (bandit), `B` (bugbear), `SIM`, `T20`, `PIE`, `RET`, `PTH` lint rules
- **Dev security tools** — `bandit>=1.9.0`, `safety>=3.3.0`, `pip-audit>=2.9.0` in dev dependencies
- **Pytest markers** — `security`, `smoke`, `crud`, `admin`, `unit`, `integration` for selective test execution

### Changed
- **Design overhaul: Obsidian Terminal v3** — complete CSS redesign with tactical operations aesthetic
  - Typography: DM Sans (body) + IBM Plex Mono (data/labels) replacing Inter
  - Color palette: ice-blue signal palette (#58a6ff accent, #3fb950 success, #f85149 danger, #d29922 warning)
  - CRT scanline texture overlay, grid pattern login background
  - Hairline rgba borders with 3 opacity tiers, deep void shadows
  - Square badges and angular elements, 2px left accent bars on active nav
  - Monospace data display throughout tables, badges, counters
  - 3 responsive breakpoints (1024px, 768px, 480px) instead of 1
  - `:focus-visible` outlines on all interactive elements, custom scrollbars
- **Dependency versions** — fastapi >=0.135.0, uvicorn >=0.42.0, sqlalchemy >=2.0.48, pydantic >=2.11.0, pyjwt >=2.12.0, cryptography >=46.0.0, structlog >=25.1.0, ruff >=0.11.0, mypy >=1.15.0, pytest >=8.5.0
- **Version bump** — 0.9.0 → 0.10.0

### Security
- **CSP nonce** — per-request nonce for scripts; `unsafe-inline` removed from `script-src`
- **HSTS** — `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- **Cross-origin isolation** — `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`
- **API cache prevention** — `Cache-Control: no-store` on all `/api/` responses
- **CSP hardening** — `frame-ancestors 'none'`, `base-uri 'self'`, `form-action 'self'`, `object-src 'none'`
- **CORS restricted** — default origins changed from `["*"]` to `["http://localhost:8443", "https://localhost:8443"]`
- **Bcrypt work factor** — increased from 12 to 14 rounds (ANSSI recommendation)
- **Password complexity** — mandatory 12+ chars with uppercase, lowercase, digit, and special character (ANSSI R22)
- **Default secrets blocked** — startup fails in production (APP_DEBUG=false) if default secrets are detected
- **Docker non-root** — new `netlv` service user, `cap_drop: ALL` + `cap_add: NET_RAW, NET_ADMIN`, `no-new-privileges`
- **Docker secrets required** — `SECRET_KEY`, `JWT_SECRET_KEY`, `ADMIN_PASSWORD`, `POSTGRES_PASSWORD` use `${VAR:?error}` syntax
- **PostgreSQL hardened** — `read_only: true`, `no-new-privileges`, tmpfs for /tmp and /run
- **ZAP API key** — enabled by default (was `api.disablekey=true`)
- **Input validation** — regex host/port validation in testssl.sh and ssh-audit routers, Docker image name validation in Trivy, IP address validation in CSV import
- **Token storage** — JWT moved from `localStorage` to `sessionStorage` (reduced XSS exposure)
- **XSS escape** — strengthened `escape()` function (backticks, forward slashes), added `escapeAttr()` for attribute contexts
- **Accessibility** — `role="dialog" aria-modal="true"` on all modal overlays

### Fixed
- **CVE enrichment test** — `mitre_techniques` field default is `[]` not `None`
- **Circuit breaker state names** — uppercase enum values (`CLOSED`/`OPEN`/`HALF_OPEN`)

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

[v0.13.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.13.0
[v0.12.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.12.0
[v0.6.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.6.0
[v0.5.1]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.5.1
[v0.5.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.5.0
[v0.4.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.4.0
[v0.3.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.3.0
[v0.2.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.2.0
[v0.1.0]: https://github.com/AurevLan/NetLanVentory/releases/tag/v0.1.0
