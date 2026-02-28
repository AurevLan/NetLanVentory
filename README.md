# NetLanVentory

Modular network scanning and inventory tool. Discover hosts, scan ports, fingerprint services and operating systems, manage DNS associations, run ZAP web vulnerability scans, and browse everything through a REST API or a dark-theme web dashboard.

## Features

### Network discovery & scanning
- **ARP sweep** — Layer 2 host discovery via scapy, with async ICMP ping fallback
- **Port scanner** — TCP SYN/connect scan powered by nmap
- **Service detector** — async banner grabbing + nmap `-sV` version detection
- **OS fingerprinting** — nmap `-O` with heuristic fallback based on open ports
- **Modular architecture** — add a new scanner by dropping a single file in `netlanventory/modules/`

### Asset management
- **Editable asset fields** — hostname, OS family/version, device type, editable directly from the dashboard with evolving autocomplete suggestions (`<datalist>`) populated from existing values in the database
- **DNS association** — attach multiple FQDN/DNS names to each asset; names are used by ZAP scans as additional scan targets

### ZAP web vulnerability scanning
- **On-demand ZAP scans** — trigger a ZAP spider + active scan against any asset directly from the dashboard
- **CVE tracking** — each ZAP report counts the CVEs found in the alerts; tracked per scan
- **CVE evolution histogram** — Overview tab in the asset modal shows a mixed Chart.js chart: stacked bars (High / Medium / Low / Info alerts) + a purple line (CVE count) per scan, with a right-hand Y-axis; single-scan view shows the traditional horizontal bar chart
- **ZAP auto-scan scheduler** — server-side asyncio loop (checks every 60 s) automatically triggers ZAP scans against all active assets that have web ports open (80, 443, 8080, 8443, 8000, 3000, 4443); scan targets include the asset IP **and all associated DNS names**

### ZAP auto-scan settings
- **Global master switch** — enable/disable auto-scan and set a default interval (minutes) from the admin panel → *ZAP Auto-scan* tab
- **Per-asset override** — each asset can individually enable/disable auto-scan and override the global interval; `NULL` on an asset means "use global value"

### Security & authentication
- **JWT authentication** — all API endpoints require a valid Bearer token (except `/api/v1/auth/login`)
- **Role-based access** — `admin` role required for user management and global settings
- **OIDC / SSO** — optional OpenID Connect provider configured via the admin panel
- **User management** — create, activate/deactivate and delete users from the dashboard

### Infrastructure
- **REST API** — FastAPI with OpenAPI docs at `/docs`
- **Web dashboard** — dark-theme SPA at `http://localhost:8000`
- **CLI** — `netlv` command with Rich-formatted tables and live progress

---

## Requirements

- Docker + Docker Compose (recommended)
- **or** Python 3.11+, PostgreSQL 14+, nmap, libpcap, OWASP ZAP (for ZAP features)

## Quick start with Docker

```bash
git clone https://github.com/AurevLan/NetLanVentory.git
cd NetLanVentory
cp .env.example .env          # edit passwords / SECRET_KEY as needed
docker compose up --build
```

| Service | URL |
|---------|-----|
| Dashboard | http://localhost:8000 |
| API docs (Swagger) | http://localhost:8000/docs |
| ReDoc | http://localhost:8000/redoc |

> **Note:** The app container uses `network_mode: host` so scapy can send raw ARP frames. It requires `NET_ADMIN` and `NET_RAW` capabilities (set automatically by Docker Compose).

## Default admin account

On first startup, a default admin account is automatically created if no users exist in the database:

| Field | Default value |
|-------|---------------|
| Email | `admin@localhost` |
| Password | `changeme` |

**Change these before exposing the app on a network.** Edit `.env` before the first `docker compose up`:

```env
ADMIN_EMAIL=your@email.com
ADMIN_PASSWORD=a-strong-password
JWT_SECRET_KEY=<openssl rand -hex 32>
```

> The bootstrap only runs once (when the `users` table is empty). If the stack is already running, change the password via the dashboard → **Users** tab, or recreate the database volume (`docker compose down -v && docker compose up --build`) to trigger a fresh bootstrap.

## Local development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Start PostgreSQL (or point DATABASE_URL at an existing instance)
cp .env.example .env

# Run migrations
alembic upgrade head

# Start the API server
netlv serve --reload
```

## CLI usage

```bash
# List available scanning modules
netlv modules list

# Run a full scan (requires root for SYN scan + ARP)
sudo netlv scan run \
  --target 192.168.1.0/24 \
  --modules arp_sweep,port_scanner,service_detector,os_fingerprint

# Browse results
netlv assets list
netlv assets list --active-only --filter 192.168.1

# Show full detail for a host
netlv assets show 192.168.1.1

# List past scans
netlv scan list

# Point the CLI at a remote API server
netlv --api-url http://my-server:8000 assets list
```

## REST API

### Assets

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/assets` | List assets (`?active_only`, `?limit`, `?skip`) |
| `GET` | `/api/v1/assets/vocabulary` | Distinct OS families and device types for autocomplete |
| `GET` | `/api/v1/assets/{id}` | Get asset by UUID |
| `GET` | `/api/v1/assets/by-ip/{ip}` | Get asset by IP address |
| `POST` | `/api/v1/assets` | Create asset manually |
| `PATCH` | `/api/v1/assets/{id}` | Update asset fields (hostname, os_family, os_version, device_type, zap_auto_scan_enabled, zap_scan_interval_minutes, …) |
| `DELETE` | `/api/v1/assets/{id}` | Delete asset |

### DNS entries

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/assets/{id}/dns` | List DNS entries for an asset |
| `POST` | `/api/v1/assets/{id}/dns` | Add a DNS entry (`{ "fqdn": "host.example.com" }`) |
| `DELETE` | `/api/v1/assets/{id}/dns/{dns_id}` | Remove a DNS entry |

### Scans & modules

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/scans` | List scans |
| `POST` | `/api/v1/scans` | Start a new scan (async, 202 Accepted) |
| `GET` | `/api/v1/scans/{id}` | Get scan status and results |
| `DELETE` | `/api/v1/scans/{id}` | Delete scan |
| `GET` | `/api/v1/modules` | List registered modules |
| `GET` | `/api/v1/modules/{name}` | Get module metadata + options schema |

### ZAP

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/zap/scan` | Launch a ZAP scan against a target URL |
| `GET` | `/api/v1/zap/reports` | List ZAP reports (supports `?asset_id`) |
| `GET` | `/api/v1/zap/reports/{id}` | Get full ZAP report with alerts and CVE count |
| `DELETE` | `/api/v1/zap/reports/{id}` | Delete a ZAP report |

### Admin

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/admin/zap-settings` | Get global ZAP auto-scan settings |
| `PUT` | `/api/v1/admin/zap-settings` | Update global ZAP auto-scan settings |
| `GET` | `/api/v1/admin/oidc` | Get OIDC provider configuration |
| `PUT` | `/api/v1/admin/oidc` | Update OIDC provider configuration |

### Authentication & users

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/auth/login` | Obtain JWT token (`application/x-www-form-urlencoded`) |
| `GET` | `/api/v1/users/me` | Current user profile |
| `GET` | `/api/v1/users` | List users (admin only) |
| `POST` | `/api/v1/users` | Create user (admin only) |
| `PATCH` | `/api/v1/users/{id}` | Update user (admin only) |
| `DELETE` | `/api/v1/users/{id}` | Delete user (admin only) |

### Start a scan via API

```bash
curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -d 'username=admin@localhost&password=changeme' | jq -r .access_token
# → <TOKEN>

curl -X POST http://localhost:8000/api/v1/scans \
  -H 'Authorization: Bearer <TOKEN>' \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "192.168.1.0/24",
    "modules": ["arp_sweep", "port_scanner", "service_detector", "os_fingerprint"]
  }'
```

## ZAP auto-scan configuration

1. Open the dashboard → **Admin** → **ZAP Auto-scan**
2. Enable the global master switch and set a default interval (1–10 080 minutes)
3. For each asset that needs a different schedule (or to opt out), open the asset modal → **Details** tab → toggle *ZAP auto-scan* and optionally set a per-asset interval

The scheduler wakes every 60 seconds and launches a scan whenever:
- auto-scan is enabled for an asset (asset toggle, or global if asset toggle is unset), **and**
- the configured interval has elapsed since the last auto-scan, **and**
- the asset has at least one open web port (80, 443, 8080, 8443, 8000, 3000, 4443)

Scan targets are built automatically: `{scheme}://{ip}` + `{scheme}://{fqdn}` for every DNS name attached to the asset.

## Adding a module

Create `netlanventory/modules/my_module.py`:

```python
from netlanventory.modules.base import BaseModule, ModuleCategory, ModuleMetadata

class MyModule(BaseModule):
    metadata = ModuleMetadata(
        name="my_module",
        display_name="My Module",
        version="1.0.0",
        category=ModuleCategory.SERVICE,
        description="Does something useful.",
        author="You",
        requires_root=False,
        options_schema={
            "type": "object",
            "properties": {
                "target": {"type": "string"},
            },
            "required": ["target"],
        },
    )

    async def run(self, session, options):
        # ... your logic here ...
        return {
            "module": self.metadata.name,
            "status": "success",
            "assets_found": 0,
            "details": {},
        }
```

Restart the server — the module is auto-discovered and immediately available via `netlv modules list` and the API.

## Project structure

```
NetLanVentory/
├── netlanventory/
│   ├── core/          # config, async DB engine, structlog, module registry, scheduler
│   ├── models/        # SQLAlchemy ORM (Asset, Scan, Port, ScanResult, AssetDns, GlobalSettings, ZapReport, …)
│   ├── schemas/       # Pydantic request/response schemas
│   ├── modules/       # BaseModule ABC + built-in scanners
│   ├── api/
│   │   ├── routers/   # assets, scans, modules, zap, dns, auth, users, admin
│   │   └── static/    # Single-page dashboard (HTML + JS + CSS, no build step)
│   └── cli/           # Click commands, Rich output helpers
├── alembic/           # Database migrations
├── tests/             # pytest-asyncio test suite (SQLite in-memory)
├── Dockerfile
└── docker-compose.yml
```

## Running tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

Tests use SQLite in-memory — no PostgreSQL required.

## Tech stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.11 |
| API framework | FastAPI + Uvicorn |
| Database | PostgreSQL 16 (asyncpg / SQLAlchemy 2.0) |
| Migrations | Alembic |
| Scanning | scapy, python-nmap |
| Web vulnerability scanning | OWASP ZAP |
| CLI | Click + Rich |
| Logging | structlog |
| Container | Docker Compose |

## License

MIT
