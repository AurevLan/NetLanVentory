# NetLanVentory

Modular network scanning and inventory tool. Discover hosts, scan ports, fingerprint services and operating systems, and browse everything through a REST API or CLI.

## Features

- **ARP sweep** — Layer 2 host discovery via scapy, with async ICMP ping fallback
- **Port scanner** — TCP SYN/connect scan powered by nmap
- **Service detector** — async banner grabbing + nmap `-sV` version detection
- **OS fingerprinting** — nmap `-O` with heuristic fallback based on open ports
- **Modular architecture** — add a new scanner by dropping a single file in `netlanventory/modules/`
- **REST API** — FastAPI with OpenAPI docs at `/docs`
- **Web dashboard** — dark-theme SPA at `http://localhost:8000`
- **CLI** — `netlv` command with Rich-formatted tables and live progress

## Requirements

- Docker + Docker Compose (recommended)
- **or** Python 3.11+, PostgreSQL 14+, nmap, libpcap

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

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/assets` | List assets (supports `?active_only`, `?limit`, `?skip`) |
| `GET` | `/api/v1/assets/{id}` | Get asset by UUID |
| `GET` | `/api/v1/assets/by-ip/{ip}` | Get asset by IP address |
| `POST` | `/api/v1/assets` | Create asset manually |
| `PATCH` | `/api/v1/assets/{id}` | Update asset fields |
| `DELETE` | `/api/v1/assets/{id}` | Delete asset |
| `GET` | `/api/v1/scans` | List scans |
| `POST` | `/api/v1/scans` | Start a new scan (async, 202 Accepted) |
| `GET` | `/api/v1/scans/{id}` | Get scan status and results |
| `DELETE` | `/api/v1/scans/{id}` | Delete scan |
| `GET` | `/api/v1/modules` | List registered modules |
| `GET` | `/api/v1/modules/{name}` | Get module metadata + options schema |

### Start a scan via API

```bash
curl -X POST http://localhost:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "target": "192.168.1.0/24",
    "modules": ["arp_sweep", "port_scanner", "service_detector", "os_fingerprint"]
  }'
```

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
│   ├── core/          # config, async DB engine, structlog, module registry
│   ├── models/        # SQLAlchemy ORM (Asset, Scan, Port, ScanResult)
│   ├── schemas/       # Pydantic request/response schemas
│   ├── modules/       # BaseModule ABC + built-in scanners
│   ├── api/           # FastAPI app, routers, static dashboard
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
| CLI | Click + Rich |
| Logging | structlog |
| Container | Docker Compose |

## License

MIT
