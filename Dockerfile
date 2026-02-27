# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies (runtime + dev extras)
COPY pyproject.toml README.md ./
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install \
    "hatchling" && \
    pip install --no-cache-dir --prefix=/install ".[dev]"

# ── Stage 2: Test runner ──────────────────────────────────────────────────────
FROM python:3.11-slim AS test

WORKDIR /app

# Copy installed packages (includes dev deps: pytest, httpx, aiosqlite…)
COPY --from=builder /install /usr/local

# Copy source and tests
COPY netlanventory/ ./netlanventory/
COPY tests/ ./tests/
COPY alembic/ ./alembic/
COPY alembic.ini .

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

CMD ["pytest", "tests/", "-v", "--tb=short"]

# ── Stage 3: Runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim

LABEL org.opencontainers.image.title="NetLanVentory"
LABEL org.opencontainers.image.description="Modular network scanning and inventory tool"
LABEL org.opencontainers.image.version="0.1.0"

# Install runtime system dependencies
# nmap: port/OS scanning   libpcap-dev: ARP capture (scapy)   iputils-ping: ping fallback
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libpcap-dev \
    libpq5 \
    postgresql-client \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy application source
COPY netlanventory/ ./netlanventory/
COPY alembic/ ./alembic/
COPY alembic.ini .

# Network scanning requires raw socket access — run as root
# (NET_ADMIN + NET_RAW capabilities are set in docker-compose.yml)

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["python", "-m", "uvicorn", "netlanventory.api.app:app", \
     "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
