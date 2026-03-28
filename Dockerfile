# ── Stage 0a: Nuclei binary ───────────────────────────────────────────────────
FROM projectdiscovery/nuclei:latest AS nuclei-bin

# ── Stage 0b: Trivy binary ────────────────────────────────────────────────────
FROM ghcr.io/aquasecurity/trivy:latest AS trivy-bin

# ── Stage 0c: testssl.sh ──────────────────────────────────────────────────────
FROM debian:bookworm-slim AS testssl-bin
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN curl -sSL https://github.com/drwetter/testssl.sh/raw/3.2/testssl.sh \
    -o /usr/local/bin/testssl.sh && chmod +x /usr/local/bin/testssl.sh

# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM python:3.14-slim AS builder

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
FROM python:3.14-slim AS test

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
FROM python:3.14-slim

LABEL org.opencontainers.image.title="NetLanVentory"
LABEL org.opencontainers.image.description="Modular network scanning and inventory tool"
LABEL org.opencontainers.image.version="0.13.0"

# Install runtime system dependencies
# nmap: port/OS scanning   iputils-ping: ping discovery
# openssl: required by testssl.sh   dnsutils: dig used by testssl.sh
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libpq5 \
    postgresql-client \
    iputils-ping \
    net-tools \
    openssl \
    dnsutils \
    bsdextrautils \
    && rm -rf /var/lib/apt/lists/*

# Install ssh-audit (Python package, no system dep needed)
RUN pip install --no-cache-dir ssh-audit

# Copy Nuclei binary from dedicated stage
COPY --from=nuclei-bin /usr/local/bin/nuclei /usr/local/bin/nuclei

# Copy Trivy binary from dedicated stage
COPY --from=trivy-bin /usr/local/bin/trivy /usr/local/bin/trivy

# Copy testssl.sh from dedicated stage
COPY --from=testssl-bin /usr/local/bin/testssl.sh /usr/local/bin/testssl.sh

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# ── Security: non-root user with NET_RAW capability ──────────────────────────
# Create a dedicated service account. The container runs as non-root by default.
# Raw socket access (ARP scans) is granted via NET_RAW capability in docker-compose.yml.
RUN groupadd --system netlv && \
    useradd --system --gid netlv --create-home --shell /usr/sbin/nologin netlv && \
    # nmap needs setuid for raw socket operations when run as non-root
    chmod u+s /usr/bin/nmap

WORKDIR /app

# Copy application source
COPY --chown=netlv:netlv netlanventory/ ./netlanventory/
COPY --chown=netlv:netlv alembic/ ./alembic/
COPY --chown=netlv:netlv alembic.ini .

# Create temp directories with correct ownership
RUN mkdir -p /tmp/netlv && chown netlv:netlv /tmp/netlv

# Switch to non-root user
USER netlv

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    TMPDIR=/tmp/netlv

EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8443/health')" || exit 1

CMD ["python", "-m", "uvicorn", "netlanventory.api.app:app", \
     "--host", "0.0.0.0", "--port", "8443", "--workers", "1"]
