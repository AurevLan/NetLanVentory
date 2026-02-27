# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY pyproject.toml .
RUN pip install --upgrade pip && \
    pip install --no-cache-dir --prefix=/install \
    "hatchling" && \
    pip install --no-cache-dir --prefix=/install .

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
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

# Create non-root user (but keep root capabilities for raw sockets)
RUN groupadd -r netlv && useradd -r -g netlv -d /app netlv && \
    chown -R netlv:netlv /app

# Allow nmap + scapy to use raw sockets without full root
RUN setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap 2>/dev/null || true && \
    setcap cap_net_raw,cap_net_admin+eip $(which python3.11) 2>/dev/null || true

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

USER netlv

CMD ["python", "-m", "uvicorn", "netlanventory.api.app:app", \
     "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
