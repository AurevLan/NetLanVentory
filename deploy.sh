#!/usr/bin/env bash
# =============================================================================
# deploy.sh — NetLanVentory deployment helper
#
# Usage:
#   ./deploy.sh              First-time deployment: generates .env and starts
#   ./deploy.sh --reinit     Regenerate ALL secrets (new .env, keep DB name/user)
#   ./deploy.sh --start      Start an already-configured stack
#   ./deploy.sh --stop       Stop the stack
#   ./deploy.sh --restart    Rebuild and restart the stack
#   ./deploy.sh --logs       Tail application logs
#   ./deploy.sh --help       Show this help
# =============================================================================
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }

# ── Locate project root ───────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
ENV_FILE="$SCRIPT_DIR/.env"

# ── Helpers ───────────────────────────────────────────────────────────────────
check_deps() {
    local missing=()
    command -v docker  &>/dev/null || missing+=("docker")
    command -v openssl &>/dev/null || missing+=("openssl")
    # docker compose (v2 plugin) or docker-compose (v1)
    if ! docker compose version &>/dev/null 2>&1; then
        missing+=("docker-compose-plugin (or docker compose v2)")
    fi
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing required tools: ${missing[*]}"
    fi
}

# Generate a cryptographically random hex string of <n> bytes (→ 2n hex chars)
rand_hex() { openssl rand -hex "${1:-32}"; }

# Generate a URL-safe base64 random string of <n> bytes
rand_b64() { openssl rand -base64 "${1:-32}" | tr '+/' '-_' | tr -d '=\n'; }

# ── .env generation ───────────────────────────────────────────────────────────
generate_env() {
    local force="${1:-false}"

    if [[ -f "$ENV_FILE" && "$force" != "true" ]]; then
        warn ".env already exists — skipping generation (use --reinit to regenerate)"
        return
    fi

    if [[ -f "$ENV_FILE" ]]; then
        local backup="$ENV_FILE.bak.$(date +%Y%m%d_%H%M%S)"
        cp "$ENV_FILE" "$backup"
        warn "Existing .env backed up to: $backup"
    fi

    info "Generating secrets…"

    local postgres_password; postgres_password="$(rand_hex 24)"
    local secret_key;        secret_key="$(rand_hex 32)"
    local jwt_secret_key;    jwt_secret_key="$(rand_hex 32)"
    local zap_api_key;       zap_api_key="$(rand_b64 24)"

    # Prompt for admin credentials
    local admin_email admin_password
    echo ""
    read -rp "$(echo -e "${BOLD}Admin e-mail${RESET} [admin@localhost]: ")" admin_email
    admin_email="${admin_email:-admin@localhost}"

    while true; do
        read -rsp "$(echo -e "${BOLD}Admin password${RESET} (leave blank to auto-generate): ")" admin_password
        echo ""
        if [[ -z "$admin_password" ]]; then
            admin_password="$(rand_b64 18)"
            warn "Auto-generated admin password — see summary below."
            break
        fi
        if [[ ${#admin_password} -lt 12 ]]; then
            warn "Password too short (min 12 characters). Try again."
        else
            break
        fi
    done

    cat > "$ENV_FILE" <<EOF
# =============================================================================
# NetLanVentory — environment configuration
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# WARNING: This file contains secrets — never commit it to version control.
# =============================================================================

# ── Database ──────────────────────────────────────────────────────────────────
DATABASE_URL=postgresql+asyncpg://netlv:${postgres_password}@localhost:5432/netlanventory
POSTGRES_DB=netlanventory
POSTGRES_USER=netlv
POSTGRES_PASSWORD=${postgres_password}

# ── Application ───────────────────────────────────────────────────────────────
APP_HOST=0.0.0.0
APP_PORT=8000
APP_DEBUG=false
LOG_LEVEL=INFO

# ── Security ──────────────────────────────────────────────────────────────────
SECRET_KEY=${secret_key}
JWT_SECRET_KEY=${jwt_secret_key}

# ── Bootstrap admin account (created on first start if no users exist) ────────
ADMIN_EMAIL=${admin_email}
ADMIN_PASSWORD=${admin_password}

# ── OWASP ZAP ─────────────────────────────────────────────────────────────────
# Enable ZAP API key: set api.disablekey=false in docker-compose.yml as well.
ZAP_API_KEY=${zap_api_key}

# ── NVD / CVE lookup (optional) ───────────────────────────────────────────────
# Register at https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=

# ── Nuclei scanner ────────────────────────────────────────────────────────────
NUCLEI_RATE_LIMIT=150
NUCLEI_TIMEOUT=30
MAX_CONCURRENT_NUCLEI_SCANS=2
EOF

    chmod 600 "$ENV_FILE"
    success ".env created (permissions: 600)"

    # Print summary (one-time display)
    echo ""
    echo -e "${BOLD}════════════════════════ GENERATED CREDENTIALS ════════════════════════${RESET}"
    echo -e "  ${CYAN}PostgreSQL password${RESET}  : ${postgres_password}"
    echo -e "  ${CYAN}SECRET_KEY${RESET}           : ${secret_key}"
    echo -e "  ${CYAN}JWT_SECRET_KEY${RESET}       : ${jwt_secret_key}"
    echo -e "  ${CYAN}ZAP API key${RESET}          : ${zap_api_key}"
    echo -e "  ${CYAN}Admin e-mail${RESET}         : ${admin_email}"
    echo -e "  ${CYAN}Admin password${RESET}       : ${admin_password}"
    echo -e "${BOLD}════════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${YELLOW}  Save these credentials now — they will not be shown again.${RESET}"
    echo ""
}

# ── Docker Compose helpers ────────────────────────────────────────────────────
dc() { docker compose "$@"; }

stack_start() {
    info "Building images and starting the stack…"
    dc up --build -d --remove-orphans
    echo ""
    info "Waiting for health checks…"
    local retries=0
    until dc ps --format json 2>/dev/null | grep -q '"Health":"healthy"' || [[ $retries -ge 30 ]]; do
        sleep 3
        (( retries++ ))
    done
    success "Stack is up."
    echo ""
    dc ps
    echo ""
    local port
    port="$(grep '^APP_PORT=' "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo 8000)"
    success "Dashboard → http://localhost:${port}"
    success "API docs  → http://localhost:${port}/docs"
}

stack_stop() {
    info "Stopping the stack…"
    dc down
    success "Stack stopped."
}

stack_restart() {
    info "Rebuilding and restarting the stack…"
    dc down
    dc up --build -d --remove-orphans
    success "Stack restarted."
}

# ── Argument parsing ──────────────────────────────────────────────────────────
show_help() {
    echo -e "${BOLD}NetLanVentory deployment script${RESET}"
    echo ""
    echo "Usage: ./deploy.sh [option]"
    echo ""
    echo "Options:"
    echo "  (none)       First-time deploy: generate .env (if missing) and start"
    echo "  --reinit     Regenerate ALL secrets and restart"
    echo "  --start      Start an already-configured stack (no rebuild)"
    echo "  --stop       Stop the stack"
    echo "  --restart    Rebuild images and restart"
    echo "  --logs       Tail logs for the app service"
    echo "  --help       Show this help"
}

main() {
    check_deps

    case "${1:-}" in
        "")
            generate_env "false"
            stack_start
            ;;
        --reinit)
            warn "This will regenerate ALL secrets. The database volume will be preserved,"
            warn "but the admin account and connection credentials will change."
            read -rp "$(echo -e "${RED}Continue? [y/N]${RESET} ")" confirm
            [[ "${confirm,,}" == "y" ]] || { info "Aborted."; exit 0; }
            dc down 2>/dev/null || true
            generate_env "true"
            stack_start
            ;;
        --start)
            [[ -f "$ENV_FILE" ]] || die ".env not found — run ./deploy.sh first"
            dc up -d --remove-orphans
            ;;
        --stop)
            stack_stop
            ;;
        --restart)
            stack_restart
            ;;
        --logs)
            dc logs -f app
            ;;
        --help|-h)
            show_help
            ;;
        *)
            error "Unknown option: ${1}"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
