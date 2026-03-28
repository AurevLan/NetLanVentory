#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  NetLanVentory — Script de recette / Non-regression test suite     ║
# ║                                                                     ║
# ║  Usage:                                                            ║
# ║    ./scripts/recette.sh              # Full recette                ║
# ║    ./scripts/recette.sh --quick      # Quick smoke tests only      ║
# ║    ./scripts/recette.sh --security   # Security tests only         ║
# ║    ./scripts/recette.sh --coverage   # With coverage report        ║
# ╚══════════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Configuration ────────────────────────────────────────────────────
export SECRET_KEY="${SECRET_KEY:-test-secret-key-for-recette}"
export JWT_SECRET_KEY="${JWT_SECRET_KEY:-test-jwt-secret-key-recette}"
export ADMIN_PASSWORD="${ADMIN_PASSWORD:-Recette1234!@#\$}"
export APP_DEBUG="${APP_DEBUG:-true}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# ── Counters ─────────────────────────────────────────────────────────
PASS=0
FAIL=0
SKIP=0
TOTAL_START=$(date +%s)

# ── Helpers ──────────────────────────────────────────────────────────
step() {
    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}  $1${RESET}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
}

pass() {
    echo -e "  ${GREEN}✓ PASS${RESET} — $1"
    ((PASS++))
}

fail() {
    echo -e "  ${RED}✗ FAIL${RESET} — $1"
    ((FAIL++))
}

skip() {
    echo -e "  ${YELLOW}○ SKIP${RESET} — $1"
    ((SKIP++))
}

run_test() {
    local name="$1"
    shift
    if "$@" > /dev/null 2>&1; then
        pass "$name"
    else
        fail "$name"
    fi
}

# ── Parse arguments ──────────────────────────────────────────────────
MODE="full"
COVERAGE_FLAG=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick)    MODE="quick"; shift ;;
        --security) MODE="security"; shift ;;
        --coverage) COVERAGE_FLAG="--cov=netlanventory --cov-report=term-missing --cov-report=html:htmlcov"; shift ;;
        --help|-h)
            echo "Usage: $0 [--quick|--security|--coverage]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo -e "${BOLD}${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║       NetLanVentory — Recette Non-Régression            ║"
echo "║       Mode: ${MODE}                                     ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${RESET}"
echo "  Date:    $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Python:  $(python3 --version 2>/dev/null || echo 'not found')"
echo "  Dir:     $PROJECT_DIR"
echo ""

# ══════════════════════════════════════════════════════════════════════
# PHASE 1: Pre-flight checks
# ══════════════════════════════════════════════════════════════════════
step "PHASE 1: Pre-flight Checks"

# Check Python
if command -v python3 &>/dev/null; then
    pass "Python3 available ($(python3 --version))"
else
    fail "Python3 not found"
    echo -e "${RED}Cannot continue without Python3${RESET}"
    exit 1
fi

# Check pytest
if python3 -m pytest --version &>/dev/null; then
    pass "pytest available"
else
    fail "pytest not installed (run: pip install -e '.[dev]')"
    exit 1
fi

# Check ruff
if python3 -m ruff --version &>/dev/null; then
    pass "ruff linter available"
else
    skip "ruff not installed"
fi

# Check project structure
for f in netlanventory/api/app.py tests/conftest.py pyproject.toml; do
    if [[ -f "$f" ]]; then
        pass "File exists: $f"
    else
        fail "Missing file: $f"
    fi
done

# ══════════════════════════════════════════════════════════════════════
# PHASE 2: Static Analysis (skip in --quick mode)
# ══════════════════════════════════════════════════════════════════════
if [[ "$MODE" != "quick" ]]; then
    step "PHASE 2: Static Analysis"

    # Ruff lint
    if python3 -m ruff check netlanventory/ tests/ --quiet 2>/dev/null; then
        pass "Ruff lint — no issues"
    else
        fail "Ruff lint — issues found"
    fi

    # Security-specific lint rules
    if python3 -m ruff check netlanventory/ --select S --quiet 2>/dev/null; then
        pass "Bandit security rules (via ruff) — clean"
    else
        fail "Bandit security rules — issues found"
    fi
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 3: Unit Tests
# ══════════════════════════════════════════════════════════════════════
if [[ "$MODE" != "security" ]]; then
    step "PHASE 3: Unit Tests"

    echo -e "  Running unit tests..."
    if python3 -m pytest tests/unit/ tests/test_registry.py tests/test_scoring.py tests/test_config.py \
        -v --tb=short -x $COVERAGE_FLAG 2>&1 | tail -5; then
        pass "Unit tests passed"
    else
        fail "Unit tests failed"
    fi
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 4: Security Regression Tests
# ══════════════════════════════════════════════════════════════════════
step "PHASE 4: Security Regression Tests"

echo -e "  Running security regression suite..."
if python3 -m pytest tests/test_security_regression.py \
    -v --tb=short -x $COVERAGE_FLAG 2>&1 | tail -10; then
    pass "Security regression tests passed"
else
    fail "Security regression tests FAILED — potential security regression!"
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 5: API Endpoint Tests
# ══════════════════════════════════════════════════════════════════════
if [[ "$MODE" == "full" || "$MODE" == "quick" ]]; then
    step "PHASE 5: API Endpoint Tests"

    echo -e "  Running API smoke tests..."
    if python3 -m pytest tests/test_api_health.py tests/test_api_assets.py tests/test_api_scans.py \
        -v --tb=short -x $COVERAGE_FLAG 2>&1 | tail -5; then
        pass "API core smoke tests passed"
    else
        fail "API core smoke tests failed"
    fi

    if [[ "$MODE" == "full" ]]; then
        echo -e "  Running full API CRUD tests..."
        if python3 -m pytest tests/test_api_crud_complete.py \
            -v --tb=short -x $COVERAGE_FLAG 2>&1 | tail -5; then
            pass "API CRUD tests passed"
        else
            fail "API CRUD tests failed"
        fi

        echo -e "  Running scan endpoint smoke tests..."
        if python3 -m pytest tests/test_api_scan_endpoints.py \
            -v --tb=short -x $COVERAGE_FLAG 2>&1 | tail -5; then
            pass "Scan endpoint smoke tests passed"
        else
            fail "Scan endpoint smoke tests failed"
        fi

        echo -e "  Running admin endpoint tests..."
        if python3 -m pytest tests/test_api_admin.py \
            -v --tb=short -x $COVERAGE_FLAG 2>&1 | tail -5; then
            pass "Admin endpoint tests passed"
        else
            fail "Admin endpoint tests failed"
        fi

        echo -e "  Running security features tests..."
        if python3 -m pytest tests/test_api_security_features.py \
            -v --tb=short -x $COVERAGE_FLAG 2>&1 | tail -5; then
            pass "Security features tests passed"
        else
            fail "Security features tests failed"
        fi
    fi
fi

# ══════════════════════════════════════════════════════════════════════
# PHASE 6: Integration Tests (full mode only)
# ══════════════════════════════════════════════════════════════════════
if [[ "$MODE" == "full" ]]; then
    step "PHASE 6: Integration Tests"

    echo -e "  Running integration tests..."
    if python3 -m pytest tests/integration/ \
        -v --tb=short -x $COVERAGE_FLAG 2>&1 | tail -5; then
        pass "Integration tests passed"
    else
        fail "Integration tests failed"
    fi
fi

# ══════════════════════════════════════════════════════════════════════
# RESULTS
# ══════════════════════════════════════════════════════════════════════
TOTAL_END=$(date +%s)
DURATION=$((TOTAL_END - TOTAL_START))

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════${RESET}"
echo -e "${BOLD}  RESULTS${RESET}"
echo -e "${CYAN}══════════════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${GREEN}Passed:${RESET}  $PASS"
echo -e "  ${RED}Failed:${RESET}  $FAIL"
echo -e "  ${YELLOW}Skipped:${RESET} $SKIP"
echo -e "  Duration: ${DURATION}s"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}${BOLD}║  ✓ RECETTE RÉUSSIE — Aucune régression détectée         ║${RESET}"
    echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
    exit 0
else
    echo -e "${RED}${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${RED}${BOLD}║  ✗ RECETTE ÉCHOUÉE — $FAIL échec(s) détecté(s)           ║${RESET}"
    echo -e "${RED}${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
    exit 1
fi
