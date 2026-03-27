# ╔══════════════════════════════════════════════════════════════════╗
# ║  NetLanVentory — Development & Testing Makefile                ║
# ╚══════════════════════════════════════════════════════════════════╝

.DEFAULT_GOAL := help
SHELL := /bin/bash
PYTHON ?= python3
PIP ?= pip3

# Colors
GREEN  := \033[32m
YELLOW := \033[33m
RED    := \033[31m
CYAN   := \033[36m
RESET  := \033[0m

# ── Environment variables for tests ──────────────────────────────
export SECRET_KEY ?= test-secret-key-for-makefile-runs
export JWT_SECRET_KEY ?= test-jwt-secret-key-for-makefile
export ADMIN_PASSWORD ?= Test1234!@\#$$
export APP_DEBUG ?= true

# ── Help ─────────────────────────────────────────────────────────
.PHONY: help
help: ## Show this help
	@echo ""
	@echo "  $(CYAN)NetLanVentory$(RESET) — Development Commands"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2}'
	@echo ""

# ── Installation ─────────────────────────────────────────────────
.PHONY: install install-dev
install: ## Install runtime dependencies
	$(PIP) install -e .

install-dev: ## Install all dependencies (dev + runtime)
	$(PIP) install -e ".[dev,full]"

# ── Testing ──────────────────────────────────────────────────────
.PHONY: test test-unit test-integration test-security test-api test-coverage test-fast

test: ## Run full test suite (recette complète)
	@echo "$(CYAN)══ Running full test suite ══$(RESET)"
	$(PYTHON) -m pytest tests/ -v --tb=short -x
	@echo "$(GREEN)✓ All tests passed$(RESET)"

test-fast: ## Run tests in parallel (requires pytest-xdist)
	$(PYTHON) -m pytest tests/ -v --tb=short -x -q

test-unit: ## Run unit tests only
	@echo "$(CYAN)── Unit tests ──$(RESET)"
	$(PYTHON) -m pytest tests/unit/ tests/test_registry.py tests/test_scoring.py tests/test_config.py -v --tb=short

test-integration: ## Run integration tests only
	@echo "$(CYAN)── Integration tests ──$(RESET)"
	$(PYTHON) -m pytest tests/integration/ -v --tb=short

test-security: ## Run security regression tests only
	@echo "$(CYAN)── Security regression tests ──$(RESET)"
	$(PYTHON) -m pytest tests/test_security_regression.py -v --tb=short

test-api: ## Run all API endpoint tests
	@echo "$(CYAN)── API tests ──$(RESET)"
	$(PYTHON) -m pytest tests/test_api_*.py tests/test_api_crud_complete.py tests/test_api_scan_endpoints.py tests/test_api_admin.py -v --tb=short

test-coverage: ## Run tests with coverage report
	@echo "$(CYAN)══ Running tests with coverage ══$(RESET)"
	$(PYTHON) -m pytest tests/ \
		--cov=netlanventory \
		--cov-report=term-missing \
		--cov-report=html:htmlcov \
		--cov-fail-under=40 \
		-v --tb=short
	@echo "$(GREEN)✓ Coverage report: htmlcov/index.html$(RESET)"

# ── Linting & Security Scanning ──────────────────────────────────
.PHONY: lint lint-fix typecheck audit

lint: ## Run ruff linter (includes bandit security rules)
	@echo "$(CYAN)── Linting ──$(RESET)"
	$(PYTHON) -m ruff check netlanventory/ tests/
	@echo "$(GREEN)✓ Lint passed$(RESET)"

lint-fix: ## Auto-fix lint issues
	$(PYTHON) -m ruff check --fix netlanventory/ tests/

typecheck: ## Run mypy type checking
	@echo "$(CYAN)── Type checking ──$(RESET)"
	$(PYTHON) -m mypy netlanventory/ --ignore-missing-imports
	@echo "$(GREEN)✓ Types OK$(RESET)"

audit: ## Run dependency security audit (pip-audit + safety)
	@echo "$(CYAN)── Dependency security audit ──$(RESET)"
	-$(PYTHON) -m pip_audit 2>/dev/null || echo "$(YELLOW)⚠ pip-audit not installed$(RESET)"
	-$(PYTHON) -m safety check 2>/dev/null || echo "$(YELLOW)⚠ safety not installed$(RESET)"

# ── Full Recette (acceptance testing) ────────────────────────────
.PHONY: recette recette-ci

recette: lint typecheck test-coverage ## Full acceptance: lint + types + tests + coverage
	@echo ""
	@echo "$(GREEN)╔══════════════════════════════════════════╗$(RESET)"
	@echo "$(GREEN)║  ✓ RECETTE COMPLÈTE — TOUT EST OK       ║$(RESET)"
	@echo "$(GREEN)╚══════════════════════════════════════════╝$(RESET)"

recette-ci: lint test ## CI-optimized recette (no coverage threshold in CI)
	@echo "$(GREEN)✓ CI recette passed$(RESET)"

# ── Docker ───────────────────────────────────────────────────────
.PHONY: docker-build docker-test docker-up docker-down

docker-build: ## Build Docker image
	docker compose build

docker-test: ## Run tests in Docker
	docker compose --profile test up --build --exit-code-from tests tests

docker-up: ## Start all services
	docker compose up -d

docker-down: ## Stop all services
	docker compose down

# ── Database ─────────────────────────────────────────────────────
.PHONY: db-migrate db-revision

db-migrate: ## Run Alembic migrations
	alembic upgrade head

db-revision: ## Create new Alembic revision (usage: make db-revision MSG="add column")
	alembic revision --autogenerate -m "$(MSG)"

# ── Cleanup ──────────────────────────────────────────────────────
.PHONY: clean
clean: ## Remove build artifacts and caches
	rm -rf __pycache__ .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
