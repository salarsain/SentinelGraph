# ============================================================
# SentinelGraph — Makefile
# ============================================================
.PHONY: help up down logs migrate seed test lint format clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Docker ──────────────────────────────────────────────────
up: ## Start all services
	docker-compose up -d --build

down: ## Stop all services
	docker-compose down

logs: ## Tail logs for all services
	docker-compose logs -f

logs-backend: ## Tail backend logs
	docker-compose logs -f backend

logs-worker: ## Tail Celery worker logs
	docker-compose logs -f celery-worker

restart: ## Restart all services
	docker-compose restart

rebuild: ## Full rebuild
	docker-compose down && docker-compose up -d --build

# ── Database ────────────────────────────────────────────────
migrate: ## Run Alembic migrations
	docker-compose exec backend alembic upgrade head

migrate-new: ## Create new migration (usage: make migrate-new MSG="add_users")
	docker-compose exec backend alembic revision --autogenerate -m "$(MSG)"

migrate-down: ## Rollback last migration
	docker-compose exec backend alembic downgrade -1

seed: ## Seed database with test data
	docker-compose exec backend python -m scripts.seed

db-shell: ## Open PostgreSQL shell
	docker-compose exec postgres psql -U sentinelgraph -d sentinelgraph

# ── Testing ─────────────────────────────────────────────────
test: ## Run all backend tests
	docker-compose exec backend pytest tests/ -v --tb=short

test-cov: ## Run tests with coverage
	docker-compose exec backend pytest tests/ -v --cov=app --cov-report=html

test-scope: ## Run scope gateway tests
	docker-compose exec backend pytest tests/test_scope_gateway.py -v

# ── Code Quality ────────────────────────────────────────────
lint: ## Run linters
	docker-compose exec backend ruff check app/

format: ## Format code
	docker-compose exec backend ruff format app/

# ── Utilities ───────────────────────────────────────────────
shell: ## Open Python shell in backend
	docker-compose exec backend python

backend-shell: ## Open bash in backend container
	docker-compose exec backend bash

redis-cli: ## Open Redis CLI
	docker-compose exec redis redis-cli

clean: ## Remove all containers, volumes, and build cache
	docker-compose down -v --rmi all --remove-orphans

env: ## Copy .env.example to .env
	cp .env.example .env
	@echo "✓ .env created — edit it with your secrets"
