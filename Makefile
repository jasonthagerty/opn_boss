.PHONY: install dev test lint fmt clean serve scan

install:
	uv sync

dev:
	uv sync --extra dev

test:
	uv run pytest

test-cov:
	uv run pytest --cov=opn_boss --cov-report=html --cov-report=term-missing

lint:
	uv run ruff check opn_boss tests
	uv run mypy opn_boss

fmt:
	uv run ruff format opn_boss tests
	uv run ruff check --fix opn_boss tests

serve:
	uv run opnboss serve

scan:
	uv run opnboss scan

status:
	uv run opnboss status

clean:
	rm -rf .pytest_cache __pycache__ .coverage htmlcov dist
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
