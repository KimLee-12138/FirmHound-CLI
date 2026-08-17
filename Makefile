.PHONY: help install dev test lint format clean run-smoke docker-build docker-run

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?##' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?##"}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install production dependencies
	pip install -r requirements.txt

dev: ## Install development dependencies
	pip install -r requirements.txt
	pip install -e .

test: ## Run all tests
	pytest

lint: ## Run ruff check
	ruff check fsa tools tests

format: ## Auto-format code with ruff
	ruff format fsa tools tests

clean: ## Remove build artifacts and run directories
	rm -rf build dist *.egg-info .pytest_cache .coverage .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} +

run-smoke: ## Run end-to-end smoke test with fixture firmware
	python -m fsa.cli --config config/dev.yaml smoke tests/fixtures/sample.bin

docker-build: ## Build Docker image
	docker build -t fsa:latest .

docker-run: ## Run one-shot analysis in Docker
	docker run --rm -it -v $(PWD)/runs:/workspace/runs fsa:latest
