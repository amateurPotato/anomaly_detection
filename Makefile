# ==============================================================================
# anomaly-detection — local development helpers
# ==============================================================================
# Usage:
#   make install        install all deps into .venv
#   make test           run full test suite with coverage
#   make test-fast      run tests without coverage (quicker feedback)
#   make test-llm       run only the LLM analyser tests
#   make test-tracker   run only the tracker integration tests
#   make demo           run the simple simulator demo against local Ollama
#   make demo-cloud     run the simple simulator demo against Claude (needs ANTHROPIC_API_KEY)
#   make run-demo       run the 3-scenario test harness (generate_test_data.py)
#   make run-demo-cloud run the 3-scenario test harness against Claude
#   make check-ollama   verify Ollama is reachable at OLLAMA_BASE_URL
# ==============================================================================

PYTHON    := .venv/bin/python
PIP       := .venv/bin/pip
# Use python -m pytest to avoid stale shebang paths in the venv
PYTEST    := $(PYTHON) -m pytest

# Ollama defaults (override on the command line: make demo OLLAMA_MODEL=mistral)
OLLAMA_BASE_URL ?= http://localhost:11434
OLLAMA_MODEL    ?= llama3

.PHONY: install test test-fast test-llm test-tracker demo demo-cloud run-demo run-demo-cloud check-ollama

# ------------------------------------------------------------------------------
# Environment
# ------------------------------------------------------------------------------

install:
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"
	$(PIP) install httpx
	@echo ""
	@echo "✓  Environment ready. Activate with: source .venv/bin/activate"

# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------

## Full suite — branch coverage, fails if < 100 %
test:
	$(PYTEST) tests/ \
		--cov=. \
		--cov-report=term-missing \
		--cov-branch \
		-v

## Quick pass — no coverage (faster during development)
test-fast:
	$(PYTEST) tests/ -v

## Only LLM analyser tests
test-llm:
	$(PYTEST) tests/llm/ -v

## Only tracker integration tests
test-tracker:
	$(PYTEST) tests/engine/test_tracker.py -v

## Only simulator/demo tests
test-demo:
	$(PYTEST) tests/demo/ -v

# ------------------------------------------------------------------------------
# Demo — local Ollama (default)
# ------------------------------------------------------------------------------

demo:
	@echo "[demo] Using local Ollama  model=$(OLLAMA_MODEL)  url=$(OLLAMA_BASE_URL)"
	OLLAMA_MODEL=$(OLLAMA_MODEL) \
	OLLAMA_BASE_URL=$(OLLAMA_BASE_URL) \
	$(PYTHON) -m anomaly_detection.demo.simulator

# ------------------------------------------------------------------------------
# Demo — Anthropic Claude (cloud)
# ------------------------------------------------------------------------------

demo-cloud:
	@if [ -z "$$ANTHROPIC_API_KEY" ]; then \
		echo "ERROR: ANTHROPIC_API_KEY is not set."; \
		exit 1; \
	fi
	@echo "[demo] Using Claude cloud"
	USE_CLOUD_LLM=true \
	ANTHROPIC_API_KEY=$$ANTHROPIC_API_KEY \
	$(PYTHON) -m anomaly_detection.demo.simulator

# ------------------------------------------------------------------------------
# Scenario-based test harness (generate_test_data.py)
# ------------------------------------------------------------------------------

## 3-scenario harness — local Ollama (benign / scanner / exfiltration)
run-demo:
	@echo "[run-demo] Using local Ollama  model=$(OLLAMA_MODEL)  url=$(OLLAMA_BASE_URL)"
	OLLAMA_MODEL=$(OLLAMA_MODEL) \
	OLLAMA_BASE_URL=$(OLLAMA_BASE_URL) \
	$(PYTHON) generate_test_data.py

## 3-scenario harness — Anthropic Claude
run-demo-cloud:
	@if [ -z "$$ANTHROPIC_API_KEY" ]; then \
		echo "ERROR: ANTHROPIC_API_KEY is not set."; \
		exit 1; \
	fi
	@echo "[run-demo] Using Claude cloud"
	USE_CLOUD_LLM=true \
	ANTHROPIC_API_KEY=$$ANTHROPIC_API_KEY \
	$(PYTHON) generate_test_data.py

# ------------------------------------------------------------------------------
# Health checks
# ------------------------------------------------------------------------------

check-ollama:
	@echo "Checking Ollama at $(OLLAMA_BASE_URL) ..."
	@curl -sf $(OLLAMA_BASE_URL)/api/tags > /dev/null \
		&& echo "✓  Ollama is running" \
		|| (echo "✗  Ollama is NOT reachable at $(OLLAMA_BASE_URL)"; exit 1)
	@echo "Pulling $(OLLAMA_MODEL) if not cached ..."
	curl -s -X POST $(OLLAMA_BASE_URL)/api/pull \
		-H 'Content-Type: application/json' \
		-d '{"name": "$(OLLAMA_MODEL)", "stream": false}' \
		| $(PYTHON) -c "import sys,json; d=json.load(sys.stdin); print('✓ ', d.get('status','done'))"
