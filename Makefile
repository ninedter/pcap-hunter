.PHONY: install install-system install-python check-deps doctor test test-pdf verify lint format run clean fix-permissions help run-api run-api-dev smoke-api docker-build docker-up docker-down docker-verify web-build run-web lock lock-check

# Prefer the Python interpreter that streamlit is installed under. Falls back
# to whatever python3 is on $PATH. This matters on macOS where framework
# Python and Homebrew Python often coexist.
PYTHON := $(shell command -v streamlit >/dev/null 2>&1 && head -n1 "$$(command -v streamlit)" | sed 's/^\#!//' || echo python3)

# -------------------------------------------------------------------------
# Install
#
# All install logic lives in scripts/install.py (cross-platform).
# The targets below are just idiomatic `make` entry points that delegate.
# -------------------------------------------------------------------------

install:
	@$(PYTHON) scripts/install.py

install-system:
	@$(PYTHON) scripts/install.py --skip-python

install-python:
	@$(PYTHON) scripts/install.py --skip-system

check-deps doctor:
	@$(PYTHON) scripts/install.py --check-only

# -------------------------------------------------------------------------
# Dev targets
# -------------------------------------------------------------------------

test:
	PYTHONPATH=. pytest tests/ -v --cov=app

# Focused smoke test: PDF generation with charts + correlations + beacon DF.
# Run this after any change to pdf_generator.py, chart_images.py, main.py
# PDF section, or the charts module. Uses --no-header --no-summary for a
# quick readable signal.
test-pdf:
	PYTHONPATH=. pytest tests/test_pdf_generator.py tests/test_pdf_integration.py \
		tests/test_chart_images.py tests/test_chart_rendering.py -v

lint:
	ruff check .

format:
	ruff format .

# Pre-commit / pre-push verification gate.
# Runs: format check, lint, full test suite (no --ignore flags).
# If this passes, it's safe to commit/push. CI runs the same checks.
verify:
	@echo "=== 1/3: ruff format check ==="
	@ruff format --check .
	@echo ""
	@echo "=== 2/3: ruff lint ==="
	@ruff check .
	@echo ""
	@echo "=== 3/3: full test suite ==="
	@PYTHONPATH=. pytest tests/ -q
	@echo ""
	@echo "✓ verify passed — safe to commit & push"

# Run the LEGACY Streamlit interface — checks deps first so users don't get
# blank dashboards. The v3 React workbench is `make docker-up` (supported) or
# `make run-web` (host, for development).
run: check-deps
	streamlit run app/main.py

clean:
	rm -rf .pytest_cache .coverage htmlcov
	find . -type d -name "__pycache__" -exec rm -rf {} +

fix-permissions:
	@echo "Granting capture permissions for macOS (a system prompt may appear)..."
	@osascript -e 'do shell script "chown $(USER) /dev/bpf*" with administrator privileges'
	@ls -l /dev/bpf*

# -------------------------------------------------------------------------
# v3 web workbench on the host (development only — Docker is the supported path)
#
# Mirrors the Dockerfile: the web-builder stage runs `npm ci` + `npm run
# build:web` and copies dist/client/ into app/web/static/, and the runtime CMD
# is `uvicorn app.web.app:create_app --factory --port 8501`. The only
# difference is the bind address: loopback here, because there is no container
# boundary in front of it.
# -------------------------------------------------------------------------

WEB_UI_DIR := prototype-friendly-ui
WEB_STATIC_DIR := app/web/static

web-build:
	cd $(WEB_UI_DIR) && npm ci && npm run build:web
	find $(WEB_STATIC_DIR) -mindepth 1 ! -name .gitkeep -delete
	cp -R $(WEB_UI_DIR)/dist/client/. $(WEB_STATIC_DIR)/

run-web: web-build
	PYTHONPATH=. uvicorn app.web.app:create_app --factory --host 127.0.0.1 --port 8501

# -------------------------------------------------------------------------
# Dependency locks
#
# The three hash-pinned locks are compiled by uv from the requirements-*.txt
# input ranges. These are exactly the commands recorded in each lock's header.
# uv keeps the pins already present in an existing lock unless the inputs no
# longer allow them, so `make lock` after an input edit produces a minimal diff.
# -------------------------------------------------------------------------

UV ?= uv
LOCK_INPUTS := requirements-build.txt requirements-runtime.txt requirements-dev.txt
LOCK_FILES := requirements-build.lock requirements.lock requirements-test.lock
# Scratch copy for lock-check; tmp/ is gitignored and the copy is overwritten on every run.
LOCK_CHECK_DIR := tmp/lock-check

UV_COMPILE := $(UV) pip compile --universal --python-version 3.13 --generate-hashes
LOCK_BUILD := $(UV_COMPILE) requirements-build.txt -o requirements-build.lock
LOCK_RUNTIME := $(UV_COMPILE) requirements-runtime.txt -o requirements.lock
LOCK_TEST := $(UV_COMPILE) requirements-runtime.txt requirements-dev.txt -o requirements-test.lock

lock:
	$(LOCK_BUILD)
	$(LOCK_RUNTIME)
	$(LOCK_TEST)

# Regenerate the locks in a scratch copy and fail if they differ from the
# committed ones (i.e. an input range was edited without re-locking).
# Exit codes: 0 = in sync, 1 = drift, 2 = uv could not compile.
lock-check:
	@mkdir -p $(LOCK_CHECK_DIR)
	@cp $(LOCK_INPUTS) $(LOCK_FILES) $(LOCK_CHECK_DIR)/
	@cd $(LOCK_CHECK_DIR) && { $(LOCK_BUILD) && $(LOCK_RUNTIME) && $(LOCK_TEST); } >/dev/null 2>compile.err \
		|| { cat $(LOCK_CHECK_DIR)/compile.err >&2; exit 2; }
	@status=0; \
	for f in $(LOCK_FILES); do diff -u "$$f" "$(LOCK_CHECK_DIR)/$$f" || status=1; done; \
	if [ $$status -eq 0 ]; then echo "✓ locks match their inputs"; \
	else echo "✗ lock drift — run 'make lock' and review the diff" >&2; fi; \
	exit $$status

# -------------------------------------------------------------------------
# Docker targets — the canonical build-and-verify path.
#
# Any local verification that requires a build goes through Docker so it
# never depends on the host's (fragmented) Python setup.
# -------------------------------------------------------------------------

docker-build:
	docker build --target runtime -t pcap-hunter:latest .

docker-up: docker-build
	docker compose up -d pcap-hunter-ui
	@echo "UI running at http://localhost:8501 (docker compose logs -f pcap-hunter-ui)"

docker-down:
	docker compose down

# Build-backed verification gate: format check + lint + full test suite,
# executed inside the runtime image (same env the app ships in).
docker-verify:
	docker build --target test -t pcap-hunter:test .
	docker run --rm pcap-hunter:test

# -------------------------------------------------------------------------
# API targets
# -------------------------------------------------------------------------

run-api:
	PYTHONPATH=. uvicorn app.api.app:create_app --factory --host 127.0.0.1 --port 8000

run-api-dev:
	PYTHONPATH=. uvicorn app.api.app:create_app --factory --host 127.0.0.1 --port 8000 --reload --log-level debug

smoke-api:
	@bash scripts/api_smoke_test.sh

# -------------------------------------------------------------------------
# Help
# -------------------------------------------------------------------------

help:
	@echo "PCAP Hunter — make targets"
	@echo ""
	@echo "  make install          Full install (system + python) + verification"
	@echo "  make install-system   System binaries only"
	@echo "  make install-python   Python packages only"
	@echo "  make check-deps       Verify all dependencies are present"
	@echo "  make doctor           Alias for check-deps"
	@echo "  make run              Start the LEGACY Streamlit UI (checks deps first)"
	@echo "  make web-build        Build the v3 React workbench into app/web/static/"
	@echo "  make run-web          Build + serve the v3 workbench on 127.0.0.1:8501 (dev)"
	@echo "  make test             Run the test suite with coverage"
	@echo "  make test-pdf         Focused PDF + charts test suite"
	@echo "  make verify           Pre-commit gate: format + lint + full tests"
	@echo "  make lint             Run ruff check"
	@echo "  make format           Run ruff format"
	@echo "  make clean            Remove caches"
	@echo "  make docker-build     Build the runtime image (pcap-hunter:latest)"
	@echo "  make docker-up        Build + start the v3 workbench container on :8501 (supported path)"
	@echo "  make docker-down      Stop compose services"
	@echo "  make docker-verify    Format + lint + full tests inside the image"
	@echo "  make run-api          Start the integrations API on :8000"
	@echo "  make run-api-dev      Run API with --reload + debug logging"
	@echo "  make smoke-api        End-to-end smoke test against local API"
	@echo "  make lock             Recompile the three uv lock files from their inputs"
	@echo "  make lock-check       Fail if the committed locks differ from a fresh compile"
	@echo "  make fix-permissions  Grant macOS BPF capture permissions"
	@echo ""
	@echo "All install targets delegate to: python3 scripts/install.py"
	@echo "Windows users without make: run  .\\scripts\\install.ps1  (or the same install.py)"
