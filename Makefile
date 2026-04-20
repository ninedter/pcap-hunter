.PHONY: install install-system install-python check-deps doctor test lint format run clean fix-permissions help

# Prefer the Python interpreter that streamlit is installed under. Falls back
# to whatever python3 is on $PATH. This matters on macOS where framework
# Python and Homebrew Python often coexist.
PYTHON := $(shell command -v streamlit >/dev/null 2>&1 && head -n1 "$$(command -v streamlit)" | sed 's/^\#!//' || echo python3)

# -------------------------------------------------------------------------
# Top-level targets
# -------------------------------------------------------------------------

# Full install: system binaries (if possible) + python packages + sanity check
install: install-system install-python check-deps
	@echo ""
	@echo "✅ PCAP Hunter install complete. Run 'make run' to start."

# Install ONLY python packages (skip system deps — assumes you installed them)
install-python:
	pip install -r requirements.txt

# OS-aware system dependency installer
install-system:
	@UNAME="$$(uname -s)"; \
	if [ "$$UNAME" = "Darwin" ]; then \
		$(MAKE) install-system-macos; \
	elif [ "$$UNAME" = "Linux" ]; then \
		$(MAKE) install-system-linux; \
	else \
		echo "⚠️  Unknown platform '$$UNAME'. Install tshark, zeek, yara manually."; \
	fi

install-system-macos:
	@if ! command -v brew >/dev/null 2>&1; then \
		echo "❌ Homebrew not found. Install from https://brew.sh/ first."; \
		exit 1; \
	fi
	@echo "📦 Installing system dependencies via Homebrew..."
	@command -v tshark >/dev/null 2>&1 || brew install wireshark
	@command -v zeek >/dev/null 2>&1 || brew install zeek
	@command -v yara >/dev/null 2>&1 || brew install yara
	@# Pango is needed for PDF generation via WeasyPrint
	@brew list pango >/dev/null 2>&1 || brew install pango

install-system-linux:
	@if ! command -v apt-get >/dev/null 2>&1; then \
		echo "⚠️  apt-get not found. Install tshark/zeek/yara using your distro's package manager."; \
		exit 0; \
	fi
	@echo "📦 Installing system dependencies via apt..."
	sudo apt-get update
	sudo apt-get install -y tshark zeek yara libpango1.0-dev libpcap0.8

# Verify all required binaries and python packages are present.
# Exits non-zero if any REQUIRED dep is missing — safe to wire into CI.
check-deps:
	@$(PYTHON) scripts/check_dependencies.py

# Friendly alias: full dependency report
doctor: check-deps

# -------------------------------------------------------------------------
# Dev targets
# -------------------------------------------------------------------------

test:
	PYTHONPATH=. pytest tests/ -v --cov=app

lint:
	ruff check .

format:
	ruff format .

# Run the app — checks deps first so users don't get blank dashboards.
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
# Help
# -------------------------------------------------------------------------

help:
	@echo "PCAP Hunter — make targets"
	@echo ""
	@echo "  make install          Full install (system + python) + verification"
	@echo "  make install-system   System binaries only (tshark, zeek, yara, pango)"
	@echo "  make install-python   Python packages only (pip install -r requirements.txt)"
	@echo "  make check-deps       Verify all dependencies are present"
	@echo "  make doctor           Alias for check-deps"
	@echo "  make run              Start the app (checks deps first)"
	@echo "  make test             Run the test suite with coverage"
	@echo "  make lint             Run ruff check"
	@echo "  make format           Run ruff format"
	@echo "  make clean            Remove caches"
	@echo "  make fix-permissions  Grant macOS BPF capture permissions"
