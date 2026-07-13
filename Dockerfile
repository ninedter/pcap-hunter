# ---------- Builder ----------
FROM python:3.11-bookworm AS builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates gnupg \
    tshark wireshark-common \
    gcc g++ make libpcap0.8 libpcap0.8-dev \
 && rm -rf /var/lib/apt/lists/*

# Add Zeek repo for Debian 12 (bookworm) and install Zeek (headers not needed here)
RUN echo "deb [signed-by=/usr/share/keyrings/zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/Debian_12/ /" \
      > /etc/apt/sources.list.d/zeek.list \
 && curl -fsSL https://download.opensuse.org/repositories/security:/zeek/Debian_12/Release.key \
      | gpg --dearmor -o /usr/share/keyrings/zeek.gpg \
 && apt-get update && apt-get install -y --no-install-recommends zeek \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /w
COPY requirements.txt .
RUN pip install --upgrade pip setuptools wheel \
 && pip wheel -r requirements.txt --wheel-dir /wheels

# ---------- Runtime ----------
FROM python:3.11-bookworm AS runtime
ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    DEBIAN_FRONTEND=noninteractive \
    PYTHONPATH=/app

# System deps (no compilers here):
# - tshark/wireshark-common: packet parsing + capinfos
# - libpango/libcairo/libgdk-pixbuf/shared-mime-info/fonts: WeasyPrint PDF export
# (kaleido 0.2.1 bundles its own headless Chromium — no system browser needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates gnupg \
    tshark wireshark-common libpcap0.8 \
    libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 \
    shared-mime-info fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

# Add Zeek repo + install Zeek in runtime image
RUN echo "deb [signed-by=/usr/share/keyrings/zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/Debian_12/ /" \
      > /etc/apt/sources.list.d/zeek.list \
 && curl -fsSL https://download.opensuse.org/repositories/security:/zeek/Debian_12/Release.key \
      | gpg --dearmor -o /usr/share/keyrings/zeek.gpg \
 && apt-get update && apt-get install -y --no-install-recommends zeek \
 && rm -rf /var/lib/apt/lists/*

# The OBS package installs under /opt/zeek — put it on PATH so `which zeek`,
# make doctor, and anything not using find_bin's fallback paths all work.
ENV PATH="/opt/zeek/bin:${PATH}"

WORKDIR /app
COPY --from=builder /wheels /wheels
COPY requirements.txt .
RUN pip install --no-cache-dir /wheels/*

# Repo-shaped layout: the package lives at /app/app so absolute imports
# (from app.pipeline import ...) resolve identically to a local checkout.
# The previous flattened COPY (app/ -> /app/) broke `uvicorn app.api.app`.
COPY app/ ./app/

# Synthetic first-run demo capture (see pcaps/_make_demo.py) — powers the
# "Load demo capture" button so a fresh install has something to analyze.
COPY pcaps/demo.pcap ./pcaps/demo.pcap

# Non-root + data dirs
RUN useradd -m runner && mkdir -p /data /app/data && chown -R runner:runner /app /data
USER runner

EXPOSE 8000 8501

# Default: run Streamlit. The compose file runs the integrations API from the
# same image with an explicit uvicorn command.
CMD ["streamlit", "run", "app/main.py", "--server.port=8501", "--server.address=0.0.0.0"]

# ---------- Test (canonical local verification: make docker-verify) ----------
# Mirrors `make verify` (format check + lint + full suite) inside the runtime
# environment, so verification never depends on the host Python setup.
FROM runtime AS test
USER root
COPY pyproject.toml Makefile ./
COPY tests/ ./tests/
RUN chown -R runner:runner /app
USER runner
CMD ["sh", "-c", "ruff format --check app tests && ruff check app tests && python -m pytest tests/ -q"]
