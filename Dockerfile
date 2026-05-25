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
FROM python:3.11-bookworm
ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    DEBIAN_FRONTEND=noninteractive

# System deps (no compilers here)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates gnupg \
    tshark wireshark-common libpcap0.8 \
 && rm -rf /var/lib/apt/lists/*

# Add Zeek repo + install Zeek in runtime image
RUN echo "deb [signed-by=/usr/share/keyrings/zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/Debian_12/ /" \
      > /etc/apt/sources.list.d/zeek.list \
 && curl -fsSL https://download.opensuse.org/repositories/security:/zeek/Debian_12/Release.key \
      | gpg --dearmor -o /usr/share/keyrings/zeek.gpg \
 && apt-get update && apt-get install -y --no-install-recommends zeek \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /wheels /wheels
COPY requirements.txt .
RUN pip install --no-cache-dir /wheels/*

# Your modularized app
COPY app/ /app/

# Non-root + data dirs
RUN useradd -m runner && mkdir -p /data && chown -R runner:runner /app /data
USER runner

EXPOSE 8000 8501

# Default: run Streamlit. Override with:
#   docker run ... pcap-hunter make run-api
# to run the integrations API instead.
CMD ["streamlit", "run", "/app/main.py", "--server.port=8501", "--server.address=0.0.0.0"]