# syntax=docker/dockerfile:1.7
FROM cgr.dev/chainguard/wolfi-base@sha256:dbcc3a4a3b1b9e68420a4742940aa6267c97e61811736a5fef0918a06ade1827 AS os-bootstrap
# Bootstrap a consistent, signature-verified public Wolfi root filesystem.
# The bootstrap image and its vendor package repository do not enter runtime.
RUN apk add --no-cache curl && mkdir -p /tmp/wolfi-keys /rootfs \
 && curl -fsSL https://packages.wolfi.dev/os/wolfi-signing.rsa.pub -o /tmp/wolfi-keys/wolfi-signing.rsa.pub \
 && echo 'f0031424cf46f7db780ce63a45f0fd6aa6f85f601e6bb3b7a91fe3d4d5b7d2cc  /tmp/wolfi-keys/wolfi-signing.rsa.pub' | sha256sum -c - \
 && echo 'https://packages.wolfi.dev/os' > /tmp/wolfi-repositories \
 && apk --root /rootfs --initdb --no-cache --keys-dir /tmp/wolfi-keys --repositories-file /tmp/wolfi-repositories add wolfi-baselayout ca-certificates-bundle apk-tools busybox \
 && mkdir -p /rootfs/etc/apk/keys \
 && cp /tmp/wolfi-keys/wolfi-signing.rsa.pub /rootfs/etc/apk/keys/ \
 && cp /tmp/wolfi-repositories /rootfs/etc/apk/repositories

FROM scratch AS os-base
COPY --from=os-bootstrap /rootfs/ /

FROM os-base AS native-base
RUN apk update && apk upgrade && apk add --no-cache build-base cmake ninja bison flex flex-dev linux-headers git curl pkgconf python-3.13 python-3.13-dev 'libpcap-dev>=1.10.7' openssl-dev zlib-dev glib-dev libgcrypt-dev pcre2-dev 'c-ares-dev>=1.34.9' 'libxml2-dev>=2.15.4-r1' nghttp2-dev lz4-dev zstd-dev libmaxminddb-dev speexdsp-dev zeromq-dev

FROM native-base AS zeek-builder
ARG TARGETARCH
ARG ZEEK_BUILD_JOBS=2
RUN curl -fsSL https://download.zeek.org/zeek-9.0.1.tar.gz -o /tmp/zeek.tar.gz \
 && echo 'fbee2eb5ee6ebd64ef0db830fbb9fa1d702d58807643c719e8338a59329197f2  /tmp/zeek.tar.gz' | sha256sum -c - \
 && tar -xzf /tmp/zeek.tar.gz -C /tmp
# Build generated headers before Spicy hooks; cache objects across interrupted builds.
RUN --mount=type=cache,id=pcap-zeek-9.0.1-${TARGETARCH},target=/tmp/zeek-build,sharing=locked \
 cmake -S /tmp/zeek-9.0.1 -B /tmp/zeek-build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/zeek -DCARES_ROOT_DIR=/usr -DCARES_LIBRARIES=/usr/lib/libcares.so \
 -DENABLE_ZEEK_UNIT_TESTS=OFF -DINSTALL_AUX_TOOLS=OFF -DINSTALL_BTEST=OFF -DINSTALL_BTEST_PCAPS=OFF -DINSTALL_ZEEKCTL=OFF -DINSTALL_ZEEK_CLIENT=OFF -DINSTALL_ZKG=OFF \
 && cmake --build /tmp/zeek-build --target zeek_autogen_files --parallel "$ZEEK_BUILD_JOBS" \
 && cmake --build /tmp/zeek-build --parallel "$ZEEK_BUILD_JOBS" \
 && cmake --install /tmp/zeek-build

FROM native-base AS wireshark-builder
RUN curl -fsSL https://www.wireshark.org/download/src/wireshark-4.6.9.tar.xz -o /tmp/wireshark.tar.xz \
 && echo 'd062d416a1ab3a49975aafe3a671c882dde0562ccd71b078808ceb59d465fc0f  /tmp/wireshark.tar.xz' | sha256sum -c - \
 && tar -xJf /tmp/wireshark.tar.xz -C /tmp \
 && cmake -S /tmp/wireshark-4.6.9 -B /tmp/wireshark-build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/wireshark -DCMAKE_INSTALL_LIBDIR=lib \
 -DBUILD_wireshark=OFF -DBUILD_tshark=ON -DBUILD_dumpcap=OFF -DBUILD_extcap=OFF -DENABLE_LTO=OFF -DENABLE_DOCS=OFF -DBUILD_TESTING=OFF \
 && cmake --build /tmp/wireshark-build --parallel 2 \
 && cmake --install /tmp/wireshark-build

FROM native-base AS python-builder
RUN apk add --no-cache py3.13-pip libxslt-dev
WORKDIR /w
COPY requirements.lock requirements-test.lock requirements-build.lock ./
RUN python3.13 -m venv --without-pip /opt/venv \
 && python3.13 -m pip --python /opt/venv/bin/python install --no-cache-dir --require-hashes -r requirements-build.lock \
 && python3.13 -m pip --python /opt/venv/bin/python install --no-cache-dir --require-hashes --no-build-isolation --no-binary=lxml -r requirements.lock \
 && python3.13 -m pip --python /opt/venv/bin/python uninstall -y setuptools wheel \
 && /opt/venv/bin/python -c 'from lxml import etree; assert etree.LIBXML_VERSION >= (2,15,4), etree.LIBXML_VERSION'

FROM python:3.13-slim-trixie@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb AS browser-builder
ARG TARGETARCH
COPY docker/fetch_browser.py /fetch_browser.py
RUN python3 /fetch_browser.py "$TARGETARCH" /opt/chrome

FROM node:22-trixie-slim@sha256:2117f713a417f3aff682ac8f5bc2ebbdf1beed51f36e67ab1e0fd3866b6d2d8f AS web-builder
WORKDIR /web
COPY prototype-friendly-ui/package.json prototype-friendly-ui/package-lock.json ./
RUN npm ci
COPY prototype-friendly-ui/index.html prototype-friendly-ui/vite.config.mjs ./
COPY prototype-friendly-ui/src/ ./src/
COPY prototype-friendly-ui/public/ ./public/
RUN npm run build:web

FROM os-base AS runtime-base
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
 STREAMLIT_BROWSER_GATHER_USAGE_STATS=false PYTHONPATH=/app \
 PATH="/opt/venv/bin:/opt/zeek/bin:/opt/wireshark/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
 LD_LIBRARY_PATH="/opt/zeek/lib:/opt/zeek/lib64:/opt/wireshark/lib" BROWSER_PATH=/opt/chrome/chrome-headless-shell
RUN apk update && apk upgrade && apk add --no-cache python-3.13 pango cairo font-opensans 'libpcap>=1.10.7' libstdc++ openssl zlib glib libgcrypt pcre2 'c-ares>=1.34.9' 'libxml2>=2.15.4-r1' libxslt nghttp2 lz4 zstd libmaxminddb speexdsp zeromq \
 so:libnss3.so so:libnspr4.so so:libatk-1.0.so.0 so:libatk-bridge-2.0.so.0 so:libcups.so.2 so:libdbus-1.so.3 so:libdrm.so.2 so:libgbm.so.1 so:libXcomposite.so.1 so:libXdamage.so.1 so:libXrandr.so.2 so:libxkbcommon.so.0 so:libasound.so.2
FROM runtime-base AS native-runtime
COPY --from=python-builder /opt/venv /opt/venv
COPY --from=zeek-builder /opt/zeek /opt/zeek
COPY --from=wireshark-builder /opt/wireshark /opt/wireshark
COPY --from=browser-builder /opt/chrome /opt/chrome
# Resolve the parser/browser ABIs from the corresponding signed library packages.
RUN apk add --no-cache so:liblz4.so.1 so:libXfixes.so.3 so:libudev.so.1
COPY --from=wireshark-builder /tmp/wireshark-4.6.9/COPYING /usr/share/licenses/pcap-hunter/tshark-COPYING
COPY --from=zeek-builder /tmp/zeek-9.0.1/COPYING /usr/share/licenses/pcap-hunter/zeek-COPYING
FROM native-runtime AS runtime
USER root
# Replacing the application also supports a previously verified native image context.
RUN apk update && apk upgrade \
 && apk add --no-cache 'python-3.13>=3.13.18_git20261030-r0' 'py3-pip-wheel>=26.2.2-r2' \
 && rm -rf /app/app
WORKDIR /app
COPY app/ ./app/
COPY .streamlit/ ./.streamlit/
COPY docker/verify_runtime.py docker/native-components.json /usr/share/pcap-hunter/
COPY --from=web-builder /web/dist/client/ ./app/web/static/
RUN ln -sf /opt/wireshark/bin/tshark /usr/bin/tshark \
 && if ! id runner >/dev/null 2>&1; then addgroup -g 1000 runner && adduser -D -u 1000 -G runner -h /home/runner runner; fi \
 && test "$(id -u runner)" = 1000 && test "$(id -g runner)" = 1000 \
 && mkdir -p /data /app/data /agent-inbox /agent-results \
 && chown -R runner:runner /app /data /agent-inbox /agent-results \
 && find / -xdev -type f -perm /6000 -exec chmod a-s {} +
RUN python /usr/share/pcap-hunter/verify_runtime.py
USER runner
EXPOSE 8000 8501
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["python", "-c", "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.getenv('PCAP_HUNTER_HEALTH_PORT','8501')+'/healthz', timeout=3)"]
CMD ["uvicorn", "app.web.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8501"]

FROM runtime AS test
USER root
RUN apk add --no-cache py3.13-pip
COPY requirements-test.lock /tmp/requirements-test.lock
RUN /usr/bin/python3.13 -m pip --python /opt/venv/bin/python install --no-cache-dir --require-hashes -r /tmp/requirements-test.lock
COPY --chown=runner:runner pyproject.toml Makefile ./
COPY --chown=runner:runner tests/ ./tests/
COPY --chown=runner:runner docker/ ./docker/
USER runner
CMD ["sh", "-c", "ruff format --check app tests docker && ruff check app tests docker && python -m pytest tests/ -q"]
