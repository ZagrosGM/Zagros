ARG PYTHON_VERSION=3.12
# Dashboard toolchain for the unified Zagros panel (React 18 + vite 5 +
# Tailwind) — node 20 LTS. The release image is currently amd64-only because
# the pinned PPP client package manifest below is amd64-specific.
ARG NODE_IMAGE=node:20.19.0-bookworm-slim

# --------------------------------------------------------------------------
# Stage 1: dashboard frontend (React + vite). Self-contained: CI and local
# `docker build` produce identical assets; no pre-built build/ is committed.
# --------------------------------------------------------------------------
FROM $NODE_IMAGE AS dashboard

WORKDIR /code

COPY app/dashboard/package.json app/dashboard/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY app/dashboard ./
ENV VITE_BASE_API=/api/
# The build script itself pins --outDir/--assetsDir and writes 404.html for
# SPA deep links (scripts/postbuild.mjs).
RUN npm run build

# --------------------------------------------------------------------------
# Stage 2: pinned ACCEL-PPP runtime for the independent PPTP provider.
# The immutable commit archive is verified before extraction. The final image
# receives only the allowlisted modules; no compiler/toolchain is shipped.
# --------------------------------------------------------------------------
FROM python:$PYTHON_VERSION-slim AS accel-ppp-build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl cmake make gcc libc6-dev linux-libc-dev \
       libpcre2-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY vendor/accel-ppp/manifest.json /tmp/accel-ppp-manifest.json
RUN set -eux; \
    version="$(python3 -c 'import json;print(json.load(open("/tmp/accel-ppp-manifest.json"))["version"])')"; \
    url="$(python3 -c 'import json;print(json.load(open("/tmp/accel-ppp-manifest.json"))["source"])')"; \
    expected="$(python3 -c 'import json;print(json.load(open("/tmp/accel-ppp-manifest.json"))["sha256"])')"; \
    curl -fL --retry 3 --proto '=https' --tlsv1.2 -o /tmp/accel-ppp-source.tar.gz "$url"; \
    echo "$expected  /tmp/accel-ppp-source.tar.gz" | sha256sum -c -; \
    mkdir -p /src /src/build /stage /bundle/sbin /bundle/lib/accel-ppp /bundle/source; \
    tar -xzf /tmp/accel-ppp-source.tar.gz -C /src --strip-components=1; \
    cmake -S /src -B /src/build \
      -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/zagros/accel-ppp/1.14.0 \
      -DLIB_SUFFIX= -DRADIUS=FALSE -DSHAPER=FALSE -DNETSNMP=FALSE -DLUA=FALSE \
      -DBUILD_PPTP_DRIVER=FALSE -DBUILD_IPOE_DRIVER=FALSE \
      -DBUILD_VLAN_MON_DRIVER=FALSE; \
    cmake --build /src/build --parallel "$(nproc)"; \
    DESTDIR=/stage cmake --install /src/build; \
    cp /stage/opt/zagros/accel-ppp/1.14.0/sbin/accel-pppd /bundle/sbin/accel-pppd; \
    for module in libtriton.so libpptp.so libauth_mschap_v2.so libchap-secrets.so libippool.so libsigchld.so libpppd_compat.so liblog_file.so; do \
      found="$(find /stage/opt -type f -name "$module" -print -quit)"; \
      test -n "$found"; cp "$found" "/bundle/lib/accel-ppp/$module"; \
    done; \
    cp /tmp/accel-ppp-source.tar.gz "/bundle/source/accel-ppp-${version}-source.tar.gz"; \
    cp /src/COPYING /bundle/source/COPYING; \
    cp /tmp/accel-ppp-manifest.json /bundle/source/manifest.json; \
    LD_LIBRARY_PATH=/bundle/lib/accel-ppp /bundle/sbin/accel-pppd --version | grep -Fx "accel-ppp ${version}"; \
    test "$(find /bundle/lib/accel-ppp -maxdepth 1 -type f | wc -l)" -eq 8

# --------------------------------------------------------------------------
# Stage 3: python dependencies
# --------------------------------------------------------------------------
FROM python:$PYTHON_VERSION-slim AS build

ENV PYTHONUNBUFFERED=1

WORKDIR /code

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential gcc python3-dev libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# NOTE: no core binary is baked into the image. Every core driver
# (xray, sing-box, hysteria2, tuic, ...) self-installs its official
# release binary on demand at runtime (see app/cores/drivers/*/) —
# and the installer/host tooling is equally core-agnostic.

COPY ./requirements.txt /code/
RUN python3 -m pip install --upgrade pip setuptools \
    && pip install --no-cache-dir --upgrade -r /code/requirements.txt

# --------------------------------------------------------------------------
# Final image
# --------------------------------------------------------------------------
FROM python:$PYTHON_VERSION-slim
ARG ZAGROS_VERSION=1.0.0
LABEL org.opencontainers.image.title="Zagros" \
      org.opencontainers.image.description="Zagros — Enterprise Multi-Core VPN Management Platform" \
      org.opencontainers.image.source="https://github.com/ZagrosGM/Zagros" \
      org.opencontainers.image.version="${ZAGROS_VERSION}" \
      org.opencontainers.image.licenses="AGPL-3.0"

# Runtime network tooling for the host-managing cores:
#  * iptables — SSH per-UID usage accounting (owner-match chain, alpha.7.4)
#  * nftables/iproute2 — atomic cross-core classifiers, per-outbound tables
#  * openvpn/wireguard-tools — client-side policy domains (not server cores)
#  * procps — sysctl required by wg-quick and host-network TUN preflights
#  * openssh-client/server — managed SSH egress and SSH inbound runtime
#  * certbot  — REAL ACME / Let's Encrypt issuance from the Certificates
#    page (alpha.7.5 item 9); the panel detects it at runtime, and acme.sh /
#    lego stay supported for operators who install them instead.
# All are inert until such a feature is enabled, and NET_ADMIN comes from
# the compose spec (installer grants it). PPP/IPsec client artifacts are
# version-pinned and SHA-256 verified before dpkg/apt resolves their library
# closure; provenance/licenses stay in the final image for audit.
COPY vendor/ppp-clients/manifest.json /tmp/ppp-client-manifest.json
RUN set -eux; \
    test "$(dpkg --print-architecture)" = "amd64"; \
    apt-get update; \
    mkdir -p /tmp/ppp-client-debs /usr/share/doc/zagros; \
    cd /tmp/ppp-client-debs; \
    specs="$(python3 -c 'import json; d=json.load(open("/tmp/ppp-client-manifest.json")); print(" ".join(p["package"]+"="+p["version"] for p in d["packages"]))')"; \
    apt-get download $specs; \
    python3 -c 'import hashlib,json,pathlib; d=json.load(open("/tmp/ppp-client-manifest.json")); root=pathlib.Path("/tmp/ppp-client-debs"); [(lambda f,p: (_ for _ in ()).throw(SystemExit(f"sha256 mismatch: {f.name}")) if hashlib.sha256(f.read_bytes()).hexdigest()!=p["sha256"] else None)(root/p["filename"],p) for p in d["packages"]]'; \
    apt-get install -y --no-install-recommends \
       iptables nftables iproute2 openvpn wireguard-tools procps busybox-static \
       openssh-client openssh-server certbot libpcre2-8-0 ca-certificates \
       /tmp/ppp-client-debs/*.deb; \
    cp /tmp/ppp-client-manifest.json /usr/share/doc/zagros/ppp-client-manifest.json; \
    test "$(dpkg-query -W -f='${Version}' ppp)" = "2.5.2-1+1"; \
    test "$(dpkg-query -W -f='${Version}' xl2tpd)" = "1.3.18-1+b1"; \
    test "$(dpkg-query -W -f='${Version}' sstp-client)" = "1.0.20-1+b2"; \
    test "$(dpkg-query -W -f='${Version}' pptp-linux)" = "1.10.0-2"; \
    test "$(dpkg-query -W -f='${Version}' strongswan-charon)" = "6.0.1-6+deb13u6"; \
    test -x /usr/sbin/pppd; test -x /usr/sbin/xl2tpd; \
    test -x /usr/sbin/sstpc; \
    test -f /usr/lib/pppd/2.5.2/sstp-pppd-plugin.so; \
    test -x /usr/sbin/pptp; \
    test -x /usr/lib/ipsec/charon; test -x /usr/sbin/swanctl; \
    rm -rf /tmp/ppp-client-debs /var/lib/apt/lists/*

ENV PYTHON_LIB_PATH=/usr/local/lib/python${PYTHON_VERSION%.*}/site-packages

WORKDIR /code

RUN rm -rf $PYTHON_LIB_PATH/*

COPY --from=build $PYTHON_LIB_PATH $PYTHON_LIB_PATH
COPY --from=build /usr/local/bin /usr/local/bin

COPY --from=accel-ppp-build /bundle/sbin/accel-pppd /opt/zagros/accel-ppp/1.14.0/sbin/accel-pppd
COPY --from=accel-ppp-build /bundle/lib/accel-ppp /opt/zagros/accel-ppp/1.14.0/lib/accel-ppp
COPY --from=accel-ppp-build /bundle/source /usr/share/doc/zagros/accel-ppp-1.14.0

COPY . /code
# Frontend assets always come from the deterministic dashboard stage
# (this path is git-ignored in the working tree).
COPY --from=dashboard /code/build /code/app/dashboard/build

RUN ln -s /code/zagros-cli.py /usr/bin/zagros-cli \
    && chmod +x /usr/bin/zagros-cli \
    && zagros-cli completion install --shell bash

CMD ["bash", "-c", "alembic upgrade head; python main.py"]
