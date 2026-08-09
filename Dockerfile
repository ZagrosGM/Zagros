ARG PYTHON_VERSION=3.12
# Dashboard toolchain for the unified Zagros panel (React 18 + vite 5 +
# Tailwind) — node 20 LTS, multi-arch (amd64 + arm64).
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
# Stage 2: python dependencies
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
LABEL org.opencontainers.image.title="Zagros" \
      org.opencontainers.image.description="Zagros — Enterprise Multi-Core VPN Management Platform" \
      org.opencontainers.image.source="https://github.com/ZagrosGM/Zagros" \
      org.opencontainers.image.licenses="AGPL-3.0"

# Runtime network tooling for the host-managing cores:
#  * iptables — SSH per-UID usage accounting (owner-match chain, alpha.7.4)
#  * iproute2 — WireGuard/OpenVPN interface plumbing + net diagnostics
#  * certbot  — REAL ACME / Let's Encrypt issuance from the Certificates
#    page (alpha.7.5 item 9); the panel detects it at runtime, and acme.sh /
#    lego stay supported for operators who install them instead.
# All are inert until such a feature is enabled, and NET_ADMIN comes from
# the compose spec (installer grants it).
RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables iproute2 certbot \
    && rm -rf /var/lib/apt/lists/*

ENV PYTHON_LIB_PATH=/usr/local/lib/python${PYTHON_VERSION%.*}/site-packages

WORKDIR /code

RUN rm -rf $PYTHON_LIB_PATH/*

COPY --from=build $PYTHON_LIB_PATH $PYTHON_LIB_PATH
COPY --from=build /usr/local/bin /usr/local/bin

COPY . /code
# Frontend assets always come from the deterministic dashboard stage
# (this path is git-ignored in the working tree).
COPY --from=dashboard /code/build /code/app/dashboard/build

RUN ln -s /code/zagros-cli.py /usr/bin/zagros-cli \
    && chmod +x /usr/bin/zagros-cli \
    && zagros-cli completion install --shell bash

CMD ["bash", "-c", "alembic upgrade head; python main.py"]
