ARG PYTHON_VERSION=3.12
# Dashboard toolchain pinned to the node line the dashboard's vite 3 stack
# was built and verified with.
ARG NODE_IMAGE=node:16.20.2-bullseye-slim

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
RUN npm run build --if-present -- --outDir build --assetsDir statics \
    && cp ./build/index.html ./build/404.html

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
