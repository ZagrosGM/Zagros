ARG PYTHON_VERSION=3.12

FROM python:$PYTHON_VERSION-slim AS build

ENV PYTHONUNBUFFERED=1

WORKDIR /code

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential gcc python3-dev libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# NOTE: no core binary is baked into the image. Every core driver
# (xray, sing-box, hysteria2, tuic, ...) self-installs its official
# release binary on demand at runtime (see app/cores/drivers/*/).

COPY ./requirements.txt /code/
RUN python3 -m pip install --upgrade pip setuptools \
    && pip install --no-cache-dir --upgrade -r /code/requirements.txt

FROM python:$PYTHON_VERSION-slim
LABEL org.opencontainers.image.title="Zagros" \
      org.opencontainers.image.description="Zagros — Enterprise Multi-Core VPN Management Platform" \
      org.opencontainers.image.source="https://github.com/ZagrosGM/Zagros"

ENV PYTHON_LIB_PATH=/usr/local/lib/python${PYTHON_VERSION%.*}/site-packages

WORKDIR /code

RUN rm -rf $PYTHON_LIB_PATH/*

COPY --from=build $PYTHON_LIB_PATH $PYTHON_LIB_PATH
COPY --from=build /usr/local/bin /usr/local/bin

COPY . /code

RUN ln -s /code/zagros-cli.py /usr/bin/zagros-cli \
    && chmod +x /usr/bin/zagros-cli \
    && zagros-cli completion install --shell bash

CMD ["bash", "-c", "alembic upgrade head; python main.py"]
