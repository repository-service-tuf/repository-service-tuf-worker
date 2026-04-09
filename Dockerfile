# Base
FROM python:3.13-slim AS base_os

# Builder requirements and deps
FROM base_os AS builder

ENV PYTHONDONTWRITEBYTECODE=1
ENV UV_COMPILE_BYTECODE=1

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /builder


RUN apt-get update && apt-get install gcc libpq-dev -y


COPY pyproject.toml uv.lock ./

RUN uv sync --frozen --no-dev --no-install-project


RUN apt-get remove gcc --purge -y \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean autoclean \
    && apt-get autoremove --yes

# Final image
FROM base_os AS pre-final
RUN apt-get update && apt-get install libpq-dev -y && rm -rf /var/lib/apt/lists/*
COPY --from=builder /builder/.venv /opt/repository-service-tuf-worker/.venv
ENV PATH="/opt/repository-service-tuf-worker/.venv/bin:$PATH"

# Final stage
FROM pre-final

WORKDIR /opt/repository-service-tuf-worker
ENV DATA_DIR=/data
RUN mkdir $DATA_DIR
COPY alembic.ini /opt/repository-service-tuf-worker/
COPY alembic /opt/repository-service-tuf-worker/alembic
COPY app.py /opt/repository-service-tuf-worker
COPY entrypoint.sh /opt/repository-service-tuf-worker
COPY supervisor.conf ${DATA_DIR}/
COPY repository_service_tuf_worker /opt/repository-service-tuf-worker/repository_service_tuf_worker
ENTRYPOINT ["bash", "entrypoint.sh"]
