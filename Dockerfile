# Base
FROM python:3.13-slim AS base_os

# Builder requirements and deps
FROM base_os AS builder

ENV PYTHONDONTWRITEBYTECODE=1
ADD Pipfile* /builder/

WORKDIR /builder
RUN apt-get update && apt-get install gcc libpq-dev -y

RUN pip install --upgrade pip && pip install pipenv

RUN pipenv install --system --deploy

RUN apt-get remove gcc --purge -y \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean autoclean \
    && apt-get autoremove --yes

# Final image
FROM base_os AS pre-final
RUN apt-get update && apt-get install libpq-dev -y && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/bin /usr/local/bin/
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages/

# Final stage
FROM pre-final

WORKDIR /opt/repository-service-tuf-worker
RUN mkdir /data
COPY alembic.ini /opt/repository-service-tuf-worker/
COPY alembic /opt/repository-service-tuf-worker/alembic
COPY app.py /opt/repository-service-tuf-worker
COPY entrypoint.sh /opt/repository-service-tuf-worker
COPY supervisor.conf /opt/repository-service-tuf-worker/
COPY repository_service_tuf_worker /opt/repository-service-tuf-worker/repository_service_tuf_worker
ENTRYPOINT ["bash", "entrypoint.sh"]