# Base
FROM python:3.14-slim AS base_os

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
COPY --from=builder /usr/local/lib/python3.14/site-packages /usr/local/lib/python3.14/site-packages/

# Final stage
FROM pre-final

# Create a non-root user
RUN addgroup --system rstuf && adduser --system --group rstuf

WORKDIR /opt/repository-service-tuf-worker
ENV DATA_DIR=/data
RUN mkdir $DATA_DIR && chown rstuf:rstuf $DATA_DIR

COPY --chown=rstuf:rstuf alembic.ini /opt/repository-service-tuf-worker/
COPY --chown=rstuf:rstuf alembic /opt/repository-service-tuf-worker/alembic
COPY --chown=rstuf:rstuf app.py /opt/repository-service-tuf-worker
COPY --chown=rstuf:rstuf entrypoint.sh /opt/repository-service-tuf-worker
COPY --chown=rstuf:rstuf supervisor.conf ${DATA_DIR}/
COPY --chown=rstuf:rstuf repository_service_tuf_worker /opt/repository-service-tuf-worker/repository_service_tuf_worker

USER rstuf

ENTRYPOINT ["bash", "entrypoint.sh"]