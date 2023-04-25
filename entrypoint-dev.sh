#!/bin/bash
if [ -z $RSTUF_WORKER_ID ]; then
    export RSTUF_WORKER_ID=$(hostname)
fi
alembic upgrade head
watchmedo auto-restart -d /opt/repository-service-tuf-worker -R -p '*.py' -- supervisord -c supervisor-dev.conf