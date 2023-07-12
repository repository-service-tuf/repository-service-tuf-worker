#!/bin/bash
if [ -z $RSTUF_WORKER_ID ]; then
    export RSTUF_WORKER_ID=$(hostname)
fi

alembic upgrade head
if [[ $? -ne 0 ]]; then
    echo "Failed to initiate the database"
    exit 1
fi
watchmedo auto-restart -d /opt/repository-service-tuf-worker -R -p '*.py' -- supervisord -c supervisor-dev.conf