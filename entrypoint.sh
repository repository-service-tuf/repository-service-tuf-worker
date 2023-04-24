#!/bin/bash
if [ -z $RSTUF_WORKER_ID ]; then
    export RSTUF_WORKER_ID=$(hostname)
fi
alembic upgrade head
supervisord -c $DATA_DIR/supervisor.conf