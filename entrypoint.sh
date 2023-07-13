#!/bin/bash
if [ -z $RSTUF_WORKER_ID ]; then
    export RSTUF_WORKER_ID=$(hostname)
fi

alembic upgrade head
if [[ $? -ne 0 ]]; then
    echo "Failed to initiate the database"
    exit 1
fi
supervisord -c $DATA_DIR/supervisor.conf