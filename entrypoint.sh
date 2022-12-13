#!/bin/bash
alembic upgrade head
supervisord -c $DATA_DIR/supervisor.conf