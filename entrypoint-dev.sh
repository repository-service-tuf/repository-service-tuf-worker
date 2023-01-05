#!/bin/bash
alembic upgrade head
watchmedo auto-restart -d /opt/repository-service-tuf-worker -R -p '*.py' -- supervisord -c supervisor-dev.conf