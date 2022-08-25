#!/bin/env python3
#
# Copyright (c) 2022 Kairo de Araujo
#
#
import json
import logging
import os
from enum import Enum

import redis
from celery import Celery, signals
from dynaconf import Dynaconf

from repo_worker import kaprien

SETTINGS_FILE = os.getenv("SETTINGS_FILE", "settings.ini")

worker_settings = Dynaconf(
    settings_files=[SETTINGS_FILE],
    envvar_prefix="KAPRIEN",
    environments=True,
)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)


class status(Enum):
    PRE_RUN = "PRE_RUN"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    UNKNOWN = "UNKNOWN"
    FAILURE = "FAILURE"


redis_backend = redis.StrictRedis.from_url("redis://redis")

# TODO: Issue https://github.com/KAPRIEN/kaprien/issues/6
# BROKER_USE_SSL = {
#     "keyfile": "data/certs/engine_mq.pem",
#     "certfile": "data/certs/engine_mq.crt",
#     "ca_certs": "data/certs/ca_mq.crt",
#     "cert_reqs": ssl.CERT_REQUIRED,
# }

app = Celery(
    f"kaprien_repo_worker_{worker_settings.WORKER_ID}",
    broker=f"amqp://{worker_settings.RABBITMQ_SERVER}",
    backend="redis://redis",
    result_persistent=True,
    task_acks_late=True,
    task_track_started=True,
    broker_heartbeat=0,
    # broker_use_ssl=BROKER_USE_SSL
    # (https://github.com/KAPRIEN/kaprien/issues/6)
)


@app.task(serializer="json")
def kaprien_repo_worker(action, settings, payload):
    logging.debug(f"{action} received")
    return kaprien.main(
        action=action,
        payload=payload,
        worker_settings=worker_settings,
        task_settings=settings,
    )


def _publish_backend(status, task_id):
    redis_backend.set(
        f"celery-task-meta-{task_id}",
        json.dumps({"status": status.value, "task_id": task_id}),
    )


@signals.task_prerun.connect(sender=kaprien_repo_worker)
def task_pre_run_notifier(**kwargs):
    logging.debug((f"{status.PRE_RUN.value}: {kwargs.get('task_id')}"))
    _publish_backend(status.PRE_RUN, kwargs.get("task_id"))


@signals.task_unknown.connect(sender=kaprien_repo_worker)
def task_unknown_notifier(**kwargs):
    logging.debug((f"{status.UNKNOWN.value}: {kwargs.get('task_id')}"))
    _publish_backend(status.UNKNOWN, kwargs.get("task_id"))


@signals.task_failure.connect(sender=kaprien_repo_worker)
def task_failure_notifier(**kwargs):
    logging.debug((f"{status.FAILURE.value}: {kwargs.get('task_id')}"))
    _publish_backend(status.FAILURE, kwargs.get("task_id"))
