#!/bin/env python3

# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT

import json
import logging
from enum import Enum
from typing import Any, Dict, Optional

import redis
from celery import Celery, schedules, signals

from repository_service_tuf_worker import get_worker_settings
from repository_service_tuf_worker.repository import MetadataRepository

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


worker_settings = get_worker_settings()


class status(Enum):
    RECEIVED = "RECEIVED"
    PRE_RUN = "PRE_RUN"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    UNKNOWN = "UNKNOWN"
    FAILURE = "FAILURE"


redis_backend = redis.StrictRedis.from_url(
    worker_settings.REDIS_SERVER,
    port=worker_settings.get("REDIS_SERVER_PORT", 6379),
    db=worker_settings.get("REDIS_SERVER_DB_RESULT", 0),
)

# TODO: Issue https://github.com/repository-service-tuf/vmware/issues/6
# BROKER_USE_SSL = {
#     "keyfile": "data/certs/engine_mq.pem",
#     "certfile": "data/certs/engine_mq.crt",
#     "ca_certs": "data/certs/ca_mq.crt",
#     "cert_reqs": ssl.CERT_REQUIRED,
# }

app = Celery(
    f"repository_service_tuf_worker_{worker_settings.WORKER_ID}",
    broker=worker_settings.BROKER_SERVER,
    backend=(
        f"{worker_settings.REDIS_SERVER}"
        f":{worker_settings.get('REDIS_SERVER_PORT', 6379)}"
        f"/{worker_settings.get('REDIS_SERVER_DB_RESULT', 0)}"
    ),
    result_persistent=True,
    task_acks_late=True,
    task_track_started=True,
    broker_heartbeat=0,
    # broker_use_ssl=BROKER_USE_SSL
    # (https://github.com/repository-service-tuf/vmware/issues/6)
)


@app.task(serializer="json", bind=True)
def repository_service_tuf_worker(
    self,
    action: str,
    payload: Optional[Dict[str, Any]] = None,
    refresh_settings: Optional[bool] = True,
):
    """
    Repository Service for TUF Metadata Worker main Celery consumer.

    Args:
        action: which action to be executed by the task.
        payload: data that will be given to the action.
        refresh_settings: whether to refresh repository settings.
    """
    if refresh_settings is True:
        repository.refresh_settings(worker_settings)

    repository_action = getattr(repository, action)
    if payload is None:
        result = repository_action()
    else:
        # add task id to payload
        payload["task_id"] = self.request.id

        result = repository_action(payload, update_state=self.update_state)

    return result


def _publish_signals(
    status: status, task_id: str, result: Optional[str] = None
):
    """
    Publishes Signals to the Result Backend.

    Args:
        status: Task status
        task_id: Task identification
        result: Result about the Task
    """
    redis_backend.set(
        f"celery-task-meta-{task_id}",
        json.dumps(
            {"status": status.value, "task_id": task_id, "result": result}
        ),
    )


@signals.task_prerun.connect(sender=repository_service_tuf_worker)
def task_pre_run_notifier(**kwargs):
    """Publishes Signal when task is in PRE_RUN state"""
    logging.debug((f"{status.PRE_RUN.value}: {kwargs.get('task_id')}"))
    _publish_signals(status.PRE_RUN, kwargs.get("task_id"))


@signals.task_unknown.connect(sender=repository_service_tuf_worker)
def task_unknown_notifier(**kwargs):
    """Publishes Signal when task is in UNKNOWN state"""
    logging.debug((f"{status.UNKNOWN.value}: {kwargs.get('task_id')}"))
    _publish_signals(status.UNKNOWN, kwargs.get("task_id"))


@signals.task_received.connect(sender=repository_service_tuf_worker)
def task_received_notifier(**kwargs):
    """Publishes Signal when task is in RECEIVED state"""
    logging.debug((f"{status.RECEIVED}: {kwargs.get('task_id')}"))
    _publish_signals(status.RECEIVED, kwargs.get("task_id"))


app.conf.beat_schedule = {
    "bump_online_roles": {
        "task": "app.repository_service_tuf_worker",
        "schedule": schedules.crontab(minute="*/10"),
        "kwargs": {
            "action": "bump_online_roles",
        },
        "options": {
            "task_id": "bump_online_roles",
            "queue": "rstuf_internals",
            "acks_late": True,
        },
    },
}

repository = MetadataRepository.create_service()
