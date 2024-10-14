#!/bin/env python3

# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import datetime
import json
import logging
from enum import Enum
from typing import Any, Dict, List, Optional

import redis
from celery import Celery, chain, chord, group, schedules, shared_task, signals
from tuf.api.metadata import MetaFile

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

repository = MetadataRepository.create_service()


@app.task(serializer="json", bind=True)
def repository_service_tuf_worker(
    self,
    action: str,
    payload: Optional[Dict[str, Any]] = None,
):
    """
    Repository Service for TUF Metadata Worker main Celery consumer.

    Args:
        action: which action to be executed by the task.
        payload: data that will be given to the action.
    """
    repository_action = getattr(repository, action)
    if payload is None:
        result = repository_action()
    else:
        # add task id to payload
        payload["task_id"] = self.request.id

        result = repository_action(payload, update_state=self.update_state)

    return result


@app.task(serializer="json", queue="rstuf_internals")
def is_role_expired(role: str) -> Optional[str]:
    """
    Check if a role is expired.

    Args:
        role: Role to be checked.

    Returns:
        None if the role is not expired, otherwise the role name.
    """
    if repository._is_expired(role):
        return repository._update_targets_delegated_role(role)


@app.task(serializer="json", queue="rstuf_internals")
def update_snapshot_timestamp(*args) -> Dict[str, Any]:
    """
    Update the snapshot timestamp.

    Args:
        args: List of arguments.

    Returns:
        Dictionary with the updated snapshot timestamp.
    """
    snapshot_meta = {m: MetaFile(v) for m, v in args[0][0].items()}
    target_files = args[0][1]

    def update_snapshot():
        if snapshot_meta:
            snapshot = repository.load_snapshot()
            snapshot.signed.meta.update(snapshot_meta)
            repository._bump_and_persist(snapshot, "snapshot")
            logging.debug("Bumped version of 'Snapshot' role")
            version = snapshot.signed.version
            return version

    repository.update_db_files_to_published(target_files)
    repository._update_timestamp(update_snapshot())


@app.task(serializer="json", queue="rstuf_internals")
def update_roles(*args) -> Dict[str, Any]:
    """
    Update roles.

    Args:
        roles: List of roles to be updated.

    Returns:
        Dictionary with the updated roles.
    """
    meta = {}
    target_files = []
    for arg0 in args[0]:
        # concatenate the dictionaries
        meta.update(arg0[0])
        target_files.extend(arg0[1])

    return meta, target_files


@app.task(serializer="json", queue="rstuf_internals")
def chain_bump_online_roles() -> Dict[str, Any]:
    """
    Chain of tasks to bump online roles.

    Returns:
        Dictionary with the online roles.
    """
    with repository._redis.lock("LOCK_TARGETS", repository._timeout):
        roles = repository.get_delegated_roles()
        c = chain(
            group(is_role_expired.s(role) for role in roles),
            update_roles.s(),
            update_snapshot_timestamp.s(),
        )()
        return c.get()


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
    # "bump_online_roles": {
    #     "task": "app.repository_service_tuf_worker",
    #     "schedule": schedules.crontab(minute="*/15"),
    #     "kwargs": {
    #         "action": "bump_online_roles",
    #     },
    #     "options": {
    #         "task_id": "bump_online_roles",
    #         "queue": "rstuf_internals",
    #         "acks_late": True,
    #     },
    "bump_online_roles": {
        "task": "app.chain_bump_online_roles",
        "schedule": schedules.crontab(minute="*/15"),
        "options": {
            "task_id": "bump_online_roles",
            "queue": "rstuf_internals",
            "acks_late": True,
        },
    },
}
