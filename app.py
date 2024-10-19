#!/bin/env python3

# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import json
import logging
import time
import itertools
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
def _update_online_role(role: List[str]) -> Optional[str]:
    """
    Check if a role is expired and update it.
    """
    return repository._update_targets_delegated_role(role)

@app.task(serializer="json", queue="rstuf_internals")
def _update_snapshot_timestamp(*args) -> Dict[str, Any]:
    """
    Update the snapshot timestamp with the updated roles data.
    """
    updated_roles = list(itertools.chain.from_iterable(args[0]))
    target_files = []
    snapshot_meta = {}
    database_meta = {}
    for role in updated_roles:
        if role:
            snapshot_meta.update(
                {f"{k}": MetaFile(v["version"]) for k, v in role.items()}
            )
            # Update the database_meta with the expire time of the roles, except the targets
            database_meta.update({k: v["expire"] for k, v in role.items() if k != "targets"})
            target_files.extend([v["target_files"] for v in role.values()])

    repository.update_timestamp(
        repository.update_snapshot(
            snapshot_meta, database_meta, target_files
        ).signed.version
    )

    logging.info(f"Updated snapshot/timestamp with {len(updated_roles)} roles")


@app.task(serializer="json", queue="rstuf_internals")
def _end_chain_callback(result, start_time: float):
    """
    Callback to calculate the total execution time of the chain.

    Args:
        result: The result from the previous task in the chain.
        start_time: The start time captured at the beginning of the chain.

    Returns:
        The final result of the chain and the total execution time.
    """
    end_time = time.time()
    total_time = end_time - start_time

    logging.info(
        f"Total execution time for bump_online_roles: {total_time:.2f} seconds"
    )

    # Return the final result along with the execution time for reference
    return {"result": result, "execution_time_seconds": total_time}


@app.task(serializer="json", queue="rstuf_internals")
def bump_online_roles(expired: bool = False) -> None:
    """
    Bump all online roles.
    """
    start_time = time.time()
    if repository.bootstrap_state != "finished":
        logging.info("Bootstrap not finished yet. Skipping bump_online_roles")
        c = chain(_end_chain_callback.s(None, start_time))()
        return

    status_lock_targets = False
    # Lock to avoid race conditions. See `LOCK_TIMEOUT` in the Worker
    # development guide documentation.
    try:
        with repository._redis.lock("LOCK_TARGETS", repository._timeout):
            chunks_size = 500
            roles = repository.get_delegated_rolenames(expired=expired)
            group_update_roles = _update_online_role.chunks(zip(roles), chunks_size).group()
            # c = chain(
            #     group(_update_online_role.s(role) for role in roles)(),
            #     _update_snapshot_timestamp.s(),
            #     _end_chain_callback.s(start_time),
            # )(queue="rstuf_internals")
            c = chain(
                group_update_roles,
                _update_snapshot_timestamp.s(),
                _end_chain_callback.s(start_time),
            )(queue="rstuf_internals")
            return c
    except redis.exceptions.LockNotOwnedError:
        # The LockNotOwnedError happens when the task exceeds the timeout,
        # and another task owns the lock.
        # If the task time out, the lock is released. If it doesn't finish
        # properly, it will raise (fail) the task. Otherwise, the ignores
        # the error because another task didn't lock it.
        if status_lock_targets is False:
            logging.error(
                "The task to bump all online roles exceeded the timeout "
                f"of {repository._timeout} seconds."
            )
            raise redis.exceptions.LockError(
                f"RSTUF: Task exceed `LOCK_TIMEOUT` ({repository._timeout} "
                "seconds)"
            )


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
        "task": "app.bump_online_roles",
        "schedule": schedules.crontab(minute="*/10"),
        "options": {
            "task_id": "bump_online_roles",
            "queue": "rstuf_internals",
            "acks_late": True,
        },
    },
}
