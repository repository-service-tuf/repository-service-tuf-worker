#!/bin/env python3

# SPDX-FileCopyrightText: 2023-2025 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import itertools
import json
import logging
import time
import ssl
from enum import Enum
from typing import Any, Dict, List, Optional

import redis
from celery import Celery, chain, schedules, signals

from repository_service_tuf_worker import get_worker_settings, parse_if_secret
from repository_service_tuf_worker.repository import (
    MetadataRepository,
    MetaFile,
)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)


worker_settings = get_worker_settings()

BOR_LOCK = "BOR"
BOR_TTL = worker_settings.get("BUMP_ONLINE_ROLES_TTL", 600)  # Lock expiration


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

if worker_settings.get("BROKER_SSL_ENABLE", "false") == "false":
    BROKER_USE_SSL = None
else:
    BROKER_USE_SSL = {
        "keyfile": parse_if_secret(worker_settings.BROKER_SSL_KEYFILE),
        "certfile": parse_if_secret(worker_settings.BROKER_SSL_CERTFILE),
        "ca_certs": parse_if_secret(worker_settings.BROKER_SSL_CA_CERTS),
        "cert_reqs": ssl.CERT_REQUIRED,
    }

repository = MetadataRepository.create_service()


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
    broker_heartbeat=0
)

if BROKER_USE_SSL:
    app.conf.broker_use_ssl = BROKER_USE_SSL
    app.conf.redis_backend_use_ssl = BROKER_USE_SSL
    logging.info(
        "SSL explicitly configured for Celery broker. Ensure BROKER_SERVER URL uses an SSL scheme (e.g., amqps:// or rediss://)."
    )

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
def _end_bor_chain_callback(result, start_time: float):
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
    repository._redis.delete(BOR_LOCK)
    logging.info("Bump online roles lock removed")
    return {"result": result, "execution_time_seconds": total_time}


@app.task(serializer="json", queue="rstuf_internals")
def _update_online_role(role: str) -> Optional[str]:
    """
    Update online role (DB and JSON)
    """
    return repository.update_targets_delegated_role(role)


@app.task(serializer="json", queue="rstuf_internals")
def _update_snapshot_timestamp(*args) -> Dict[str, Any]:
    """
    Update the snapshot timestamp with the updated roles data.
    """
    updated_roles = list(itertools.chain.from_iterable(args[0]))
    snapshot_meta = {}
    database_meta = {}
    start_time = time.time()
    for role in updated_roles:
        if role:
            # Generate snapshot meta
            snapshot_meta.update(
                {f"{k}.json": MetaFile(v["version"]) for k, v in role.items()}
            )
            # Generate database meta
            database_meta.update(
                {
                    k: (v["expire"], v["version"])
                    for k, v in role.items()
                    if k != "targets"
                }
            )
    logging.info(
        "Time parsing _update_snapshot_timestamp: "
        f"{time.time() - start_time} seconds"
    )

    repository._update_timestamp(
        repository.update_snapshot(snapshot_meta, database_meta).signed.version
    )
    logging.info(
        "Time updating _update_snapshot_timestamp: "
        f"{time.time() - start_time} seconds"
    )

    logging.info(
        f"Updated snapshot/timestamp with {len(updated_roles)} role(s)"
    )


@app.task(serializer="json", queue="rstuf_internals")
def bump_online_roles(expired: bool = False) -> List[Optional[str]]:
    """
    Bump all online roles.
    """

    def _calculate_chunk_size(num_roles: int) -> int:
        chunk_size_cfg = repository._settings.get_fresh(
            "BUMP_ONLINE_ROLES_CHUNK_SIZE", 500
        )
        if num_roles <= chunk_size_cfg:
            chunk_size = int(num_roles / 2)
        else:
            chunk_size = chunk_size_cfg

        return chunk_size

    start_time = time.time()

    # Try to acquire lock
    if not repository._redis.set(BOR_LOCK, "locked", ex=BOR_TTL, nx=True):
        logging.info(
            "Skipping bump_online_roles, another task is already running."
        )
        _end_bor_chain_callback(None, start_time)
        return []

    if repository.bootstrap_state != "finished":
        logging.info("Skipping bump_online_roles, bootstrap not finished.")
        # call end within the bump_online_role task
        _end_bor_chain_callback(None, start_time)
        return []

    status_lock_targets = False
    # Lock to avoid race conditions. See `LOCK_TIMEOUT` in the Worker
    # development guide documentation.
    try:
        with repository._redis.lock("LOCK_TARGETS", repository._timeout):
            roles = repository.get_delegated_rolenames(expired=expired)
            logging.info(f"Total roles to bump: {len(roles)}")

            # No expired roles, call end within the bump_online_role task
            if len(roles) == 0:
                _end_bor_chain_callback(None, start_time)
                return roles

            chunk_size = _calculate_chunk_size(len(roles))

            # It is a corner cases
            # We have only one role to be update and chunk_size is 0
            # _calculate_chunk_size() will return (1 / 2) = 0
            # Celery chunks cannot have group equal 1, so we execute
            # without groups, directly.
            # it also applies when there is one role independet of the chunk
            # size
            if chunk_size == 0 and len(roles) == 1:
                # call the update and end of chain within bump_online_role task
                _update_snapshot_timestamp(
                    [[repository.update_targets_delegated_role(roles[0])]]
                )
                _end_bor_chain_callback(None, start_time)

                return roles

            else:
                # Run updates in chain using chunks which improves the
                # performance.
                # As a Worker can pick multiple tasks in parallel, more
                # workers more performance.

                # task groups from the chunk size
                # ex: 2048 creates 5 task groups of _update_online_role task
                task_groups = _update_online_role.chunks(
                    zip(roles), chunk_size
                ).group()
                logging.info(
                    f"Tasks: {len(task_groups)} | Chunk size: {chunk_size}"
                )
                # create the chain with task groups and call a task
                # _update_snapshot_timestamp with the result of
                # _update_online_role task
                # when finished, call _end_bor_chain_callback task
                chain(
                    task_groups,
                    _update_snapshot_timestamp.s(task_groups),
                    _end_bor_chain_callback.s(start_time),
                )(queue="rstuf_internals")

                return roles
    except redis.exceptions.LockNotOwnedError:
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
        "schedule": schedules.crontab(minute="*/5"),
        "kwargs": {"expired": True},
        "options": {
            "task_id": "bump_online_roles",
            "queue": "rstuf_internals",
            "acks_late": True,
        },
    },
}
