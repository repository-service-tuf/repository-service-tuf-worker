#!/bin/env python3
#
# Copyright (c) 2020 Kairo de Araujo
#
#
import importlib
import json
import logging
from dataclasses import dataclass
from enum import Enum

import redis
from celery import Celery, signals
from dynaconf import Dynaconf

from repo_worker import services  # noqa
from repo_worker.tuf import IKeyVault, IStorage, MetadataRepository

worker_settings = Dynaconf(
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


def _publish_backend(status, task_id):
    redis_backend.set(
        f"celery-task-meta-{task_id}",
        json.dumps({"status": status.value, "task_id": task_id}),
    )


@dataclass
class WorkerConfig:
    settings: Dynaconf
    repository: MetadataRepository


def _get_config(settings):
    worker_settings.update(settings)
    settings = worker_settings
    storage_backends = [
        storage.__name__.upper() for storage in IStorage.__subclasses__()
    ]

    if settings.STORAGE_BACKEND.upper() not in storage_backends:
        raise ValueError(
            f"Invalid Storage Backend {settings.STORAGE_BACKEND}. Supported "
            f"Storage Backends {', '.join(storage_backends)}"
        )
    else:
        settings.STORAGE_BACKEND = getattr(
            importlib.import_module("repo_worker.services"),
            settings.STORAGE_BACKEND,
        )

        if missing := [
            s.name
            for s in settings.STORAGE_BACKEND.settings()
            if s.required and s.name not in settings
        ]:
            raise AttributeError(
                f"'Settings' object has not attribute(s) {', '.join(missing)}"
            )

        settings.STORAGE_BACKEND.configure(settings)
        storage_kwargs = {
            s.argument: settings.store[s.name]
            for s in settings.STORAGE_BACKEND.settings()
        }

    keyvault_backends = [
        keyvault.__name__.upper() for keyvault in IKeyVault.__subclasses__()
    ]
    if settings.KEYVAULT_BACKEND.upper() not in keyvault_backends:
        raise ValueError(
            f"Invalid Key Vault Backend {settings.KEYVAULT_BACKEND}. "
            f"Supported Key Vault Backends: {', '.join(keyvault_backends)}"
        )
    else:
        settings.KEYVAULT_BACKEND = getattr(
            importlib.import_module("repo_worker.services"),
            settings.KEYVAULT_BACKEND,
        )

        if missing := [
            s.name
            for s in settings.KEYVAULT_BACKEND.settings()
            if s.required and s.name not in settings
        ]:
            raise AttributeError(
                f"'Settings' object has not attribute(s) {', '.join(missing)}"
            )

        settings.KEYVAULT_BACKEND.configure(settings)
        keyvault_kwargs = {
            s.argument: settings.store[s.name]
            for s in settings.KEYVAULT_BACKEND.settings()
        }

    storage = settings.STORAGE_BACKEND(**storage_kwargs)
    keyvault = settings.KEYVAULT_BACKEND(**keyvault_kwargs)

    repository = MetadataRepository(storage, keyvault, settings)

    return WorkerConfig(settings=settings, repository=repository)


@app.task(serializer="json")
def kaprien_repo_worker(action, settings, payload):

    config = _get_config(settings)
    if action == "add_targets":
        repository_function = getattr(config.repository, action)
        repository_function(payload.get("targets"))

    else:
        raise AttributeError(
            f"module 'MetadataRepository' has no attribute '{action}'"
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
