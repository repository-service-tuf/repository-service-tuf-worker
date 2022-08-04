#!/bin/env python3
#
# Copyright (c) 2020 Kairo de Araujo
#
#
import logging

from celery import Celery
from dynaconf import Dynaconf

from kaprien_repo_worker import runner

settings = Dynaconf(
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


# BROKER_USE_SSL = {
#     "keyfile": "data/certs/engine_mq.pem",
#     "certfile": "data/certs/engine_mq.crt",
#     "ca_certs": "data/certs/ca_mq.crt",
#     "cert_reqs": ssl.CERT_REQUIRED,
# }

app = Celery(
    f"kaprien_repo_worker_{settings.WORKER_ID}",
    broker=f"amqp://{settings.RABBITMQ_SERVER}",
    backend="rpc://",
    result_persistent=True,
    task_acks_late=True,
    broker_heartbeat=0,
    # broker_use_ssl=BROKER_USE_SSL,
)


@app.task(serializer="json")
def kaprien_repository_action(task):
    result = runner.main(task)

    return result
