# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import os

from dynaconf import Dynaconf

DATA_DIR = os.getenv("DATA_DIR", "/data")
os.makedirs(DATA_DIR, exist_ok=True)


def parse_if_secret(env_var: str) -> str:
    if env_var.startswith("/run/secrets/"):
        # The user has stored their variable using container secrets.
        with open(env_var) as f:
            content = f.read().rstrip("\n")
    else:
        content = env_var

    return content


def get_worker_settings() -> Dynaconf:
    SETTINGS_FILE = os.path.join(DATA_DIR, "settings.ini")
    return Dynaconf(
        settings_files=[SETTINGS_FILE],
        envvar_prefix="RSTUF",
    )


def get_repository_settings() -> Dynaconf:
    worker_settings = get_worker_settings()
    redis_server = worker_settings.get("REDIS_SERVER")

    if redis_server:
        # Host can be redis://redis or just redis
        if "://" in redis_server:
            host = redis_server.split("://")[1]
        else:
            host = redis_server

        return Dynaconf(
            redis_enabled=True,
            redis={
                "host": host,
                "port": worker_settings.get("REDIS_SERVER_PORT", 6379),
                "db": worker_settings.get("REDIS_SERVER_DB_REPO_SETTINGS", 1),
                "decode_responses": True,
            },
        )
    else:
        return Dynaconf(
            loaders=["repository_service_tuf_worker.loaders"],
            DB_SERVER=worker_settings.get("DB_SERVER"),
        )
