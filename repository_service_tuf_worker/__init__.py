# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import os

from dynaconf import Dynaconf

DATA_DIR = os.getenv("DATA_DIR", "/data")
os.makedirs(DATA_DIR, exist_ok=True)


def get_worker_settings() -> Dynaconf:
    SETTINGS_FILE = os.path.join(DATA_DIR, "settings.ini")
    return Dynaconf(
        settings_files=[SETTINGS_FILE],
        envvar_prefix="RSTUF",
    )


def get_repository_settings() -> Dynaconf:
    worker_settings = get_worker_settings()

    return Dynaconf(
        redis_enabled=True,
        redis={
            "host": worker_settings.REDIS_SERVER.split("redis://")[1],
            "port": worker_settings.get("REDIS_SERVER_PORT", 6379),
            "db": worker_settings.get("REDIS_SERVER_DB_REPO_SETTINGS", 1),
            "decode_responses": True,
        },
    )
