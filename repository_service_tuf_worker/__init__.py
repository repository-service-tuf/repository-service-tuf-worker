# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import os

from dynaconf import Dynaconf

_DEFAULT_CONTAINER_DATA_DIR = "/data"


def _resolve_data_dir() -> str:
    """Worker state directory. Prefer ``DATA_DIR``; else ``/data`` in containers;
    on a dev machine without permission to use ``/data``, fall back to
    ``./data-test`` (same as tox). A shell ``DATA_DIR=/data`` that cannot be
    created is overridden so local ``pytest`` still runs.
    """
    fallback = os.path.join(os.getcwd(), "data-test")

    if "DATA_DIR" in os.environ:
        path = os.environ["DATA_DIR"]
        try:
            os.makedirs(path, exist_ok=True)
            return path
        except OSError:
            os.makedirs(fallback, exist_ok=True)
            os.environ["DATA_DIR"] = fallback
            return fallback

    try:
        os.makedirs(_DEFAULT_CONTAINER_DATA_DIR, exist_ok=True)
        return _DEFAULT_CONTAINER_DATA_DIR
    except OSError:
        os.makedirs(fallback, exist_ok=True)
        return fallback


DATA_DIR = _resolve_data_dir()


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

    return Dynaconf(
        redis_enabled=True,
        redis={
            "host": worker_settings.REDIS_SERVER.split("redis://")[1],
            "port": worker_settings.get("REDIS_SERVER_PORT", 6379),
            "db": worker_settings.get("REDIS_SERVER_DB_REPO_SETTINGS", 1),
            "decode_responses": True,
        },
    )
