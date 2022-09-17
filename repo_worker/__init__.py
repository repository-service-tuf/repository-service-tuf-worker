import os

from dynaconf import Dynaconf

DATA_DIR = os.getenv("DATA_DIR", "/data")
os.makedirs(DATA_DIR, exist_ok=True)
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.ini")

worker_settings = Dynaconf(
    settings_files=[SETTINGS_FILE],
    envvar_prefix="KAPRIEN",
)


SETTINGS_REPOSITORY_FILE = os.path.join(DATA_DIR, "task_settings.ini")
repository_settings = Dynaconf(
    redis_enabled=True,
    redis={
        "host": worker_settings.REDIS_SERVER.split("redis://")[1],
        "port": worker_settings.get("KAPRIEN_REDIS_SERVER_PORT", 6379),
        "db": worker_settings.get("KAPRIEN_REDIS_SERVER_DB_REPO_SETTINGS", 1),
        "decode_responses": True,
    },
)
