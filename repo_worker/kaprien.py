import logging
from typing import Any, Dict

import redis
from dynaconf import Dynaconf

from repo_worker.worker_settings import config


def store_online_keys(
    roles_config: Dict[str, Any], worker_config: Dynaconf
) -> bool:
    if role_settings := roles_config.get("roles"):
        for rolename, items in role_settings.items():
            # store keys in Key Vault
            if keys := items.get("keys"):
                worker_config.KEYVAULT.put(rolename, keys.values())
    else:
        return False

    return True


def main(
    action: str,
    payload: Dict[str, Any],
    worker_settings: Dynaconf,
    task_settings: Dynaconf,
) -> bool:

    if action == "add_initial_metadata":
        # Initialize the TUF Metadata
        config.update(worker_settings, task_settings)
        config.get.repository.add_initial_metadata(payload.get("metadata"))

        # Store online keys to the Key Vault
        store_online_keys(payload.get("settings"), config.get.settings)

    elif action == "add_targets":
        config.update(worker_settings, task_settings)
        config.get.repository.add_targets(payload.get("targets"))

    elif action == "automatic_version_bump":
        r = redis.StrictRedis.from_url(config.get.settings.REDIS_SERVER)
        with r.lock("TUF_REPO_LOCK"):
            logging.debug(
                f"[{action}] starting with settings "
                f"{config.get.settings.to_dict()}"
            )
            if config.get.settings.get("BOOTSTRAP") is None:
                logging.info(
                    "[automatic_version_bump] No bootstrap, skipping..."
                )
                return None

            config.get.repository.bump_snapshot()
            config.get.repository.bump_bins_roles()

            return True

    else:
        raise AttributeError(f"Invalid action attribute '{action}'")

    return True
