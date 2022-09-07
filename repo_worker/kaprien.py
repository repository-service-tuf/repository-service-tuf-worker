import logging
from typing import Any, Dict

import redis
from dynaconf import Dynaconf

from repo_worker.config import runner


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
        r = redis.StrictRedis.from_url(runner.get.settings.RESULT_BACKEND_SERVER)
        with r.lock("TUF_REPO_LOCK"):
            # Initialize the TUF Metadata
            runner.update(worker_settings, task_settings)
            runner.get.repository.add_initial_metadata(payload.get("metadata"))

            # Store online keys to the Key Vault
            if settings := payload.get("settings"):
                store_online_keys(settings, runner.get.settings)
            else:
                raise (ValueError("No settings in the payload"))

    elif action == "add_targets":
        r = redis.StrictRedis.from_url(runner.get.settings.RESULT_BACKEND_SERVER)
        with r.lock("TUF_REPO_LOCK"):
            runner.update(worker_settings, task_settings)
            runner.get.repository.add_targets(payload.get("targets"))

    elif action == "automatic_version_bump":
        r = redis.StrictRedis.from_url(runner.get.settings.RESULT_BACKEND_SERVER)
        with r.lock("TUF_REPO_LOCK"):
            logging.debug(
                f"[{action}] starting with settings "
                f"{runner.get.settings.to_dict()}"
            )
            if runner.get.settings.get("BOOTSTRAP") is None:
                logging.info(
                    "[automatic_version_bump] No bootstrap, skipping..."
                )
                return False

            runner.get.repository.bump_snapshot()
            runner.get.repository.bump_bins_roles()

            return True

    else:
        raise AttributeError(f"Invalid action attribute '{action}'")

    return True
