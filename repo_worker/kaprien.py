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
) -> bool:
    """
    Main tasks runner
    """

    if action == "add_initial_metadata":
        runner.update(worker_settings)

        # Store online keys to the Key Vault
        if settings := payload.get("settings"):
            store_online_keys(settings, runner.get.settings)
        else:
            raise (ValueError("No settings in the payload"))

        # Initialize the TUF Metadata
        runner.get.repository.add_initial_metadata(payload.get("metadata"))

    elif action == "add_targets":
        r = redis.StrictRedis.from_url(runner.get.settings.REDIS_SERVER)
        targets = payload.get("targets")
        with r.lock("TUF_BINS_HASHED"):
            runner.update(worker_settings)
            targets_meta = runner.get.repository.add_targets(targets)

        with r.lock("TUF_TARGETS_META"):
            if r.exists("umpublished_metas"):
                targets_waiting_commmit = r.get("umpublished_metas").decode(
                    "utf-8"
                )
                for bins_name, _ in targets_meta:
                    if bins_name not in targets_waiting_commmit:
                        r.append("umpublished_metas", f", {bins_name}")

            else:
                r.set(
                    "umpublished_metas",
                    ", ".join(bins_name for bins_name, _ in targets_meta),
                )

        return True

    elif action == "automatic_version_bump":
        r = redis.StrictRedis.from_url(runner.get.settings.REDIS_SERVER)
        with r.lock("TUF_SNAPSHOT_TIMESTAMP"):
            runner.update(worker_settings)
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

    elif action == "publish_targets_meta":
        runner.update(worker_settings)
        r = redis.StrictRedis.from_url(runner.get.settings.REDIS_SERVER)
        with r.lock("TUF_SNAPSHOT_TIMESTAMP"):
            import time

            time.sleep(5)
            targets_meta = r.get("umpublished_metas")
            if targets_meta is None:
                logging.debug("No new umplublished targets meta, skipping.")
                return True

            bins_names = targets_meta.decode("utf-8").split(", ")
            runner.get.repository.publish_targets_metas(bins_names)
            r.delete("umpublished_metas")
            logging.debug("Flushed umpublished targets meta")

    else:
        raise AttributeError(f"Invalid action attribute '{action}'")

    return True
