from typing import Any, Dict

from dynaconf import Dynaconf

from repo_worker.worker_settings import get_config


def store_online_keys(
    roles_config: Dict[str, Any], worker_config: Dynaconf
) -> bool:
    if role_settings := roles_config.get("roles"):
        for rolename, items in role_settings.items():
            # store keys in Key Vault
            if keys := items.get("keys"):
                worker_config.settings.KEYVAULT.put(rolename, keys.values())
    else:
        return False

    return True


def main(
    action: str,
    payload: Dict[str, Any],
    worker_settings: Dynaconf,
    task_settings: Dynaconf,
) -> bool:
    config = get_config(worker_settings, task_settings)

    if action == "add_initial_metadata":
        # Initialize the TUF Metadata
        config.repository.add_initial_metadata(payload.get("metadata"))

        # Store online keys to the Key Vault
        store_online_keys(payload.get("settings"), config)

    elif action == "add_targets":
        config.repository.add_targets(payload.get("targets"))

    elif action == "bump_snapshot":
        config.repository.bump_snapshot()

    elif action == "bump_bins_roles":
        config.repository.bump_bins_roles()

    else:
        raise AttributeError(f"Invalid action attribute '{action}'")

    return True
