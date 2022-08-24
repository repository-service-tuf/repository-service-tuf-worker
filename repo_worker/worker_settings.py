import importlib
from dataclasses import dataclass
from typing import Optional

from dynaconf import Dynaconf

# the 'service import is used by get_config() for automatically discovery
from repo_worker import services  # noqa
from repo_worker.tuf import MetadataRepository
from repo_worker.tuf.interfaces import IKeyVault, IStorage


@dataclass
class WorkerConfig:
    settings: Dynaconf
    repository: MetadataRepository


def get_config(
    worker_settings: Dynaconf, task_settings: Optional[Dynaconf] = None
) -> WorkerConfig:
    if task_settings is not None:
        worker_settings.update(task_settings)
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

    settings.STORAGE = settings.STORAGE_BACKEND(**storage_kwargs)
    settings.KEYVAULT = settings.KEYVAULT_BACKEND(**keyvault_kwargs)
    repository = MetadataRepository(
        settings.STORAGE, settings.KEYVAULT, settings
    )

    return WorkerConfig(settings=settings, repository=repository)
