import importlib
import logging
import os
from dataclasses import dataclass
from typing import Optional

from dynaconf import Dynaconf, loaders

# the 'service import is used by get_config() for automatically discovery
from repo_worker import services  # noqa
from repo_worker.tuf import MetadataRepository
from repo_worker.tuf.interfaces import IKeyVault, IStorage

DATA_DIR = os.getenv("DATA_DIR", "/data")
os.makedirs(DATA_DIR, exist_ok=True)
TASK_SETTINGS_FILE = os.path.join(DATA_DIR, "task_settings.ini")
last_task_settings = Dynaconf(
    settings_files=[TASK_SETTINGS_FILE],
)


@dataclass
class WorkerConfig:
    settings: Dynaconf
    repository: MetadataRepository


class Configuration:
    def __init__(self):
        self.config: WorkerConfig

    def update(
        self,
        worker_settings: Dynaconf,
        task_settings: Optional[Dynaconf] = None,
    ):
        if task_settings is not None:
            worker_settings.update(task_settings)
            last_task_settings.update(task_settings)
            loaders.write(
                last_task_settings.SETTINGS_FILE_FOR_DYNACONF[0],
                last_task_settings.to_dict(),
            )
        else:
            worker_settings.update(last_task_settings)

        settings = worker_settings

        storage_backends = [
            storage.__name__.upper() for storage in IStorage.__subclasses__()
        ]

        if type(settings.STORAGE_BACKEND) != str and issubclass(
            settings.STORAGE_BACKEND, tuple(IStorage.__subclasses__())
        ):
            logging.debug(
                f"STORAGE_BACKEND is defined as {settings.STORAGE_BACKEND}"
            )

        elif settings.STORAGE_BACKEND.upper() not in storage_backends:
            raise ValueError(
                f"Invalid Storage Backend {settings.STORAGE_BACKEND}."
                f"Supported Storage Backends {', '.join(storage_backends)}"
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
                    "'Settings' object has not attribute(s) "
                    f"{', '.join(missing)}"
                )

            settings.STORAGE_BACKEND.configure(settings)
            storage_kwargs = {
                s.argument: settings.store[s.name]
                for s in settings.STORAGE_BACKEND.settings()
            }
            settings.STORAGE = settings.STORAGE_BACKEND(**storage_kwargs)

        keyvault_backends = [
            keyvault.__name__.upper()
            for keyvault in IKeyVault.__subclasses__()
        ]

        if type(settings.KEYVAULT_BACKEND) != str and issubclass(
            settings.KEYVAULT_BACKEND, tuple(IKeyVault.__subclasses__())
        ):
            logging.debug(
                f"KEYVAULT_BACKEND is defined as {settings.KEYVAULT_BACKEND}"
            )

        elif settings.KEYVAULT_BACKEND.upper() not in keyvault_backends:
            raise ValueError(
                f"Invalid Key Vault Backend {settings.KEYVAULT_BACKEND}. "
                "Supported Key Vault Backends :"
                f"{', '.join(keyvault_backends)}"
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
                    "'Settings' object has not attribute(s) "
                    f"{', '.join(missing)}"
                )

            settings.KEYVAULT_BACKEND.configure(settings)
            keyvault_kwargs = {
                s.argument: settings.store[s.name]
                for s in settings.KEYVAULT_BACKEND.settings()
            }

            settings.KEYVAULT = settings.KEYVAULT_BACKEND(**keyvault_kwargs)

        repository = MetadataRepository(
            settings.STORAGE, settings.KEYVAULT, settings
        )

        self.config = WorkerConfig(settings=settings, repository=repository)

    @property
    def get(self):
        return self.config


runner = Configuration()
