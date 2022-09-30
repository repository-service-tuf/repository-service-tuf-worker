# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import enum
import importlib
import logging
import time
import warnings
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import redis
from securesystemslib.exceptions import StorageError  # type: ignore
from securesystemslib.signer import SSlibSigner  # type: ignore
from tuf.api.metadata import (  # noqa
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    Delegations,
    Key,
    Metadata,
    MetaFile,
    Role,
    Root,
    Snapshot,
    SuccinctRoles,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer

# the 'service import is used to retrieve sublcasses (Implemented Services)
from tuf_repository_service_worker import (  # noqa
    Dynaconf,
    repository_settings,
    services,
    worker_settings,
)
from tuf_repository_service_worker.interfaces import IKeyVault, IStorage


class Roles(enum.Enum):
    ROOT = Root.type
    TARGETS = Targets.type
    SNAPSHOT = Snapshot.type
    TIMESTAMP = Timestamp.type
    BIN = "bin"
    BINS = "bins"


ALL_REPOSITORY_ROLES_NAMES = [rolename.value for rolename in Roles]
OFFLINE_KEYS = {
    Roles.ROOT.value.upper(),
    Roles.TARGETS.value.upper(),
    Roles.BIN.value.upper(),
}

BIN = "bin"
BINS = "bins"
SPEC_VERSION: str = ".".join(SPECIFICATION_VERSION)


@dataclass
class ResultDetails:
    message: str
    details: Optional[Dict[str, Any]]


class MetadataRepository:
    """
    A repository service to create and maintain TUF role metadata.
    """

    def __init__(self):
        self._worker_settings = worker_settings
        self._settings = repository_settings
        self._storage_backend = self.refresh_settings().STORAGE
        self._key_storage_backend = self.refresh_settings().KEYVAULT
        self._redis = redis.StrictRedis.from_url(worker_settings.REDIS_SERVER)
        self._hours_before_expire: int = self._settings.get_fresh(
            "HOURS_BEFORE_EXPIRE", 1
        )

    @classmethod
    def create_service(cls):
        """Class Method for MetadataRepository service creation."""
        return cls()

    def refresh_settings(self, worker_settings: Optional[Dynaconf] = None):
        """Refreshes the MetadataRepository settings."""
        if worker_settings is None:
            settings = self._worker_settings
        else:
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
                f"Invalid Storage Backend {settings.STORAGE_BACKEND}. "
                f"Supported Storage Backends {', '.join(storage_backends)}"
            )
        else:
            settings.STORAGE_BACKEND = getattr(
                importlib.import_module(
                    "tuf_repository_service_worker.services"
                ),
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
                importlib.import_module(
                    "tuf_repository_service_worker.services"
                ),
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

        self._worker_settings = settings
        return settings

    def _load(self, role_name: str) -> Metadata:
        """
        Loads latest version of metadata for rolename using configured storage
        backend.

        NOTE: The storage backend is expected to translate rolenames to
        filenames and figure out the latest version.
        """
        return Metadata.from_file(role_name, None, self._storage_backend)

    def _sign(self, role: Metadata, role_name: str) -> None:
        """
        Re-signs metadata with role-specific key from global key store.

        The metadata role type is used as default key id. This is only allowed
        for top-level roles.
        """
        role.signatures.clear()
        for key in self._key_storage_backend.get(role_name):
            signer = SSlibSigner(key)
            role.sign(signer, append=True)

    def _persist(self, role: Metadata, role_name: str) -> None:
        """
        Persists metadata using the configured storage backend.

        The metadata role type is used as default role name. This is only
        allowed for top-level roles. All names but 'timestamp' are prefixed
        with a version number.
        """
        filename = f"{role_name}.json"
        if role_name != Timestamp.type:
            if filename.startswith(f"{role.signed.version}.") is False:
                filename = f"{role.signed.version}.{filename}"

        role.to_file(filename, JSONSerializer(), self._storage_backend)

    def _bump_expiry(self, role: Metadata, expiry_id: str) -> None:
        """
        Bumps metadata expiration date by role-specific interval.

        The metadata role type is used as default expiry id. This is only
        allowed for top-level roles.
        """
        role.signed.expires = datetime.now().replace(
            microsecond=0
        ) + timedelta(
            days=int(self._settings.get_fresh(f"{expiry_id}_EXPIRATION"))
        )

    def _bump_version(self, role: Metadata) -> None:
        """Bumps metadata version by 1."""
        role.signed.version += 1

    def _update_timestamp(self, snapshot_version: int) -> Metadata[Timestamp]:
        """
        Loads 'timestamp', updates meta info about passed 'snapshot'
        metadata, bumps version and expiration, signs and persists.
        """
        timestamp = self._load(Timestamp.type)
        timestamp.signed.snapshot_meta = MetaFile(version=snapshot_version)

        self._bump_version(timestamp)
        self._bump_expiry(timestamp, Timestamp.type)
        self._sign(timestamp, Timestamp.type)
        self._persist(timestamp, Timestamp.type)

        return timestamp

    def _update_snapshot(
        self, targets_meta: List[Tuple[str, int]]
    ) -> Metadata[Snapshot]:
        """
        Loads 'snapshot', updates meta info about passed 'targets' metadata,
        bumps version and expiration, signs and persists. Returns new snapshot
        version, e.g. to update 'timestamp'.
        """
        snapshot = self._load(Snapshot.type)

        for name, version in targets_meta:
            snapshot.signed.meta[f"{name}.json"] = MetaFile(version=version)

        self._bump_expiry(snapshot, Snapshot.type)
        self._bump_version(snapshot)
        self._sign(snapshot, Snapshot.type)
        self._persist(snapshot, Snapshot.type)

        return snapshot.signed.version

    def _get_path_succinct_role(self, target_path: str) -> str:
        bin_role = self._load(BIN)
        bin_succinct_roles = bin_role.signed.delegations.succinct_roles
        bins_name = bin_succinct_roles.get_role_for_target(target_path)

        return bins_name

    def _add_to_unpublished_metas(self, targets_meta: List[Tuple[str, int]]):
        """
        Add to the Redis "unpublished_meta" the edited roles.
        """
        logging.debug(f"Adding to unpublished meta {targets_meta}")
        if len(targets_meta) == 0:
            logging.info("Nothing to send to be published")
            return None

        with self._redis.lock("TUF_TARGETS_META"):
            if self._redis.exists("unpublished_metas"):
                targets_waiting_commmit = self._redis.get(
                    "unpublished_metas"
                ).decode("utf-8")
                for bins_name, _ in targets_meta:
                    if bins_name not in targets_waiting_commmit:
                        self._redis.append(
                            "unpublished_metas", f", {bins_name}"
                        )
            else:
                self._redis.set(
                    "unpublished_metas",
                    ", ".join(bins_name for bins_name, _ in targets_meta),
                )

    def _publish_meta_state(
        self, targets_meta: List[Tuple[str, int]], update_state: Optional[str]
    ) -> List[Optional[Tuple[str, int]]]:
        """
        Publish to the task the "PUBLISHING" state with details if the meta
        still not published in the latest Snapshot. It runs every 3 seconds.
        """
        logging.debug(f"waiting metas to be published {targets_meta}")

        def _update_state(targets_meta: List[Tuple[str, int]]):
            unpublised_roles = [
                f"{role} version {version}" for role, version in targets_meta
            ]

            update_state(
                state="PUBLISHING",
                meta={"unpublished_roles": unpublised_roles},
            )

        while True:
            snapshot = self._load(Roles.SNAPSHOT.value)
            for target_meta in targets_meta:
                snapshot_meta_file = snapshot.signed.meta[
                    f"{target_meta[0]}.json"
                ]
                if snapshot_meta_file.version == target_meta[1]:
                    logging.debug(f"Found published meta {target_meta}")
                    targets_meta.remove(target_meta)

            if len(targets_meta) > 0:
                _update_state(targets_meta)
                time.sleep(3)
            else:
                return None

    def add_initial_metadata(self, payload: Dict[str, Dict[str, Any]]) -> bool:
        warnings.warn(
            "Use bootstrap instead add_initial_metadata", DeprecationWarning
        )
        self.bootstrap(payload)

    def bootstrap(self, payload: Dict[str, Dict[str, Any]]) -> bool:
        """
        Bootstrap the Metadata Repository

        Add the online Keys to the Key Storage backend and the Signed Metadata
        to the Storage Backend.
        """
        # Store online keys to the Key Vault
        if settings := payload.get("settings"):
            self.store_online_keys(settings)
        else:
            raise (ValueError("No settings in the payload"))

        metadata = payload.get("metadata")
        if metadata is None:
            raise (ValueError("No metadata in the payload"))

        for role_name, data in metadata.items():
            metadata = Metadata.from_dict(data)
            metadata.to_file(
                f"{role_name}.json",
                JSONSerializer(),
                self._storage_backend,
            )
            logging.debug(f"{role_name}.json saved")

        return True

    def add_targets(self, payload: Dict[str, Any], update_state: str) -> None:
        """
        Updates 'bins' roles metadata, assigning each passed target to the
        correct bin.

        Assignment is based on the hash prefix of the target file path. All
        metadata is signed and persisted using the configured key and storage
        services.
        """
        targets = payload.get("targets")
        if targets is None:
            raise ValueError("No targets in the payload")

        with self._redis.lock("TUF_BINS_HASHED"):
            # Group target files by responsible 'bins' roles
            bin_target_groups: Dict[str, List[TargetFile]] = {}
            for target in targets:
                bins_name = self._get_path_succinct_role(target.get("path"))
                if bins_name not in bin_target_groups:
                    bin_target_groups[bins_name] = []

                target_file = TargetFile.from_dict(
                    target["info"], target["path"]
                )
                bin_target_groups[bins_name].append(target_file)

            # Update target file info in responsible 'bins' roles, bump
            # version and expiry and sign and persist
            targets_meta = []
            for bins_name, target_files in bin_target_groups.items():
                logging.debug(f"Adding targets to {bins_name}")
                bins_role = self._load(bins_name)
                for target_file in target_files:
                    bins_role.signed.targets[target_file.path] = target_file

                self._bump_expiry(bins_role, BINS)
                self._bump_version(bins_role)
                self._sign(bins_role, BINS)
                self._persist(bins_role, bins_name)

                targets_meta.append((bins_name, bins_role.signed.version))

        if len(targets_meta) > 0:
            self._add_to_unpublished_metas(targets_meta)
            self._publish_meta_state(targets_meta, update_state)

        result = ResultDetails(
            message="Task finished.",
            details={
                "targets": [target.get("path") for target in targets],
                "target_roles": [t_role for t_role in bin_target_groups],
            },
        )
        logging.debug(f"Added targets. {result}")
        return asdict(result)

    def remove_targets(
        self, payload: Dict[str, List[str]], update_state: str
    ) -> Dict[str, Any]:
        """
        Remove targets from the metadata roles.
        """
        targets = payload.get("targets")
        if targets is None:
            raise ValueError("No targets in the payload")

        if len(targets) == 0:
            raise IndexError("At list one target is required")

        deleted_targets: List[str] = []
        not_found_targets: List[str] = []

        # Group target files by responsible 'bins' roles.
        bin_target_groups: Dict[str, List[str]] = {}
        for target in targets:
            bins_name = self._get_path_succinct_role(target)
            if bins_name not in bin_target_groups:
                bin_target_groups[bins_name] = []

            bin_target_groups[bins_name].append(target)

        # Update target file info in responsible 'bins' roles, bump
        # version and expiry and sign and persist.
        targets_meta = []
        with self._redis.lock("TUF_BINS_HASHED"):
            for bins_name, paths in bin_target_groups.items():
                bins_role = self._load(bins_name)
                for path in paths:
                    if path in bins_role.signed.targets:
                        bins_role.signed.targets.pop(path)
                        deleted_targets.append(path)
                        self._bump_expiry(bins_role, BINS)
                        self._bump_version(bins_role)
                        self._sign(bins_role, BINS)
                        self._persist(bins_role, bins_name)
                        targets_meta.append(
                            (bins_name, bins_role.signed.version)
                        )

                    else:
                        not_found_targets.append(path)

        if len(targets_meta) > 0:
            self._add_to_unpublished_metas(targets_meta)
            self._publish_meta_state(targets_meta, update_state)

        result = ResultDetails(
            message="Task finished.",
            details={
                "deleted_targets": deleted_targets,
                "not_found_targets": not_found_targets,
            },
        )

        logging.debug(f"Delete targets. {result}")
        return asdict(result)

    def publish_targets_meta(self):
        """
        Publishes Targets metas.

        Add new Targets to the Snapshot Role, bump Snapshot Role and Timestamp
        Role.
        """
        with self._redis.lock("TUF_SNAPSHOT_TIMESTAMP"):
            unpublished_bins_names = self._redis.get("unpublished_metas")
            if unpublished_bins_names is None:
                logging.debug("No new unplublished targets meta, skipping.")
                return None

            snapshot = self._load(Snapshot.type)
            targets_meta = []
            bins_names = unpublished_bins_names.decode("utf-8").split(", ")
            for bins_name in bins_names:
                bins_role = self._load(bins_name)
                try:
                    bins_name_version = snapshot.signed.meta[
                        f"{bins_name}.json"
                    ]
                except KeyError:
                    bins_name_version = -1

                if bins_name_version != bins_role.signed.version:
                    targets_meta.append((bins_name, bins_role.signed.version))

            if len(targets_meta) != 0:
                self._update_timestamp(self._update_snapshot(targets_meta))
                self._redis.delete("unpublished_metas")
                logging.debug("Flushed unpublished targets meta")
            else:
                logging.info(
                    "[publish targets meta] Snapshot already up-to-date."
                )

    def bump_bins_roles(self) -> bool:
        """
        Bumps version and expiration date of 'bins' role metadata (multiple).

        The version numbers are incremented by one, the expiration dates are
        renewed using a configured expiration interval, and the metadata is
        signed and persisted using the configured key and storage services.

        Updating 'bins' also updates 'snapshot' and 'timestamp'.
        """
        try:
            bin = self._load(BIN)
        except StorageError:
            logging.error(f"{BIN} not found, not bumping.")
            return False

        bin_succinct_roles = bin.signed.delegations.succinct_roles
        targets_meta = []
        for bins_name in bin_succinct_roles.get_roles():
            bins_role = self._load(bins_name)

            if (bins_role.signed.expires - datetime.now()) < timedelta(
                hours=self._hours_before_expire
            ):
                self._bump_expiry(bins_role, BINS)
                self._bump_version(bins_role)
                self._sign(bins_role, BINS)
                self._persist(bins_role, bins_name)
                targets_meta.append((bins_name, bins_role.signed.version))

        if len(targets_meta) > 0:
            logging.info(
                "[scheduled bins bump] BINS roles version bumped: "
                f"{targets_meta}"
            )
            timestamp = self._update_timestamp(
                self._update_snapshot(targets_meta)
            )
            logging.info(
                "[scheduled bins bump] Snapshot version bumped: "
                f"{timestamp.signed.snapshot_meta.version}"
            )
            logging.info(
                "[scheduled bins bump] Timestamp version bumped: "
                f"{timestamp.signed.version} new expire "
                f"{timestamp.signed.expires}"
            )
        else:
            logging.debug(
                "[scheduled bins bump] All more than "
                f"{self._hours_before_expire} hour(s) to expire, "
                "skipping"
            )

        return True

    def bump_snapshot(self) -> bool:
        """
        Bumps version and expiration date of TUF 'snapshot' role metadata.

        The version number is incremented by one, the expiration date renewed
        using a configured expiration interval, and the metadata is signed and
        persisted using the configured key and storage services.

        Updating 'snapshot' also updates 'timestamp'.
        """

        try:
            snapshot = self._load(Snapshot.type)
        except StorageError:
            logging.error(f"{Snapshot.type} not found, not bumping.")
            return False

        if (snapshot.signed.expires - datetime.now()) < timedelta(
            hours=self._hours_before_expire
        ):
            timestamp = self._update_timestamp(self._update_snapshot([]))
            logging.info(
                "[scheduled snapshot bump] Snapshot version bumped: "
                f"{snapshot.signed.version + 1}"
            )
            logging.info(
                "[scheduled snapshot bump] Timestamp version bumped: "
                f"{timestamp.signed.version}, new expire "
                f"{timestamp.signed.expires}"
            )

        else:
            logging.debug(
                f"[scheduled snapshot bump] Expires "
                f"{snapshot.signed.expires}. More than "
                f"{self._hours_before_expire} hour, skipping"
            )

        return True

    def bump_online_roles(self) -> bool:
        """Bump online Roles (Snapshot, Timestamp, BINS)."""
        with self._redis.lock("TUF_SNAPSHOT_TIMESTAMP"):
            if self._settings.get_fresh("BOOTSTRAP") is None:
                logging.info(
                    "[automatic_version_bump] No bootstrap, skipping..."
                )
                return False

            self.bump_snapshot()
            self.bump_bins_roles()

            return True

    def store_online_keys(
        self,
        roles_config: Dict[str, Any],
    ) -> bool:
        """Store online keys in the Key Vault Backend."""
        if role_settings := roles_config.get("roles"):
            for rolename, items in role_settings.items():
                # store keys in Key Vault
                if keys := items.get("keys"):
                    self._key_storage_backend.put(rolename, keys.values())
        else:
            return False

        return True
