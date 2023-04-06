# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import enum
import importlib
import logging
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from math import log
from typing import Any, Dict, List, Optional, Tuple

import redis
from celery.app.task import Task
from celery.exceptions import ChordError
from celery.result import AsyncResult, states
from securesystemslib.exceptions import StorageError  # type: ignore
from tuf.api.metadata import (  # noqa
    SPECIFICATION_VERSION,
    Delegations,
    Key,
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    SuccinctRoles,
    TargetFile,
    Targets,
    Timestamp,
)
from tuf.api.serialization.json import JSONSerializer

# the 'service import is used to retrieve sublcasses (Implemented Services)
from repository_service_tuf_worker import (  # noqa
    Dynaconf,
    get_repository_settings,
    get_worker_settings,
    services,
)
from repository_service_tuf_worker.interfaces import IKeyVault, IStorage
from repository_service_tuf_worker.models import (
    rstuf_db,
    targets_crud,
    targets_models,
    targets_schema,
)


class Roles(enum.Enum):
    ROOT = Root.type
    TARGETS = Targets.type
    SNAPSHOT = Snapshot.type
    TIMESTAMP = Timestamp.type
    BINS = "bins"


ALL_REPOSITORY_ROLES_NAMES = [rolename.value for rolename in Roles]
OFFLINE_KEYS = {
    Roles.ROOT.value.upper(),
    Roles.TARGETS.value.upper(),
}

BINS = "bins"
SPEC_VERSION: str = ".".join(SPECIFICATION_VERSION)


@dataclass
class ResultDetails:
    status: str
    details: Optional[Dict[str, Any]]
    last_update: datetime


class MetadataRepository:
    """
    A repository service to create and maintain TUF role metadata.
    """

    def __init__(self):
        self._worker_settings: Dynaconf = get_worker_settings()
        self._settings: Dynaconf = get_repository_settings()
        self._storage_backend: IStorage = self.refresh_settings().STORAGE
        self._key_storage_backend: IKeyVault = self.refresh_settings().KEYVAULT
        self._db = self.refresh_settings().SQL
        self._redis = redis.StrictRedis.from_url(
            self._worker_settings.REDIS_SERVER
        )
        self._hours_before_expire: int = self._settings.get_fresh(
            "HOURS_BEFORE_EXPIRE", 1
        )

    @classmethod
    def create_service(cls) -> "MetadataRepository":
        """Class Method for MetadataRepository service creation."""
        return cls()

    def refresh_settings(self, worker_settings: Optional[Dynaconf] = None):
        """Refreshes the MetadataRepository settings."""
        if worker_settings is None:
            settings = self._worker_settings
        else:
            settings = worker_settings

        # SQL
        settings.SQL = rstuf_db(self._worker_settings.SQL_SERVER)

        # Backends
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
                    "repository_service_tuf_worker.services"
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

            storage_kwargs: Dict[str, Any] = {}
            for s in settings.STORAGE_BACKEND.settings():
                if settings.store.get(s.name) is None:
                    settings.store[s.name] = s.default

                storage_kwargs[s.argument] = settings.store[s.name]

            settings.STORAGE_BACKEND.configure(settings)
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
                    "repository_service_tuf_worker.services"
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

            keyvault_kwargs: Dict[str, Any] = {}
            for s in settings.KEYVAULT_BACKEND.settings():
                if settings.store.get(s.name) is None:
                    settings.store[s.name] = s.default

                keyvault_kwargs[s.argument] = settings.store[s.name]

            settings.KEYVAULT_BACKEND.configure(settings)
            settings.KEYVAULT = settings.KEYVAULT_BACKEND(**keyvault_kwargs)

        self._worker_settings = settings
        return settings

    def _sign(self, role: Metadata) -> None:
        """
        Re-signs metadata with role-specific key from global key store.

        The metadata role type is used as default key id. This is only allowed
        for top-level roles.
        """
        role.signatures.clear()
        root: Metadata[Root] = self._storage_backend.get("root")
        # All roles except root share the same one key and it doesn't matter
        # from which role we will get the key.
        keyid: str = root.signed.roles["timestamp"].keyids[0]
        public_key = root.signed.keys[keyid]
        signer = self._key_storage_backend.get(public_key)
        role.sign(signer, append=True)

    def _persist(self, role: Metadata, role_name: str) -> str:
        """
        Persists metadata using the configured storage backend.

        The metadata role type is used as default role name. This is only
        allowed for top-level roles. All names but 'timestamp' are prefixed
        with a version number.
        """
        filename = f"{role_name}.json"
        if role_name != Timestamp.type:
            if filename[0].isdigit() is False:
                filename = f"{role.signed.version}.{filename}"

        bytes_data = role.to_bytes(JSONSerializer())
        self._storage_backend.put(bytes_data, filename)
        logging.debug(f"{filename} saved")
        return filename

    def _bump_expiry(self, role: Metadata, role_name: str) -> None:
        """
        Bumps metadata expiration date by role-specific interval.
        """
        role.signed.expires = datetime.now().replace(
            microsecond=0
        ) + timedelta(
            days=int(
                self._settings.get_fresh(f"{role_name.upper()}_EXPIRATION")
            )
        )

    def _bump_version(self, role: Metadata) -> None:
        """Bumps metadata version by 1."""
        role.signed.version += 1

    def _update_timestamp(
        self,
        snapshot_version: int,
        db_targets: Optional[List[str]] = None,
    ) -> Metadata[Timestamp]:
        """
        Loads 'timestamp', updates meta info about passed 'snapshot'
        metadata, bumps version and expiration, signs and persists.

        Args:
            snapshot_version: snapshot version to add to new timestamp.
            db_targets: RSTUFTarget DB objects will be changed as published in
                the DB SQL.
        """
        timestamp = self._storage_backend.get(Timestamp.type)
        timestamp.signed.snapshot_meta = MetaFile(version=snapshot_version)

        self._bump_version(timestamp)
        self._bump_expiry(timestamp, Timestamp.type)
        self._sign(timestamp)
        self._persist(timestamp, Timestamp.type)

        # TODO review if here is the best place to change the status in DB
        if db_targets:
            targets_crud.update_to_published(self._db, db_targets)

        return timestamp

    def _update_snapshot(
        self, targets_meta: List[Tuple[str, int]]
    ) -> Metadata[Snapshot]:
        """
        Loads 'snapshot', updates meta info about passed 'targets' metadata,
        bumps version and expiration, signs and persists. Returns new snapshot
        version, e.g. to update 'timestamp'.
        """
        snapshot = self._storage_backend.get(Snapshot.type)

        for name, version in targets_meta:
            snapshot.signed.meta[f"{name}.json"] = MetaFile(version=version)

        self._bump_expiry(snapshot, Snapshot.type)
        self._bump_version(snapshot)
        self._sign(snapshot)
        self._persist(snapshot, Snapshot.type)

        return snapshot.signed.version

    def _get_path_succinct_role(self, target_path: str) -> str:
        """
        Return role name by target file path
        """
        bin_role: Metadata[Targets] = self._storage_backend.get(Targets.type)
        bin_succinct_roles = bin_role.signed.delegations.succinct_roles
        bins_name = bin_succinct_roles.get_role_for_target(target_path)

        return bins_name

    def _update_task(
        self,
        bin_targets: Dict[str, List[targets_models.RSTUFTargets]],
        update_state: Task.update_state,
        subtask: Optional[AsyncResult] = None,
    ):
        """
        Updates the 'RUNNING' state with details if the meta still not
        published in the latest Snapshot. It runs every 3 seconds until the
        task is finished.
        """
        logging.debug(f"Waiting roles to be published {list(bin_targets)}")

        def _update_state(
            state: states,
            bin_targets: Dict[str, List[targets_models.RSTUFTargets]],
            completed_roles: List[str],
            exc_type: Optional[str] = None,
            exc_message: Optional[List[str]] = None,
        ):
            update_state(
                state=state,
                meta={
                    "published_roles": completed_roles,
                    "roles_to_publish": f"{list(bin_targets.keys())}",
                    "status": "Publishing",
                    "last_update": datetime.now(),
                    "exc_type": exc_type,
                    "exc_message": exc_message,
                },
            )

        while True:
            completed_roles: List[str] = []
            for role_name, targets in bin_targets.items():
                for target in targets:
                    self._db.refresh(target)
                    if target.published is True:
                        targets.remove(target)

                if len(targets) == 0:
                    logging.debug(f"Update: {role_name} completed")
                    completed_roles.append(role_name)
            if subtask is not None and subtask.status == states.FAILURE:
                exc_type = subtask.result.__class__.__name__
                exc_message = list(subtask.result.args)
                _update_state(
                    states.FAILURE,
                    bin_targets,
                    completed_roles,
                    exc_type=exc_type,
                    exc_message=exc_message,
                )
                raise ChordError(
                    f"Failed to execute {subtask.task_id}: "
                    f"{exc_type} {exc_message}"
                )

            if sorted(completed_roles) != sorted(list(bin_targets)):
                _update_state("RUNNING", bin_targets, completed_roles)
                time.sleep(3)
            else:
                break

    def _send_publish_targets_task(self, task_id: str):  # pragma: no cover
        """
        Send a new task to the `rstuf_internals` queue to publish targets.
        """
        # it is imported in the call to avoid a circular import
        from app import repository_service_tuf_worker

        # TODO: all tasks has the same id `publish_targets`. Should be unique?
        # Should we check and avoid multiple tasks? Check that the function
        # `publish_target` has a lock to avoid race conditions.
        return repository_service_tuf_worker.apply_async(
            kwargs={
                "action": "publish_targets",
                "payload": None,
                "refresh_settings": False,
            },
            task_id=f"publish_targets-{task_id}",
            queue="rstuf_internals",
            acks_late=True,
        )

    def bootstrap(
        self,
        payload: Dict[str, Dict[str, Any]],
        update_state: Optional[
            Task.update_state
        ] = None,  # It is required (see: app.py)
    ) -> Dict[str, Any]:
        """
        Bootstrap the Metadata Repository
        """
        tuf_settings = payload.get("settings")
        if tuf_settings is None:
            raise KeyError("No 'settings' in the payload")

        root_metadata = payload.get("metadata")
        if root_metadata is None:
            raise KeyError("No 'metadata' in the payload")

        # Saves the `Root` metadata in the backend storage service and returns
        # the online public key (it uses the `Timestamp` key as reference)
        root: Metadata[Root] = Metadata.from_dict(root_metadata[Root.type])
        self._persist(root, Root.type)
        _keyid: str = root.signed.roles[Timestamp.type].keyids[0]
        public_key = root.signed.keys[_keyid]

        # Top level roles (`Targets`, `Timestamp``, `Snapshot`) initialization
        targets: Metadata[Targets] = Metadata(Targets())
        snapshot: Metadata[Snapshot] = Metadata(Snapshot())
        timestamp: Metadata[Timestamp] = Metadata(Timestamp())

        # Calculate the bit length (Number of bits between 1 and 32)
        bit_length = int(
            log(tuf_settings["services"]["number_of_delegated_bins"], 2)
        )
        # Succinct delegated roles (`bins`)
        succinct_roles = SuccinctRoles([], 1, bit_length, BINS)
        targets.signed.delegations = Delegations(
            keys={}, succinct_roles=succinct_roles
        )
        # Initialize all succinct delegated roles (`bins`), update expire,
        # sign, add to `Snapshot` meta and persist in the backend storage
        # service.
        for delegated_name in succinct_roles.get_roles():
            targets.signed.add_key(
                Key.from_securesystemslib_key(
                    self._key_storage_backend.get(public_key).key_dict
                ),
                delegated_name,
            )
            bins_role = Metadata(Targets())
            self._bump_expiry(bins_role, BINS)
            self._sign(bins_role)
            snapshot.signed.meta[f"{delegated_name}.json"] = MetaFile(
                version=bins_role.signed.version
            )
            self._persist(bins_role, delegated_name)

        # Update `Snapshot` meta with targets
        snapshot.signed.meta[f"{Targets.type}.json"] = MetaFile(
            version=targets.signed.version
        )

        # Update expire, sign and persist the top level roles (`Targets`,
        # `Timestamp``, `Snapshot`) in the backend storage service.
        for role in [targets, snapshot, timestamp]:
            self._bump_expiry(role, role.signed.type)
            self._sign(role)
            self._persist(role, role.signed.type)

        result = ResultDetails(
            status="Task finished.",
            details={
                "bootstrap": True,
            },
            last_update=datetime.now(),
        )

        return asdict(result)

    def publish_targets(self):
        """
        Publish targets from SQL DB as persistent TUF Metadata in the backend
        storage.
        """

        # lock to avoid race conditions
        with self._redis.lock("publish_targets", timeout=5.0):
            # get all delegated role names with unpublished targets
            unpublished_roles = targets_crud.read_unpublished_rolenames(
                self._db
            )

            if len(unpublished_roles) == 0:
                logging.debug("No new targets in delegated roles. Finishing")
                return None

            # initialize the new snapshot targets meta and published targets
            # from DB SQL
            new_snapshot_meta: List[Tuple(str, int)] = []
            db_published_targets: List[str] = []
            for _, rolename in unpublished_roles:
                # get the unpublished targets for the delegated, it will be use
                # to update the database when Snapshot and Timestamp is
                # published by `_update_timestamp`
                db_targets = targets_crud.read_unpublished_by_rolename(
                    db=self._db, rolename=rolename
                )
                logging.debug(f"{rolename}: New targets #: {len(db_targets)}")
                db_published_targets += [target.path for target in db_targets]

                # load the delegated targets role, clean the targets and add
                # a new meta from the SQL DB.
                # note: it might include targets from another parent task, it
                # will speed up the process of publishing new targets.
                role: Metadata[Targets] = self._storage_backend.get(rolename)
                role.signed.targets.clear()
                role.signed.targets = {
                    target[0]: TargetFile.from_dict(target[1], target[0])
                    for target in targets_crud.read_all_add_by_rolename(
                        self._db, rolename
                    )
                }

                # update expiry, bump version and persist to the storage
                self._bump_expiry(role, BINS)
                self._bump_version(role)
                self._sign(role)
                self._persist(role, rolename)
                # append to the new snapshot targets meta
                new_snapshot_meta.append((rolename, role.signed.version))

            # update snapshot and timestamp
            # note: the `db_published_targets` contains the targets that
            # needs to updated in SQL DB as 'published' and it will be done
            # by the `_update_timestamp`
            self._update_timestamp(
                self._update_snapshot(new_snapshot_meta),
                db_published_targets,
            )

    def add_targets(
        self, payload: Dict[str, Any], update_state: Task.update_state
    ) -> Optional[Dict[str, Any]]:
        """
        Add or update the new target in the SQL DB and submit the task for
        `update_targets`

        Check the target(s) in the SQL DB; if it doesn't exist, create a new
        entry or update it as not published.
        After changing the SQL DB submit a new `publish_target` task.
        This function will wait until all the targets are published.
        """
        targets = payload.get("targets")
        if targets is None:
            raise ValueError("No targets in the payload")

        # The task id will be used by `_send_publish_targets_task` (sub-task).
        task_id = payload.get("task_id")
        # Group target files by responsible 'bins' delegated roles.
        # This will be used to by `_update_task` for updating task status.
        bin_targets: Dict[str, List[targets_models.RSTUFTargets]] = {}
        for target in targets:
            bins_name = self._get_path_succinct_role(target["path"])
            db_target = targets_crud.read_by_path(self._db, target.get("path"))
            if db_target is None:
                db_target = targets_crud.create(
                    self._db,
                    targets_schema.TargetsCreate(
                        path=target.get("path"),
                        info=target.get("info"),
                        published=False,
                        action=targets_schema.TargetAction.ADD,
                        rolename=bins_name,
                    ),
                )
            else:
                db_target = targets_crud.update(
                    self._db,
                    db_target,
                    target.get("path"),
                    target.get("info"),
                )

            if bins_name not in bin_targets:
                bin_targets[bins_name] = []

            bin_targets[bins_name].append(db_target)

        # If publish_targets doesn't exists it will be True by default.
        publish_targets = payload.get("publish_targets", True)
        subtask = None
        if publish_targets is True:
            subtask = self._send_publish_targets_task(task_id)

        self._update_task(bin_targets, update_state, subtask)

        result = ResultDetails(
            status="Task finished.",
            details={
                "targets": [target.get("path") for target in targets],
                "target_roles": [t_role for t_role in bin_targets],
            },
            last_update=datetime.now(),
        )
        logging.debug(f"Added targets. {result}")

        return asdict(result)

    def remove_targets(
        self, payload: Dict[str, Any], update_state: Task.update_state
    ) -> Dict[str, Any]:
        """
        Remove targets from the metadata roles.
        """
        targets = payload.get("targets")
        if targets is None:
            raise ValueError("No targets in the payload")
        task_id = payload.get("task_id")

        if len(targets) == 0:
            raise IndexError("At list one target is required")

        deleted_targets: List[str] = []
        not_found_targets: List[str] = []

        # Group target files by responsible 'bins' delegated roles.
        # This will be used to by `publish_targets`
        bin_targets: Dict[str, List[targets_models.RSTUFTargets]] = {}
        for target in targets:
            bins_name = self._get_path_succinct_role(target)
            db_target = targets_crud.read_by_path(self._db, target)
            if db_target is None or (
                db_target.action == targets_schema.TargetAction.REMOVE
                and db_target.published is True
            ):
                # not found targets or targets already remove action and
                # published are not found.
                not_found_targets.append(target)
            else:
                db_target = targets_crud.update_action_remove(
                    self._db, db_target
                )
                deleted_targets.append(target)

                if bins_name not in bin_targets:
                    bin_targets[bins_name] = []

                bin_targets[bins_name].append(db_target)
        # If publish_targets doesn't exists it will be True by default.
        publish_targets = payload.get("publish_targets", True)
        subtask = None
        if len(deleted_targets) > 0 and publish_targets is True:
            subtask = self._send_publish_targets_task(task_id)

        self._update_task(bin_targets, update_state, subtask)

        result = ResultDetails(
            status="Task finished.",
            details={
                "deleted_targets": deleted_targets,
                "not_found_targets": not_found_targets,
            },
            last_update=datetime.now(),
        )

        logging.debug(f"Delete targets. {result}")
        return asdict(result)

    def bump_bins_roles(self) -> bool:
        """
        Bumps version and expiration date of 'bins' role metadata (multiple).

        The version numbers are incremented by one, the expiration dates are
        renewed using a configured expiration interval, and the metadata is
        signed and persisted using the configured key and storage services.

        Updating 'bins' also updates 'snapshot' and 'timestamp'.
        """
        try:
            targets = self._storage_backend.get(Targets.type)
        except StorageError:
            logging.error(f"{Targets.type} not found, not bumping.")
            return False

        targets_succinct_roles = targets.signed.delegations.succinct_roles
        targets_meta = []
        for bins_name in targets_succinct_roles.get_roles():
            bins_role: Metadata[Targets] = self._storage_backend.get(bins_name)

            if (bins_role.signed.expires - datetime.now()) < timedelta(
                hours=self._hours_before_expire
            ):
                self._bump_expiry(bins_role, BINS)
                self._bump_version(bins_role)
                self._sign(bins_role)
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
            snapshot = self._storage_backend.get(Snapshot.type)
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
