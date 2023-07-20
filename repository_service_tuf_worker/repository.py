# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import enum
import importlib
import logging
import time
import warnings
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from math import log
from typing import Any, Dict, List, Literal, Optional

import redis
from celery.app.task import Task
from celery.exceptions import ChordError
from celery.result import AsyncResult, states
from dynaconf.loaders import redis_loader
from securesystemslib.exceptions import StorageError  # type: ignore
from securesystemslib.signer import SSlibKey
from tuf.api.exceptions import BadVersionNumberError, RepositoryError
from tuf.api.metadata import (  # noqa
    SPECIFICATION_VERSION,
    Delegations,
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

# lock constants
LOCK_TARGETS = "LOCK_TARGETS"


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
        self._storage_backend: IStorage = self.refresh_settings().STORAGE
        self._key_storage_backend: IKeyVault = self.refresh_settings().KEYVAULT
        self._db = self.refresh_settings().SQL
        self._redis = redis.StrictRedis.from_url(
            self._worker_settings.REDIS_SERVER
        )
        self._hours_before_expire: int = self._settings.get_fresh(
            "HOURS_BEFORE_EXPIRE", 1
        )
        self._timeout = int(self.refresh_settings().get("LOCK_TIMEOUT", 60.0))

    @property
    def _settings(self) -> Dynaconf:
        return get_repository_settings()

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
        #
        # SQL
        #
        sql_server_url = self._worker_settings.get("SQL_SERVER")
        # clean 'postgresql://' if present
        sql_server = sql_server_url.replace("postgresql://", "")
        if sql_user := self._worker_settings.get("SQL_USER"):
            if self._worker_settings.SQL_PASSWORD.startswith("/run/secrets"):
                try:
                    with open(self._worker_settings.SQL_PASSWORD) as f:
                        sql_password = f.read().rstrip("\n")
                except OSError as err:
                    logging.error(str(err))
                    raise err
            else:
                sql_password = self._worker_settings.SQL_PASSWORD
            settings.SQL = rstuf_db(
                f"postgresql://{sql_user}:{sql_password}@{sql_server}"
            )
        else:
            settings.SQL = rstuf_db(f"postgresql://{sql_server}")

        #
        # Backends
        #
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

    def write_repository_settings(self, key: str, value: Any):
        """
        Writes repository settings.

        Repository settings are stored in a dictionary like Dynaconf object
        and each of them has its own key and value.
        Additionally, repository settings are persisted in the Redis server
        so that they can be reused by multiple RSTUF Worker instances.

        Args:
            key: key name
            value: value for the key
        """
        settings_data = self._settings.as_dict(env=self._settings.current_env)
        settings_data[key] = value
        redis_loader.write(self._settings, settings_data)

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

    def _bump_and_persist(
        self, role: Metadata, role_name: str, persist: Optional[bool] = True
    ):
        """
        Bump expiry and version, sign and persist 'role' metadata into a new
        file named VERSION.rolename.json where VERSION is the new role version.
        Optionally, if persist is false, then don't persist in a file.
        """
        self._bump_expiry(role, role_name)
        self._bump_version(role)
        self._sign(role)
        if persist:
            self._persist(role, role_name)

    def _update_timestamp(self, snapshot_version: int) -> Metadata[Timestamp]:
        """
        Loads 'timestamp', updates meta info about passed 'snapshot'
        metadata, bumps version and expiration, signs and persists.

        Args:
            snapshot_version: snapshot version to add to new timestamp.
            db_targets: RSTUFTarget DB objects will be changed as published in
                the DB SQL.
        """
        timestamp: Metadata[Timestamp] = self._storage_backend.get(
            Timestamp.type, None
        )
        timestamp.signed.snapshot_meta = MetaFile(version=snapshot_version)

        self._bump_and_persist(timestamp, Timestamp.type)

        return timestamp

    def _update_snapshot(
        self,
        target_roles: Optional[List[str]] = None,
        bump_all: Optional[bool] = False,
    ) -> int:
        """
        Loads 'snapshot', updates meta info when 'target_roles' role names are
        given, bumps version and expiration, signs and persists.
        Returns the new snapshot version.

        Args:
            bump_all: Wheter to bump all bin target roles.
        """
        snapshot: Metadata[Snapshot] = self._storage_backend.get(Snapshot.type)

        if target_roles:
            db_target_roles: List[targets_models.RSTUFTargetRoles] = []
            if bump_all:
                db_target_roles = targets_crud.read_all_roles(self._db)
                for db_role in db_target_roles:
                    bins_md: Metadata[Targets] = self._storage_backend.get(
                        db_role.rolename
                    )
                    # update expiry, bump version and persist to the storage
                    self._bump_and_persist(bins_md, BINS, persist=False)
                    self._persist(bins_md, db_role.rolename)

            else:
                db_target_roles = targets_crud.read_roles_joint_files(
                    self._db, target_roles
                )

                for db_role in db_target_roles:
                    rolename = db_role.rolename
                    bins_md: Metadata[Targets] = self._storage_backend.get(
                        rolename
                    )
                    bins_md.signed.targets.clear()
                    bins_md.signed.targets = {
                        file.path: TargetFile.from_dict(file.info, file.path)
                        for file in db_role.target_files
                        if file.action == targets_schema.TargetAction.ADD
                        # Filtering the files with action 'ADD' cannot be done
                        # in CRUD. If a target role doesn't have any target
                        # files with an action 'ADD' (only 'REMOVE') then using
                        # CRUD will not return the target role and it won't be
                        # updated. An example can be when there is a role with
                        # one target file with action "REMOVE" and the CRUD
                        # will return None for this specific role.
                    }

                    # update expiry, bump version and persist to the storage
                    self._bump_and_persist(bins_md, BINS, persist=False)
                    self._persist(bins_md, rolename)
                    # update targetfile in db
                    # note: It update only if is not published see the CRUD.
                    targets_crud.update_files_to_published(
                        self._db, [file.path for file in db_role.target_files]
                    )

                    snapshot.signed.meta[f"{rolename}.json"] = MetaFile(
                        version=bins_md.signed.version
                    )

            targets_crud.update_roles_version(
                self._db, [int(db_role.id) for db_role in db_target_roles]
            )

        # update expiry, bump version and persist to the storage
        self._bump_and_persist(snapshot, Snapshot.type)

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
        bin_targets: Dict[str, List[targets_models.RSTUFTargetFiles]],
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
            bin_targets: Dict[str, List[targets_models.RSTUFTargetFiles]],
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

    def _send_publish_targets_task(
        self, task_id: str, bins_targets: Optional[List[str]]
    ):  # pragma: no cover
        """
        Send a new task to the `rstuf_internals` queue to publish targets.
        """
        # it is imported in the call to avoid a circular import
        from app import repository_service_tuf_worker

        return repository_service_tuf_worker.apply_async(
            kwargs={
                "action": "publish_targets",
                "payload": {"bin_targets": bins_targets},
                "refresh_settings": False,
            },
            task_id=f"publish_targets-{task_id}",
            queue="rstuf_internals",
            acks_late=True,
        )

    def save_settings(self, root: Metadata[Root], settings: Dict[str, Any]):
        """
        Save settings to the repository settings.

        Args:
            root: Root metadata
            settings: payload settings
        """
        logging.info("Saving settings")
        for role in Roles:
            rolename = role.value.upper()
            threshold = 1
            num_of_keys = 1
            if rolename == Roles.ROOT.value.upper():
                # get treshold and number of keys from given root metadata
                threshold = root.signed.roles[role.value].threshold
                num_of_keys = len(root.signatures)

            self.write_repository_settings(
                f"{rolename}_EXPIRATION",
                settings["expiration"][role.value],
            )
            self.write_repository_settings(f"{rolename}_THRESHOLD", threshold)
            self.write_repository_settings(f"{rolename}_NUM_KEYS", num_of_keys)

        self.write_repository_settings(
            "NUMBER_OF_DELEGATED_BINS",
            settings["services"]["number_of_delegated_bins"],
        )

        self.write_repository_settings(
            "TARGETS_BASE_URL", settings["services"]["targets_base_url"]
        )

        self.write_repository_settings(
            "TARGETS_ONLINE_KEY", settings["services"]["targets_online_key"]
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

        # save settings
        self.save_settings(root, tuf_settings)

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
                SSlibKey.from_securesystemslib_key(
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

        # Create all Target Roles in the database RSTUFTargetRoles
        db_target_roles = [
            targets_schema.RSTUFTargetRoleCreate(
                rolename=target_role, version=1
            )
            for target_role in succinct_roles.get_roles()
        ]
        targets_crud.create_roles(self._db, db_target_roles)

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

        self.write_repository_settings("BOOTSTRAP", payload["task_id"])
        logging.info(f"Bootstrap locked with id {payload['task_id']}")

        return asdict(result)

    def publish_targets(
        self,
        payload: Optional[Dict[str, Any]] = None,
        update_state: Optional[
            Task.update_state
        ] = None,  # It is required (see: app.py)
    ):
        """
        Publish targets as persistent TUF Metadata in the backend storage,
        updating Snapshot and Timestamp.
        """
        logging.debug(f"Configured timeout: {self._timeout}")
        lock_status_targets = False
        # Lock to avoid race conditions. See `LOCK_TIMEOUT` in the Worker guide
        # documentation.
        try:
            with self._redis.lock(LOCK_TARGETS, timeout=self._timeout):
                # get all delegated role names with unpublished targets
                if payload is None or payload.get("bins_targets") is None:
                    db_roles = targets_crud.read_roles_with_unpublished_files(
                        self._db
                    )
                    if db_roles is None:
                        bins_targets = []
                    else:
                        bins_targets = [bins_role[0] for bins_role in db_roles]

                if len(bins_targets) == 0:
                    logging.debug(
                        "No new targets in delegated target roles. Finishing"
                    )
                    return asdict(
                        ResultDetails(
                            states.SUCCESS,
                            details={
                                "target_roles": "Not new targets found.",
                            },
                            last_update=datetime.now(),
                        )
                    )

                self._update_timestamp(
                    self._update_snapshot(bins_targets),
                )

            # context lock finished
            lock_status_targets = True

        except redis.exceptions.LockNotOwnedError:
            # The LockNotOwnedError happens when the task exceeds the timeout,
            # and another task owns the lock.
            # If the task time out, the lock is released. If it doesn't finish
            # properly, it will raise (fail) the task. Otherwise, the ignores
            # the error because another task didn't lock it.
            if lock_status_targets is False:
                logging.error("The task to publish targets exceeded timeout")
                raise redis.exceptions.LockError(
                    "RSTUF: Task exceed `LOCK_TIMEOUT` "
                    f"({self._timeout} seconds)"
                )

        result = ResultDetails(
            states.SUCCESS,
            details={
                "target_roles": bins_targets,
            },
            last_update=datetime.now(),
        )
        logging.debug("Targets published.")
        return asdict(result)

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
        bin_targets: Dict[str, List[targets_models.RSTUFTargetFiles]] = {}
        for target in targets:
            bins_name = self._get_path_succinct_role(target["path"])
            db_target_file = targets_crud.read_file_by_path(
                self._db, target.get("path")
            )
            if db_target_file is None:
                db_target_file = targets_crud.create_file(
                    self._db,
                    targets_schema.RSTUFTargetFileCreate(
                        path=target.get("path"),
                        info=target.get("info"),
                        published=False,
                        action=targets_schema.TargetAction.ADD,
                    ),
                    target_role=targets_crud.read_role_by_rolename(
                        self._db, bins_name
                    ),
                )
            else:
                db_target_file = targets_crud.update_file_path_and_info(
                    self._db,
                    db_target_file,
                    target.get("path"),
                    target.get("info"),
                )

            if bins_name not in bin_targets:
                bin_targets[bins_name] = []

            bin_targets[bins_name].append(db_target_file)

        # If publish_targets doesn't exists it will be True by default.
        publish_targets = payload.get("publish_targets", True)
        subtask = None
        if publish_targets is True:
            subtask = self._send_publish_targets_task(
                task_id, [bins_role for bins_role in bin_targets]
            )

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
        bin_targets: Dict[str, List[targets_models.RSTUFTargetFiles]] = {}
        for target in targets:
            bins_name = self._get_path_succinct_role(target)
            db_target = targets_crud.read_file_by_path(self._db, target)
            if db_target is None or (
                db_target.action == targets_schema.TargetAction.REMOVE
                and db_target.published is True
            ):
                # not found targets or targets already remove action and
                # published are not found.
                not_found_targets.append(target)
            else:
                db_target = targets_crud.update_file_action_to_remove(
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
            subtask = self._send_publish_targets_task(
                task_id, [t_role for t_role in bin_targets]
            )

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

    def _run_online_roles_bump(self, force: Optional[bool] = False) -> bool:
        """
        Bumps version and expiration date of all online roles (`Targets`,
        `Succinct Delegated` targets roles, `Timestamp` and `Snapshot`).

        ** It might require a lock context to avoid race conditions **

        The version numbers are incremented by one, the expiration dates are
        renewed using a configured expiration interval, and the metadata is
        signed and persisted using the configured key and storage services.

        Args:
            force: force target roles bump if they don't match the hours before
                expire (`self._hours_before_expire`)
        """
        targets_roles: List[str] = []

        try:
            targets = self._storage_backend.get(Targets.type)
        except StorageError:
            logging.error(f"{Targets.type} not found, not bumping.")
            return False

        if self._settings.get_fresh("TARGETS_ONLINE_KEY") is None:
            logging.critical("No configuration found for TARGETS_ONLINE_KEY")

        elif self._settings.get_fresh("TARGETS_ONLINE_KEY") is False:
            logging.warning(
                f"{Targets.type} don't use online key, skipping 'Targets' role"
            )

        else:
            if (targets.signed.expires - datetime.now()) < timedelta(
                hours=self._hours_before_expire
            ):
                self._bump_and_persist(targets, Targets.type)
                targets_roles.append(Targets.type)

        targets_succinct_roles = targets.signed.delegations.succinct_roles
        for bins_name in targets_succinct_roles.get_roles():
            bins_role: Metadata[Targets] = self._storage_backend.get(bins_name)

            if (bins_role.signed.expires - datetime.now()) < timedelta(
                hours=self._hours_before_expire or force is True
            ):
                targets_roles.append(bins_name)

        if len(targets_roles) > 0:
            logging.info(
                "[scheduled targets bump] Targets and delegated Targets roles "
                "version bumped: {targets_meta}"
            )
            timestamp = self._update_timestamp(
                self._update_snapshot(targets_roles, bump_all=True)
            )
            logging.info(
                "[scheduled targets bump] Snapshot version bumped: "
                f"{timestamp.signed.snapshot_meta.version}"
            )
            logging.info(
                "[scheduled targets bump] Timestamp version bumped: "
                f"{timestamp.signed.version} new expire "
                f"{timestamp.signed.expires}"
            )
        else:
            logging.debug(
                "[scheduled targets bump] All more than "
                f"{self._hours_before_expire} hour(s) to expire, "
                "skipping"
            )

        return True

    def bump_snapshot(self, force: Optional[bool] = False) -> bool:
        """
        Bumps version and expiration date of TUF 'snapshot' role metadata.

        The version number is incremented by one, the expiration date renewed
        using a configured expiration interval, and the metadata is signed and
        persisted using the configured key and storage services.

        Updating 'snapshot' also updates 'timestamp'.

        Args:
            force: force snapshot bump if it doesn't match the hours before
                expire (`self._hours_before_expire`)
        """

        try:
            snapshot = self._storage_backend.get(Snapshot.type)
        except StorageError:
            logging.error(f"{Snapshot.type} not found, not bumping.")
            return False

        if (snapshot.signed.expires - datetime.now()) < timedelta(
            hours=self._hours_before_expire or force is True
        ):
            timestamp = self._update_timestamp(self._update_snapshot())
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

    def bump_online_roles(self, force: Optional[bool] = False) -> bool:
        """
        Bump online roles (Snapshot, Timestamp, Targets and BINS).

        Args:
            force: force target roles bump if they don't match the hours before
                expire (`self._hours_before_expire`)
        """
        logging.debug(f"Configured timeout: {self._timeout}")
        if self._settings.get_fresh("BOOTSTRAP") is None:
            logging.info("[automatic_version_bump] No bootstrap, skipping...")
            return False

        status_lock_targets = False
        # Lock to avoid race conditions. See `LOCK_TIMEOUT` in the Worker guide
        # documentation.
        try:
            with self._redis.lock(LOCK_TARGETS, timeout=self._timeout):
                self._run_online_roles_bump(force=force)

            status_lock_targets = True
        except redis.exceptions.LockNotOwnedError:
            # The LockNotOwnedError happens when the task exceeds the timeout,
            # and another task owns the lock.
            # If the task time out, the lock is released. If it doesn't finish
            # properly, it will raise (fail) the task. Otherwise, the ignores
            # the error because another task didn't lock it.
            if status_lock_targets is False:
                logging.error(
                    "The task to bump Timestamp, Snapshot, and BINS exceeded "
                    f"the timeout of {self._timeout} seconds."
                )
                raise redis.exceptions.LockError(
                    f"RSTUF: Task exceed `LOCK_TIMEOUT` ({self._timeout} "
                    "seconds)"
                )

        return True

    def _trusted_root_update(
        self, current_root: Metadata[Root], new_root: Metadata[Root]
    ):
        """Verify if the new metadata is a trusted Root metadata"""

        # Verify the Type
        if new_root.signed.type != Root.type:
            raise RepositoryError(
                f"Expected 'root', got '{new_root.signed.type}'"
            )

        # Verify that new root is signed by trusted root
        current_root.verify_delegate(Root.type, new_root)

        # Verify that new root is signed by itself
        new_root.verify_delegate(Root.type, new_root)

        # Verify the new root version
        if new_root.signed.version != current_root.signed.version + 1:
            raise BadVersionNumberError(
                f"Expected root version {current_root.signed.version + 1}"
                f" instead got version {new_root.signed.version}"
            )

    def _root_metadata_update(
        self,
        new_root: Metadata[Root],
        update_state: Optional[
            Task.update_state
        ] = None,  # It is required (see: app.py)
    ) -> Dict[str, Any]:
        """
        Update Root metadata.
        It checks if the new root metadata is trusted and runs a specific
        process for updating the Root Metadata.

        Args:
            new_root: contains new metadata
                example: {"metadata": {"root": Any}}
            update_state: not used, but required argument by `app.py`
        """
        current_root: Metadata[Root] = self._storage_backend.get(Root.type)

        self._trusted_root_update(current_root, new_root)

        # We always persist the new root metadata, but we cannot persist
        # without verifying if the online key is rotated to avoid a mismatch
        # with the rest of the roles using the online key.
        current_online_keyid = current_root.signed.roles[Timestamp.type].keyids
        new_online_keyid = new_root.signed.roles[Timestamp.type].keyids
        if current_online_keyid == new_online_keyid:
            # online key is not changed, persist the new root
            self._persist(new_root, Root.type)
            logging.info(f"Updating root metadata: {new_root.signed.version}")

        else:
            # We lock this action to stop all new tasks that publish targets
            # (`publish_targets`) to avoid inconsistencies happening to the
            # TUF clients.
            # It is required lock with LOCK_TARGETS before persisting the root
            # metadata.
            status_lock_targets = False
            try:
                with self._redis.lock(LOCK_TARGETS, timeout=self._timeout):
                    # root metadata and online key are updated
                    # 1. persist the new root
                    # 2. bump all target roles
                    self._persist(new_root, Root.type)
                    logging.info(
                        f"Updating root metadata: {new_root.signed.version}"
                    )
                    self._run_online_roles_bump(force=True)
                    logging.info("Updating all targets metadata")
                    status_lock_targets = True
            except redis.exceptions.LockNotOwnedError:
                if status_lock_targets is False:
                    logging.error(
                        "The task of metadata update exceeded the timeout"
                    )
                    raise redis.exceptions.LockError(
                        "RSTUF: Task exceed `LOCK_TIMEOUT` "
                        f"({self._timeout} seconds)"
                    )

        result = ResultDetails(
            status="Task finished.",
            details={
                "message": "metadata update finished",
            },
            last_update=datetime.now(),
        )

        return asdict(result)

    def metadata_update(
        self,
        payload: Dict[Literal["metadata"], Dict[Literal[Root.type], Any]],
        update_state: Optional[
            Task.update_state
        ] = None,  # It is required (see: app.py)
    ) -> Dict[str, Any]:
        """
        Update TUF metadata.

        Args:
            payload: contains new metadata
                Supported metadata types: Root
                example: {"metadata": {"root": Any}}
            update_state: not used, but required argument by `app.py`
        """

        # there is also a verification in the RSTUF API calls
        bootstrap = self._settings.get_fresh("BOOTSTRAP")
        if bootstrap is None or "pre-" in bootstrap:
            raise RepositoryError(
                "Metadata Update requires a complete bootstrap"
            )

        metadata = payload.get("metadata")
        if metadata is None:
            raise KeyError("No 'metadata' in the payload")

        if Root.type in metadata:
            new_root = Metadata.from_dict(metadata[Root.type])
            return self._root_metadata_update(new_root)
        else:
            raise ValueError("Unsupported Metadata type")

    def metadata_rotation(
        self,
        payload: Dict[Literal["metadata"], Dict[Literal[Root.type], Any]],
        update_state: Optional[
            Task.update_state
        ] = None,  # It is required (see: app.py)
    ) -> Dict[str, Any]:
        deprecation_message = (
            "`metadata_rotation` is deprecated, use `metadata_update` instead."
            " It will be removed in version 1.0.0."
        )
        warnings.warn(deprecation_message, DeprecationWarning)
        logging.warn(deprecation_message)

        return self.metadata_update(payload, update_state)
