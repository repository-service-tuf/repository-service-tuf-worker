# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import enum
import logging
import time
import warnings
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from math import log
from typing import Any, Dict, Iterator, List, Literal, Optional

import redis
from celery.app.task import Task
from celery.exceptions import ChordError
from celery.result import AsyncResult, states
from dynaconf.loaders import redis_loader
from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.signer import Key, Signature
from tuf.api.exceptions import (
    BadVersionNumberError,
    RepositoryError,
    UnsignedMetadataError,
)
from tuf.api.metadata import (  # noqa
    SPECIFICATION_VERSION,
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
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
from tuf.api.serialization.json import CanonicalJSONSerializer, JSONSerializer

from repository_service_tuf_worker import (  # noqa
    Dynaconf,
    get_repository_settings,
    get_worker_settings,
)
from repository_service_tuf_worker.interfaces import IKeyVault, IStorage
from repository_service_tuf_worker.models import (
    rstuf_db,
    targets_crud,
    targets_models,
    targets_schema,
)
from repository_service_tuf_worker.signer import SignerStore


class Roles(enum.Enum):
    ROOT = Root.type
    TARGETS = Targets.type
    SNAPSHOT = Snapshot.type
    TIMESTAMP = Timestamp.type
    BINS = "bins"

    @staticmethod
    def online_roles() -> List[str]:
        return [Targets.type, Snapshot.type, Timestamp.type, "bins"]


ALL_REPOSITORY_ROLES_NAMES = [rolename.value for rolename in Roles]
OFFLINE_KEYS = {
    Roles.ROOT.value.upper(),
    Roles.TARGETS.value.upper(),
}

BINS = "bins"
SPEC_VERSION: str = ".".join(SPECIFICATION_VERSION)

# lock constants
LOCK_TARGETS = "LOCK_TARGETS"


class TaskName(str, enum.Enum):
    ADD_TARGETS = "add_targets"
    REMOVE_TARGETS = "remove_targets"
    BOOTSTRAP = "bootstrap"
    UPDATE_SETTINGS = "update_settings"
    PUBLISH_TARGETS = "publish_targets"
    METADATA_UPDATE = "metadata_update"
    SIGN_METADATA = "sign_metadata"
    DELETE_SIGN_METADATA = "delete_sign_metadata"


@dataclass
class TaskResult:
    task: TaskName
    status: bool
    last_update: datetime
    message: str
    error: Optional[str]
    details: Optional[Dict[str, Any]]


class MetadataRepository:
    """
    A repository service to create and maintain TUF role metadata.
    """

    def __init__(self):
        self._worker_settings: Dynaconf = get_worker_settings()
        app_settings = self.refresh_settings()
        self._storage_backend: IStorage = app_settings.STORAGE
        self._signer_store = SignerStore(app_settings)
        self._db = app_settings.SQL
        self._redis = redis.StrictRedis.from_url(
            self._worker_settings.REDIS_SERVER
        )
        self._hours_before_expire: int = self._settings.get_fresh(
            "HOURS_BEFORE_EXPIRE", 1
        )
        self._timeout = int(app_settings.get("LOCK_TIMEOUT", 60.0))

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

        # storage
        IStorage.from_dynaconf(settings)

        # keyvault
        if settings.get("KEYVAULT_BACKEND"):
            IKeyVault.from_dynaconf(settings)

        self._worker_settings = settings
        return settings

    def write_repository_settings(self, key: str, value: Any):
        """
        Writes repository settings.

        Repository settings are stored in a dictionary like Dynaconf object
        and each of them has its own key and value.
        Additionally, repository settings are persisted in the Redis server
        so that they can be reused by multiple RSTUF Worker instances.

        https://repository-service-tuf.readthedocs.io/en/latest/devel/design.html#rstuf-repository-settings-configuration  # noqa

        Args:
            key: key name

            value: value for the key
        """
        logging.info(f"Saving {key} with value: {value}")
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
        signer = self._signer_store.get(public_key)
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

            if role_name == Root.type:
                self.write_repository_settings("TRUSTED_ROOT", role.to_dict())

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
            target_roles: List of roles to bump. If provided, 'bump_all' arg
                will NOT be taken into account.
            bump_all: Wheter to bump all delegated target roles. If provided,
                then 'target_roles' arg is NOT taken into acount.
        """
        snapshot: Metadata[Snapshot] = self._storage_backend.get(Snapshot.type)
        targets: Metadata[Targets] = self._storage_backend.get(Targets.type)
        bins_used = (
            True if targets.signed.delegations.succinct_roles else False
        )

        db_target_roles: List[targets_models.RSTUFTargetRoles] = []
        if target_roles:
            db_target_roles = targets_crud.read_roles_joint_files(
                self._db, target_roles
            )

            for db_role in db_target_roles:
                rolename = db_role.rolename
                delegation: Metadata[Targets] = self._storage_backend.get(
                    rolename
                )
                delegation.signed.targets.clear()
                delegation.signed.targets = {
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
                deleg_name = BINS if bins_used else rolename
                # update expiry, bump version and persist to the storage
                self._bump_and_persist(delegation, deleg_name, persist=False)
                self._persist(delegation, rolename)
                # update targetfile in db
                # note: It update only if is not published see the CRUD.
                targets_crud.update_files_to_published(
                    self._db, [file.path for file in db_role.target_files]
                )

                snapshot.signed.meta[f"{rolename}.json"] = MetaFile(
                    version=delegation.signed.version
                )

            roles = "".join(target_roles)
            msg = f"Bumped all expired target delegation roles: {roles}"
            logging.info(msg)

        elif bump_all:
            db_target_roles = targets_crud.read_all_roles(self._db)
            for db_role in db_target_roles:
                rolename = db_role.rolename
                delegation: Metadata[Targets] = self._storage_backend.get(
                    db_role.rolename
                )
                deleg_name = BINS if bins_used else rolename
                # update expiry, bump version and persist to the storage
                self._bump_and_persist(delegation, deleg_name, persist=False)
                self._persist(delegation, db_role.rolename)

                snapshot.signed.meta[f"{rolename}.json"] = MetaFile(
                    version=delegation.signed.version
                )

            logging.info("Bumped all target delegation roles")

        if len(db_target_roles) > 0:
            targets_crud.update_roles_version(
                self._db, [int(db_role.id) for db_role in db_target_roles]
            )

        snapshot.signed.meta[f"{Targets.type}.json"] = MetaFile(
            version=targets.signed.version
        )

        # update expiry, bump version and persist to the storage
        self._bump_and_persist(snapshot, Snapshot.type)
        logging.info("Bumped version of 'Snapshot' role")

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
                    "details": {
                        "published_roles": completed_roles,
                        "roles_to_publish": f"{list(bin_targets.keys())}",
                    },
                    "message": "Publishing",
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
        sorted_roles = sorted(list(TOP_LEVEL_ROLE_NAMES))
        for role in sorted_roles:
            role_upp = role.upper()
            threshold = 1
            num_of_keys = 1
            if role == Root.type:
                # get treshold and number of keys from given root metadata
                threshold = root.signed.roles[role].threshold
                num_of_keys = len(root.signatures)

            self.write_repository_settings(
                f"{role_upp}_EXPIRATION",
                settings["roles"][role]["expiration"],
            )
            self.write_repository_settings(f"{role_upp}_THRESHOLD", threshold)
            self.write_repository_settings(f"{role_upp}_NUM_KEYS", num_of_keys)

        # For now targets always uses online key.
        self.write_repository_settings("TARGETS_ONLINE_KEY", True)

        if settings["roles"].get("bins"):
            bins = settings["roles"]["bins"]
            self.write_repository_settings(
                "BINS_EXPIRATION", bins["expiration"]
            )
            self.write_repository_settings("BINS_THRESHOLD", 1)
            self.write_repository_settings("BINS_NUM_KEYS", 1)
            self.write_repository_settings(
                "NUMBER_OF_DELEGATED_BINS",
                bins["number_of_delegated_bins"],
            )

        else:
            delegated_roles = settings["roles"]["delegated_roles"]
            for deleg_name, deleg_info in delegated_roles.items():
                name = deleg_name.upper()
                self.write_repository_settings(
                    f"{name}_EXPIRATION", deleg_info["expiration"]
                )
                self.write_repository_settings(f"{name}_THRESHOLD", 1)
                self.write_repository_settings(f"{name}_NUM_KEYS", 1)
                self.write_repository_settings(
                    f"{name}_PATH_PATTERNS",
                    delegated_roles[deleg_name]["path_patterns"],
                )

    def _setup_targets_delegations(
        self,
        online_pub_key: Key,
        targets: Metadata[Targets],
        custom_targets: Optional[Dict[str, Any]] = None,
    ):
        """Setup target delegations no matter if succinct hash bin or custom"""
        if custom_targets:
            # Using custom Target roles delegations with path prefixes.
            targets.signed.delegations = Delegations({}, {})
            for role_name, role_info in custom_targets.items():
                keyid = online_pub_key.keyid
                targets.signed.delegations.roles[role_name] = DelegatedRole(
                    role_name, [keyid], 1, True, role_info["path_prefixes"]
                )
                targets.signed.add_key(online_pub_key, role_name)
                custom_target = Metadata(Targets())
                self._bump_expiry(custom_target, role_name)
                self._sign(custom_target)
                self._persist(custom_target, role_name)
        else:
            # Using succinct hash bin delegations.
            # Calculate the bit length (Number of bits between 1 and 32)
            # Calculate the bit length (Number of bits between 1 and 32)
            bit_length = int(
                log(self._settings.get_fresh("NUMBER_OF_DELEGATED_BINS"), 2)
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
                targets.signed.add_key(online_pub_key, delegated_name)
                bins_role = Metadata(Targets())
                self._bump_expiry(bins_role, BINS)
                self._sign(bins_role)
                self._persist(bins_role, delegated_name)

    def _get_delegation_roles(
        self, targets: Metadata[Targets]
    ) -> Iterator[str]:
        """Get all Targets delegation roles no matter if bins or custom."""
        if targets.signed.delegations is None:
            raise ValueError("Targets must have delegation, internal error")

        if targets.signed.delegations.succinct_roles:
            # Using succinct hash bin delegations.
            for bin in targets.signed.delegations.succinct_roles.get_roles():
                yield bin
        else:
            # Using custom Target roles delegations with path prefixes.
            for custom_target_name in targets.signed.delegations.roles.keys():
                yield custom_target_name

    def _bootstrap_online_roles(
        self,
        root: Metadata[Root],
        custom_targets: Optional[Dict[str, Any]] = None,
    ):
        """
        Bootstrap the roles that uses the online key
        """
        # Top level roles (`Targets`, `Timestamp``, `Snapshot`) initialization
        targets: Metadata[Targets] = Metadata(Targets())
        snapshot: Metadata[Snapshot] = Metadata(Snapshot())
        timestamp: Metadata[Timestamp] = Metadata(Timestamp())

        _keyid: str = root.signed.roles[Timestamp.type].keyids[0]
        public_key = root.signed.keys[_keyid]
        self._setup_targets_delegations(public_key, targets, custom_targets)

        db_target_roles: List[targets_schema.RSTUFTargetRoleCreate] = []
        for role_name in self._get_delegation_roles(targets):
            snapshot.signed.meta[f"{role_name}.json"] = MetaFile()

            db_target_roles.append(
                targets_schema.RSTUFTargetRoleCreate(
                    rolename=role_name, version=1
                )
            )

        targets_crud.create_roles(self._db, db_target_roles)
        snapshot.signed.meta[f"{Targets.type}.json"] = MetaFile()

        # Update expire, sign and persist the top level roles (`Targets`,
        # `Timestamp``, `Snapshot`) in the backend storage service.
        for role in [targets, snapshot, timestamp]:
            self._bump_expiry(role, role.signed.type)
            self._sign(role)
            self._persist(role, role.signed.type)

    @staticmethod
    def _task_result(
        task: TaskName,
        message: str,
        error: Optional[str],
        details: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Returns a standardized Task Result to the Result Backend Service"""
        if error is not None:
            status = False
        else:
            status = True
        result = TaskResult(
            task=task,
            status=status,
            message=message,
            error=error,
            details=details,
            last_update=datetime.now(),
        )
        return asdict(result)

    def _bootstrap_finalize(
        self, root: Metadata[Root], task_id: str, settings: Dict[str, Any]
    ):
        """
        Register the bootstrap finished.
        """
        self._persist(root, Root.type)
        self.write_repository_settings("ROOT_SIGNING", None)
        self._bootstrap_online_roles(
            root, settings["roles"].get("delegated_roles")
        )
        self.write_repository_settings("BOOTSTRAP", task_id)

    def bootstrap(
        self,
        payload: Dict[str, Any],
        update_state: Optional[
            Task.update_state
        ] = None,  # It is required (see: app.py)
    ) -> Dict[str, Any]:
        """
        Bootstrap the Metadata Repository
        """
        tuf_settings = payload.get("settings")
        if tuf_settings is None:
            return self._task_result(
                task=TaskName.BOOTSTRAP,
                message="Bootstrap Failed",
                error="No 'settings' in the payload",
                details=None,
            )

        root_metadata = payload.get("metadata")
        if root_metadata is None:
            return self._task_result(
                task=TaskName.BOOTSTRAP,
                message="Bootstrap Failed",
                error="No 'metadata' in the payload",
                details=None,
            )

        bootstrap_status = self._settings.get_fresh("BOOTSTRAP")
        if bootstrap_status is not None and "pre-" not in bootstrap_status:
            return self._task_result(
                task=TaskName.BOOTSTRAP,
                message="Bootstrap Failed",
                error=f"Bootstrap state is {bootstrap_status}",
                details=None,
            )

        root: Metadata[Root] = Metadata.from_dict(root_metadata[Root.type])
        if len(root.signatures) == 0:
            self.write_repository_settings("BOOTSTRAP", None)
            return self._task_result(
                task=TaskName.BOOTSTRAP,
                message="Bootstrap Failed",
                error="Metadata requires at least one valid signature",
                details=None,
            )

        for signature in root.signatures.values():
            if self._validate_signature(root, signature) is False:
                self.write_repository_settings("BOOTSTRAP", None)
                return self._task_result(
                    task=TaskName.BOOTSTRAP,
                    message="Bootstrap Failed",
                    error="Bootstrap has invalid signature(s)",
                    details=None,
                )

        custom_targets = tuf_settings["roles"].get("delegated_roles")
        if custom_targets:
            if tuf_settings["services"].get("number_of_delegated_bins"):
                return self._task_result(
                    TaskName.BOOTSTRAP,
                    message="Bootstrap Failed",
                    error=(
                        "Bootstrap cannot use both hash bin delegation and"
                        " custom target delegations"
                    ),
                    details=None,
                )

        # save settings
        self.save_settings(root, tuf_settings)
        task_id: str = payload["task_id"]

        signed = self._validate_threshold(root)
        if signed:
            self._bootstrap_finalize(root, task_id, tuf_settings)
            message = f"Bootstrap finished {task_id}"
            logging.info(message)
        else:
            self.write_repository_settings("ROOT_SIGNING", root.to_dict())
            self.write_repository_settings("BOOTSTRAP", f"signing-{task_id}")
            message = f"Root v{root.signed.version} is pending signature"
            logging.info(message)

        return self._task_result(
            task=TaskName.BOOTSTRAP,
            message="Bootstrap Processed",
            error=None,
            details={"bootstrap": message},
        )

    def update_settings(
        self,
        payload: Dict[str, Any],
        update_state: Optional[
            Task.update_state
        ] = None,  # It is required (see: app.py)
    ) -> Dict[str, Any]:
        """
        Update repository settings with the new settings.

        Supports only updating the expiration policy settings for online roles.
        Expiration parameters reference:
        https://repository-service-tuf.readthedocs.io/en/stable/devel/design.html#tuf-repository-settings  # noqa
        """
        details: Optional[Dict[str, Any]]
        tuf_settings = payload.get("settings")
        if tuf_settings is None:
            message = "Update Settings Failed"
            error = "No 'settings' in the payload"
            details = None
        elif tuf_settings.get("expiration") is None:
            message = "Update Settings Failed"
            error = "No 'expiration' in the payload"
            details = None
        elif len(tuf_settings["expiration"]) < 1:
            message = "Update Settings Failed"
            error = "No role provided for expiration policy change"
            details = None
        else:
            logging.info("Updating settings")
            online_roles = Roles.online_roles()
            updated_roles: List[str] = []
            invalid_roles: List[str] = []
            for role in tuf_settings["expiration"]:
                if role not in online_roles:
                    invalid_roles.append(role)
                    continue

                self.write_repository_settings(
                    f"{role.upper()}_EXPIRATION",
                    tuf_settings["expiration"][role],
                )
                updated_roles.append(role)

            message = "Update Settings Succeded"
            error = None
            details = {
                "updated_roles": updated_roles,
                "invalid_roles": invalid_roles,
            }

        return self._task_result(
            task=TaskName.UPDATE_SETTINGS,
            message=message,
            error=error,
            details=details,
        )

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
                    return self._task_result(
                        task=TaskName.PUBLISH_TARGETS,
                        message="Publish Targets Processed",
                        error=None,
                        details={"target_roles": None},
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

        logging.debug("Targets published")
        return self._task_result(
            task=TaskName.PUBLISH_TARGETS,
            message="Publish Targets Processed",
            error=None,
            details={
                "target_roles": bins_targets,
            },
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
            return self._task_result(
                task=TaskName.ADD_TARGETS,
                message="Adding target(s) Failed",
                error="No 'targets' in the payload",
                details=None,
            )
        # The task id will be used by `_send_publish_targets_task` (sub-task).
        task_id = payload.get("task_id")
        # Group target files by responsible delegated role.
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

        add_targets = [target.get("path") for target in targets]
        update_roles = [t_role for t_role in bin_targets]

        logging.debug(f"Added targets: {add_targets} on Roles {update_roles}")
        return self._task_result(
            task=TaskName.ADD_TARGETS,
            message="Target(s) Added",
            error=None,
            details={
                "targets": add_targets,
                "target_roles": update_roles,
            },
        )

    def remove_targets(
        self, payload: Dict[str, Any], update_state: Task.update_state
    ) -> Dict[str, Any]:
        """
        Remove targets from the metadata roles.
        """
        targets = payload.get("targets")
        if targets is None:
            return self._task_result(
                task=TaskName.REMOVE_TARGETS,
                message="Removing target(s) Failed",
                error="No 'targets' in the payload",
                details=None,
            )
        task_id = payload.get("task_id")

        if len(targets) == 0:
            return self._task_result(
                task=TaskName.REMOVE_TARGETS,
                message="Removing target(s) Failed",
                error="At list one target is required",
                details=None,
            )

        deleted_targets: List[str] = []
        not_found_targets: List[str] = []

        # Group target files by responsible delegated role.
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

        logging.debug(
            f"Delete targets: {deleted_targets}. "
            f"Not found targets: {not_found_targets}"
        )

        return self._task_result(
            task=TaskName.REMOVE_TARGETS,
            message="Target(s) removed",
            error=None,
            details={
                "deleted_targets": deleted_targets,
                "not_found_targets": not_found_targets,
            },
        )

    def _run_online_roles_bump(self, force: Optional[bool] = False):
        """
        Bumps version and expiration date of all online roles (`Targets`,
        `Succinct Delegated` targets roles, `Timestamp` and `Snapshot`).

        ** It might require a lock context to avoid race conditions **

        The version numbers are incremented by one, the expiration dates are
        renewed using a configured expiration interval, and the metadata is
        signed and persisted using the configured key and storage services.

        Args:
            force: force all target roles bump even if they have more than
            `self._hours_before_expire` hours to expire.
        """
        targets: Metadata = self._storage_backend.get(Targets.type)
        timestamp: Metadata
        snapshot_bump = False
        if self._settings.get_fresh("TARGETS_ONLINE_KEY") is None:
            logging.critical("No configuration found for TARGETS_ONLINE_KEY")

        elif self._settings.get_fresh("TARGETS_ONLINE_KEY") is False:
            logging.warning(
                f"{Targets.type} don't use online key, skipping 'Targets' role"
            )
        else:
            if force or (targets.signed.expires - datetime.now()) < timedelta(
                hours=self._hours_before_expire
            ):
                logging.info("Bumped version of 'Targets' role")
                self._bump_and_persist(targets, Targets.type)
                snapshot_bump = True

        if force:
            # Updating all delegated target roles.
            timestamp = self._update_timestamp(
                self._update_snapshot(bump_all=True)
            )
            snapshot_bump = True
            logging.info("Targets and delegated Targets roles version bumped")
        else:
            # Updating only those delegated roles that have expired.
            delegated_roles: List[str] = []
            for role in self._get_delegation_roles(targets):
                role_md: Metadata[Targets] = self._storage_backend.get(role)
                if (role_md.signed.expires - datetime.now()) < timedelta(
                    hours=self._hours_before_expire
                ):
                    delegated_roles.append(role)

            if len(delegated_roles) > 0:
                timestamp = self._update_timestamp(
                    self._update_snapshot(target_roles=delegated_roles)
                )
                snapshot_bump = True
                roles = "".join(delegated_roles)
                logging.info(f"Bumped versions of expired roles: {roles}")
            else:
                logging.debug(
                    "[scheduled bump] All delegated roles have more than "
                    f"{self._hours_before_expire} hour(s) to expire, "
                    "skipping"
                )

        if snapshot_bump:
            snapshot_v = timestamp.signed.snapshot_meta.version
            logging.info(
                f"[scheduled bump] Snapshot version bumped: {snapshot_v}"
            )
            timestamp_v = timestamp.signed.version
            logging.info(
                f"[scheduled bump] Timestamp version bumped: {timestamp_v}"
            )

    def bump_snapshot(self, force: Optional[bool] = False):
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

        snapshot = self._storage_backend.get(Snapshot.type)
        if (snapshot.signed.expires - datetime.now()) < timedelta(
            hours=self._hours_before_expire
        ) or force:
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

    def bump_online_roles(self, force: Optional[bool] = False) -> bool:
        """
        Bump online roles (Snapshot, Timestamp, Targets and delegated roles).

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
                    "The task to bump all online roles exceeded the timeout "
                    f"of {self._timeout} seconds."
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

        # Verify the new root version
        if new_root.signed.version != current_root.signed.version + 1:
            raise BadVersionNumberError(
                f"Expected root version {current_root.signed.version + 1}"
                f" instead got version {new_root.signed.version}"
            )

        # Verify that new root is signed by trusted root
        current_root.verify_delegate(Root.type, new_root)

        # Verify that new root is signed by itself
        new_root.verify_delegate(Root.type, new_root)

    def _root_metadata_update(
        self, new_root: Metadata[Root]
    ) -> Dict[str, Any]:
        """Updates to new root metadata, if it is trusted."""
        current_root: Metadata[Root] = self._storage_backend.get(Root.type)

        try:
            self._trusted_root_update(current_root, new_root)

        except UnsignedMetadataError:
            # TODO: Add missing sanity check - new root must have at least 1
            # and only valid signature - use `get_verification_status` (#367)
            self.write_repository_settings("ROOT_SIGNING", new_root.to_dict())
            return self._task_result(
                task=TaskName.METADATA_UPDATE,
                message="Metadata Update Processed",
                error=None,
                details={
                    "role": Root.type,
                    "update": (
                        f"Root v{new_root.signed.version} is "
                        "pending signatures"
                    ),
                },
            )

        except (
            ValueError,
            TypeError,
            BadVersionNumberError,
            RepositoryError,
        ) as err:
            return self._task_result(
                task=TaskName.METADATA_UPDATE,
                message="Metadata Update Failed",
                error=f"Failed to verify the trust: {str(err)}",
                details=None,
            )

        self._root_metadata_update_finalize(current_root, new_root)
        return self._task_result(
            task=TaskName.METADATA_UPDATE,
            message="Metadata Update Processed",
            error=None,
            details={"role": Root.type},
        )

    def _root_metadata_update_finalize(
        self, current_root: Metadata[Root], new_root: Metadata[Root]
    ) -> None:
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
            return self._task_result(
                task=TaskName.METADATA_UPDATE,
                message="Metadata Update Failed",
                error="Metadata Update requires a completed bootstrap",
                details=None,
            )

        metadata = payload.get("metadata")
        if metadata is None:
            return self._task_result(
                task=TaskName.METADATA_UPDATE,
                message="Metadata Update Failed",
                error="No 'metadata' in the payload",
                details=None,
            )

        if Root.type in metadata:
            new_root = Metadata.from_dict(metadata[Root.type])
            return self._root_metadata_update(new_root)
        else:
            return self._task_result(
                task=TaskName.METADATA_UPDATE,
                message="Metadata Update Failed",
                error="Unsupported Metadata type",
                details=None,
            )

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

    @staticmethod
    def _validate_signature(
        metadata: Metadata,
        signature: Signature,
        delegator: Optional[Metadata] = None,
    ) -> bool:
        """
        Validate signature over metadata using appropriate delegator.
        If no delegator is passed, the metadata itself is used as delegator.
        """
        if delegator is None:
            delegator = metadata

        keyid = signature.keyid
        if keyid not in delegator.signed.roles[Root.type].keyids:
            logging.info(f"signature '{keyid}' not authorized")
            return False

        key = delegator.signed.keys.get(signature.keyid)
        if not key:
            logging.info(f"no key for signature '{keyid}'")
            return False

        signed_serializer = CanonicalJSONSerializer()
        signed_bytes = signed_serializer.serialize(metadata.signed)
        try:
            key.verify_signature(signature, signed_bytes)

        except UnverifiedSignatureError:
            logging.info(f"signature '{keyid}' invalid")
            return False

        return True

    @staticmethod
    def _validate_threshold(
        metadata: Metadata, delegator: Optional[Metadata] = None
    ) -> bool:
        """
        Validate signature threshold using appropriate delegator(s).
        If no delegator is passed, the metadata itself is used as delegator.
        """
        if delegator is None:
            delegator = metadata

        try:
            delegator.verify_delegate(Root.type, metadata)

        except UnsignedMetadataError as e:
            logging.info(e)
            return False

        return True

    def sign_metadata(
        self,
        payload: Dict[str, Any],
        update_state: Optional[
            Task.update_state
        ] = None,  # It is required (see: app.py)
    ) -> Dict[str, Any]:
        """Add signature to metadata for pending signing event.

        Add signature (from payload) to cached root metadata (from settings),
        if a signing event exists, and the signature is valid.

        Signing event types are 'bootstrap' or 'metadata update'.

        If the signature threshold is reached, the signing event is finalized,
        otherwise it remains in pending state.
        """

        def _result(status, error=None, bootstrap=None, update=None):
            details = {}
            if status:
                result = "Signature Processed"
            else:
                result = "Signature Failed"
            if error:
                error = error
                details = None
            elif bootstrap:
                details["bootstrap"] = bootstrap
            elif update:
                details["update"] = update

            return self._task_result(
                task=TaskName.SIGN_METADATA,
                message=result,
                error=error,
                details=details,
            )

        signature = Signature.from_dict(payload["signature"])
        rolename = payload["role"]

        # Assert requested metadata type is root
        if rolename != Root.type:
            msg = f"Expected '{Root.type}', got '{rolename}'"
            return _result(False, error=msg)

        # Assert pending signing event exists
        metadata_dict = self._settings.get_fresh("ROOT_SIGNING")
        if metadata_dict is None:
            msg = "No signatures pending for root"
            return _result(False, error=msg)

        # Assert metadata type is root
        root = Metadata.from_dict(metadata_dict)
        if not isinstance(root.signed, Root):
            msg = f"Expected 'root', got '{root.signed.type}'"
            return _result(False, error=msg)

        # If it isn't a "bootstrap" signing event, it must be "update metadata"
        bootstrap_state = self._settings.get_fresh("BOOTSTRAP")
        if "signing" in bootstrap_state:
            # Signature and threshold of initial root can only self-validate,
            # there is no "trusted root" at bootstrap time yet.
            if not self._validate_signature(root, signature):
                return _result(False, error="Invalid signature")

            root.signatures[signature.keyid] = signature
            if not self._validate_threshold(root):
                self.write_repository_settings("ROOT_SIGNING", root.to_dict())
                msg = f"Root v{root.signed.version} is pending signatures"
                return _result(True, bootstrap=msg)

            bootstrap_task_id = bootstrap_state.split("signing-")[1]
            self._bootstrap_finalize(root, bootstrap_task_id)
            return _result(True, bootstrap="Bootstrap Finished")

        else:
            # We need the "trusted root" when updating to a new root:
            # - signature could come from a key, which is only in the trusted
            #   root, OR from a key, which is only in the new root
            # - threshold must validate with the threshold of keys as defined
            #   in the trusted root AND as defined in the new root
            trusted_root = self._storage_backend.get("root")
            is_valid_trusted = self._validate_signature(
                root, signature, trusted_root
            )
            is_valid_new = self._validate_signature(root, signature)

            if not (is_valid_trusted or is_valid_new):
                return _result(False, error="Invalid signature")

            root.signatures[signature.keyid] = signature
            trusted_threshold = self._validate_threshold(root, trusted_root)
            new_threshold = self._validate_threshold(root)
            if not (trusted_threshold and new_threshold):
                self.write_repository_settings("ROOT_SIGNING", root.to_dict())
                msg = f"Root v{root.signed.version} is pending signatures"
                return _result(True, update=msg)

            # Threshold reached -> finalize event
            self._root_metadata_update_finalize(trusted_root, root)
            self.write_repository_settings("ROOT_SIGNING", None)
            return _result(True, update="Metadata update finished")

    def delete_sign_metadata(
        self,
        payload: Dict[str, Any],
        update_state: Optional[
            Task.update_state
        ] = None,  # It is required (see: app.py)
    ) -> Dict[str, Any]:
        role: str = payload.get("role")
        if role is None:
            message = "Deletion of metadata pending signatures failed"
            return self._task_result(
                task=TaskName.DELETE_SIGN_METADATA,
                message=message,
                error="No role provided for deletion.",
                details=None,
            )

        signing_status = self._settings.get_fresh(f"{role.upper()}_SIGNING")
        if signing_status is None:
            return self._task_result(
                task=TaskName.DELETE_SIGN_METADATA,
                message=f"Deletion of {role} metadata failed.",
                error=f"The {role} role is not in a signing process.",
                details=None,
            )

        self.write_repository_settings(f"{role.upper()}_SIGNING", None)
        message = (
            f"Deletion of {role} metadata successful, signing process stopped"
        )
        if role == Root.type:
            bootstrap: Optional[str] = self._settings.get_fresh("BOOTSTRAP")
            # bootstrap is in a signing process pending signatures
            if bootstrap is not None and bootstrap.startswith("signing-"):
                self.write_repository_settings("BOOTSTRAP", None)
                return self._task_result(
                    task=TaskName.DELETE_SIGN_METADATA,
                    message=message,
                    error=None,
                    details={
                        "bootstrap": "Bootstrap process has been stopped",
                    },
                )

        return self._task_result(
            task=TaskName.DELETE_SIGN_METADATA,
            message=message,
            error=None,
            details=None,
        )
