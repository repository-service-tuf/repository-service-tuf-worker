# SPDX-FileCopyrightText: 2023-2024 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import copy
import enum
import logging
import time
import warnings
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from math import log
from typing import Any, Dict, List, Literal, Optional, Tuple
from urllib.parse import urlparse

import redis
from celery.app.task import Task
from celery.exceptions import ChordError
from celery.result import AsyncResult, states
from dynaconf.loaders import redis_loader
from securesystemslib.exceptions import StorageError, UnverifiedSignatureError
from securesystemslib.signer import (
    KEY_FOR_TYPE_AND_SCHEME,
    Key,
    Signature,
    SigstoreKey,
)
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
from repository_service_tuf_worker.interfaces import IStorage
from repository_service_tuf_worker.models import (
    rstuf_db,
    targets_crud,
    targets_models,
    targets_schema,
)
from repository_service_tuf_worker.signer import SignerStore

KEY_FOR_TYPE_AND_SCHEME.update(
    {
        ("sigstore-oidc", "Fulcio"): SigstoreKey,
    }
)


class Roles(enum.Enum):
    ROOT = Root.type
    TARGETS = Targets.type
    SNAPSHOT = Snapshot.type
    TIMESTAMP = Timestamp.type
    BINS = "bins"

    @staticmethod
    def is_role(input: Any) -> bool:
        if not isinstance(input, str):
            return False

        return any(input == role.value for role in Roles)


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
    ADD_ARTIFACTS = "add_artifacts"
    REMOVE_ARTIFACTS = "remove_artifacts"
    BOOTSTRAP = "bootstrap"
    UPDATE_SETTINGS = "update_settings"
    PUBLISH_ARTIFACTS = "publish_artifacts"
    FORCE_ONLINE_METADATA_UPDATE = "force_online_metadata_update"
    METADATA_UPDATE = "metadata_update"
    METADATA_DELEGATION = "metadata_delegation"
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

    @property
    def _online_key(self) -> Key:
        key_dict = self._settings.get_fresh("ONLINE_KEY")
        if key_dict is not None:
            return Key.from_dict(key_dict.pop("keyid"), key_dict)
        else:
            root: Metadata[Root] = self._storage_backend.get(Root.type)
            # All roles except root share the same one key and it doesn't
            # matter from which role we will get the key.
            keyid: str = root.signed.roles["timestamp"].keyids[0]
            key = root.signed.keys[keyid]
            key_dict = key.to_dict()
            key_dict["keyid"] = key.keyid
            self.write_repository_settings("ONLINE_KEY", key_dict)
            return key

    @_online_key.setter
    def _online_key(self, key: Key):
        key_dict = key.to_dict()
        key_dict["keyid"] = key.keyid
        self.write_repository_settings("ONLINE_KEY", key_dict)

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
        # DB
        #
        # TODO: Removed deprecated RSTUF_SQL_* settings in the future
        sql_server_url = self._worker_settings.get("SQL_SERVER")
        sql_user = self._worker_settings.get("SQL_USER")
        sql_password = self._worker_settings.get("SQL_PASSWORD")
        if sql_server_url or sql_user or sql_password:
            logging.warning(
                "Using RSTUF_SQL_* environment variables is deprecated. "
                "Use RSTUF_DB_* instead."
            )
        db_server_url = self._worker_settings.get("DB_SERVER", sql_server_url)
        db_user = self._worker_settings.get("DB_USER", sql_user)
        db_password = self._worker_settings.get("DB_PASSWORD", sql_password)

        # TODO: Remove this warning and default to postgresql://
        if "://" not in db_server_url:
            logging.warning(
                "RSTUF_DB_SERVER does not contain a scheme. "
                "Defaulting to postgresql://"
            )
            db_server_url = f"postgresql://{db_server_url}"
        uri = urlparse(db_server_url)

        if db_user:
            if db_password is None:
                raise AttributeError(
                    "'Settings' object has no attribute 'DB_PASSWORD'"
                    "'DB_PASSWORD' is required when using 'DB_USER'"
                )
            if db_password.startswith("/run/secrets"):
                try:
                    with open(db_password) as f:
                        db_password = f.read().rstrip("\n")
                except OSError as err:
                    logging.error(str(err))
                    raise err
            db_uri = f"{uri.scheme}://{db_user}:{db_password}@{uri.netloc}"
        else:
            db_uri = f"{uri.scheme}:{uri._replace(scheme='').geturl()}"

        settings.SQL = rstuf_db(db_uri)
        #
        # Backends
        #

        # storage
        IStorage.from_dynaconf(settings)

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
        signer = self._signer_store.get(self._online_key)
        role.sign(signer)

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

            if role_name == Targets.type:
                self.write_repository_settings(
                    "TRUSTED_TARGETS", role.to_dict()
                )

        bytes_data = role.to_bytes(JSONSerializer())
        self._storage_backend.put(bytes_data, filename)
        logging.debug(f"{filename} saved")
        return filename

    def _bump_expiry(self, role: Metadata, role_name: str) -> None:
        """
        Bumps metadata expiration date by role-specific interval.
        """
        role.signed.expires = datetime.now(timezone.utc).replace(
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

    def _update_timestamp(
        self,
        snapshot_version: Optional[int] = None,
        skip: Optional[bool] = False,
    ) -> Metadata[Timestamp]:
        """
        Loads 'timestamp', updates meta info about passed 'snapshot'
        metadata, bumps version and expiration, signs and persists.

        Args:
            snapshot_version: Optional snapshot version to new timestamp.
            skip: Skip bumping version and expiration if snpashot
            version is not provided
        """
        timestamp: Metadata[Timestamp] = self._storage_backend.get(
            Timestamp.type, None
        )
        if not snapshot_version and skip:
            logging.debug(
                "No snapshot version and skip is True. Not bumping Timestamp"
            )
            return timestamp

        timestamp.signed.snapshot_meta = MetaFile(version=snapshot_version)

        self._bump_and_persist(timestamp, Timestamp.type)

        logging.debug("Bumped version of 'Target' role")
        return timestamp

    def _update_snapshot(
        self,
        target_roles: Optional[List[str]] = None,
        bump_all: Optional[bool] = False,
        only_target: Optional[bool] = False,
        only_snapshot: Optional[bool] = False,
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
            only_target: Updates only Targets role in the Snapshot Meta.
                It doesn't Bump and Persist Targets.
            only_snapshot: Bump and Persist Snapshot Role only.
        """
        snapshot: Metadata[Snapshot] = self._storage_backend.get(Snapshot.type)
        targets: Metadata[Targets] = self._storage_backend.get(Targets.type)
        bins_used = (
            True if targets.signed.delegations.succinct_roles else False
        )

        snapshot_meta_updated = False

        db_target_roles: List[targets_models.RSTUFTargetRoles] = []
        if target_roles or bump_all:
            if target_roles:
                db_target_roles = targets_crud.read_roles_joint_files(
                    self._db, target_roles
                )
            elif bump_all:
                db_target_roles = targets_crud.read_all_roles(self._db)
            else:
                raise ValueError("'bump_all' or 'target_roles")

            snapshot_meta_updated = False
            for db_role in db_target_roles:
                rolename = db_role.rolename
                try:
                    delegation: Metadata[Targets] = self._storage_backend.get(
                        rolename
                    )
                    logging.debug(f"role {rolename} loaded from disk")
                    source = "storage"
                except StorageError as err:
                    if delegation_signing := self._settings.get_fresh(
                        f"{rolename.upper()}_SIGNING"
                    ):
                        delegation = Metadata[Targets].from_dict(
                            delegation_signing
                        )
                        logging.debug(f"role {rolename} loaded from singing")
                        source = "signing"
                    else:
                        raise err
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
                delegation_name = BINS if bins_used else rolename
                # update targetfile in db
                # note: It update only if is not published see the CRUD.
                targets_crud.update_files_to_published(
                    self._db, [file.path for file in db_role.target_files]
                )
                delegation_keyids = List[str]
                if targets.signed.delegations.succinct_roles:
                    logging.debug("delegations using succinct delegations")
                    delegation_keyids = (
                        targets.signed.delegations.succinct_roles.keyids
                    )
                else:
                    logging.debug("delegations using custom delegations")
                    delegation_keyids = targets.signed.delegations.roles[
                        delegation_name
                    ].keyids

                if (
                    len(delegation_keyids) == 1
                    and self._online_key.keyid in delegation_keyids
                ):
                    logging.debug(f"role {rolename} full online keys")
                    logging.debug("update expiry, bump version and persist")
                    self._bump_and_persist(
                        delegation, delegation_name, persist=False
                    )
                    self._persist(delegation, rolename)
                    snapshot.signed.meta[f"{rolename}.json"] = MetaFile(
                        version=delegation.signed.version
                    )
                    snapshot_meta_updated = True

                elif (
                    len(delegation_keyids) > 1
                    and self._online_key.keyid in delegation_keyids
                ):
                    logging.debug(f"role {rolename} online/offline keys")
                    self._bump_expiry(delegation, rolename)
                    if source == "storage":
                        self._bump_version(delegation)
                    self._sign(delegation)
                    self.write_repository_settings(
                        f"{rolename.upper()}_SIGNING", delegation.to_dict()
                    )

                else:
                    logging.debug(f"role {rolename} offline keys")
                    delegation.signatures.clear()
                    self._bump_expiry(delegation, rolename)
                    if source == "storage":
                        self._bump_version(delegation)
                    self.write_repository_settings(
                        f"{rolename.upper()}_SIGNING", delegation.to_dict()
                    )

        if only_target:
            snapshot.signed.meta[f"{Targets.type}.json"] = MetaFile(
                version=targets.signed.version
            )
            self._bump_and_persist(snapshot, Snapshot.type)
            logging.debug("Bumped version of 'Snapshot' role")
            snapshot_meta_updated = True

        if only_snapshot:
            self._bump_and_persist(snapshot, Snapshot.type)
            logging.debug("Bumped version of 'Snapshot' role")

        if len(db_target_roles) > 0 and snapshot_meta_updated:
            targets_crud.update_roles_version(
                self._db, [int(db_role.id) for db_role in db_target_roles]
            )

        if snapshot_meta_updated:
            self._bump_and_persist(snapshot, Snapshot.type)
            logging.debug("Bumped version of 'Snapshot' role")

            return snapshot.signed.version
        else:
            return None

    def _update_targets_delegations_key(self, targets: Metadata[Targets]):
        """
        Update the key used by delegations referenced in targets metadata.

        Args:
            targets: current top level targets metadata.
        """
        current_root = self._storage_backend.get(Root.type)
        old_online_keyid = current_root.signed.roles[Targets.type].keyids[0]
        # New online keyid is set to self._online_key before function call.
        new_online_key = self._online_key
        if old_online_keyid == new_online_key.keyid:
            return

        bins = True if targets.signed.delegations.succinct_roles else False
        if bins:
            targets.signed.revoke_key(old_online_keyid)
            targets.signed.add_key(new_online_key)

        else:
            for role in targets.signed.delegations.roles.values():
                if old_online_keyid in role.keyids:
                    targets.signed.revoke_key(old_online_keyid, role.name)
                    targets.signed.add_key(new_online_key, role.name)

    def _get_role_for_artifact_path(self, artifact_path: str) -> Optional[str]:
        """
        Return role name by target file path
        """
        targets: Metadata[Targets] = self._storage_backend.get(Targets.type)
        delegations = targets.signed.delegations
        # Note: there could be more than one matching custom delegated role,
        # for this artifact path, but we get the first match. If we want to get
        # the most specific one we need to use _preorder_depth_first_walk
        # of the ngclient Updater class in python-tuf.
        try:
            role_name, _ = next(
                delegations.get_roles_for_target(artifact_path)
            )
        except StopIteration:
            return None

        return role_name

    def _update_task(
        self,
        roles_to_artifacts: Dict[str, List[targets_models.RSTUFTargetFiles]],
        update_state: Task.update_state,
        subtask: Optional[AsyncResult] = None,
    ):
        """
        Updates the 'RUNNING' state with details if the meta still not
        published in the latest Snapshot. It runs every 3 seconds until the
        task is finished.
        """
        logging.debug(
            f"Waiting roles to be published {list(roles_to_artifacts.keys())}"
        )

        def _update_state(
            state: states,
            roles_artifacts: Dict[str, List[targets_models.RSTUFTargetFiles]],
            completed_roles: List[str],
            exc_type: Optional[str] = None,
            exc_message: Optional[List[str]] = None,
        ):
            update_state(
                state=state,
                meta={
                    "details": {
                        "published_roles": completed_roles,
                        "roles_to_publish": f"{list(roles_artifacts.keys())}",
                    },
                    "message": "Publishing",
                    "last_update": datetime.now(timezone.utc),
                    "exc_type": exc_type,
                    "exc_message": exc_message,
                },
            )

        while True:
            # If using MySQL/MariaDB, we need to commit the transaction in the
            # subtask to see the changes in the main task.
            # https://stackoverflow.com/questions/58212462/db-changes-made-in-a-celery-task-not-visible-in-the-main-thread # noqa
            if "mysql" in self._db.bind.url.drivername:
                self._db.commit()

            completed_roles: List[str] = []
            for role_name, artifacts in roles_to_artifacts.items():
                for artifact in artifacts:
                    self._db.refresh(artifact)
                    if artifact.published is True:
                        artifacts.remove(artifact)

                if len(artifacts) == 0:
                    logging.debug(f"Update: {role_name} completed")
                    completed_roles.append(role_name)

            if subtask is not None and subtask.status == states.FAILURE:
                exc_type = subtask.result.__class__.__name__
                exc_message = list(subtask.result.args)
                _update_state(
                    states.FAILURE,
                    roles_to_artifacts,
                    completed_roles,
                    exc_type=exc_type,
                    exc_message=exc_message,
                )
                raise ChordError(
                    f"Failed to execute {subtask.task_id}: "
                    f"{exc_type} {exc_message}"
                )

            if sorted(completed_roles) != sorted(list(roles_to_artifacts)):
                _update_state("RUNNING", roles_to_artifacts, completed_roles)
                time.sleep(3)
            else:
                break

    def _send_publish_artifacts_task(
        self, task_id: str, delegated_artifacts: Optional[List[str]]
    ):  # pragma: no cover
        """
        Send a new task to the `rstuf_internals` queue to publish artifacts.
        """
        # it is imported in the call to avoid a circular import
        from app import repository_service_tuf_worker

        return repository_service_tuf_worker.apply_async(
            kwargs={
                "action": "publish_artifacts",
                "payload": {"delegated_artifacts": delegated_artifacts},
            },
            task_id=f"publish_artifacts-{task_id}",
            queue="rstuf_internals",
            acks_late=True,
        )

    def save_settings(self, root: Metadata[Root], roles_info: Dict[str, Any]):
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
                roles_info[role]["expiration"],
            )
            self.write_repository_settings(f"{role_upp}_THRESHOLD", threshold)
            self.write_repository_settings(f"{role_upp}_NUM_KEYS", num_of_keys)

        # For now targets always uses online key.
        self.write_repository_settings("TARGETS_ONLINE_KEY", True)

        if roles_info.get("bins"):
            bins = roles_info["bins"]
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
            self.write_repository_settings(
                "DELEGATIONS", roles_info.get("delegations")
            )

    def _add_metadata_hashbin_delegations(
        self,
        targets: Metadata[Targets],
    ):
        """Setup target delegations no matter if succinct hash bin or custom"""
        delegated_roles: List[str] = []

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
        db_target_roles: List[targets_schema.RSTUFTargetRoleCreate] = []

        for delegated_name in succinct_roles.get_roles():
            targets.signed.add_key(self._online_key, delegated_name)
            bins_role = Metadata(Targets())
            db_target_roles.append(
                targets_schema.RSTUFTargetRoleCreate(
                    rolename=delegated_name, version=1
                )
            )
            self._bump_expiry(bins_role, BINS)
            self._sign(bins_role)
            self._persist(bins_role, delegated_name)
            delegated_roles.append(delegated_name)

        targets_crud.create_roles(self._db, db_target_roles)
        self._db.commit()

    def _remove_delegated_role_keys(
        self, targets: Metadata[Targets], delegated: DelegatedRole
    ):
        other_keys = []
        logging.debug("mapping keys")
        for not_delete in targets.signed.delegations.roles:
            if not_delete == delegated:
                continue
            other_keys += targets.signed.delegations.roles[not_delete].keyids

        role_keys = targets.signed.delegations.roles[delegated.name].keyids
        for key in role_keys:
            if key not in other_keys:
                logging.debug(f"removing key id {key}")
                targets.signed.delegations.keys.delete(key)
            else:
                logging.debug(f"key {key} used by other role")

    def _add_delegated_role_keys(
        self,
        targets: Metadata[Targets],
        delegations: Delegations,
        role_name: str,
        role_metadata: Optional[Metadata[Targets]] = None,
    ):
        if len(delegations.roles[role_name].keyids) == 0:
            logging.debug(f"role '{role_name}' without key, adding online key")
            delegations.roles[role_name].keyids.append(self._online_key.keyid)

        for keyid in delegations.roles[role_name].keyids:
            if keyid not in targets.signed.delegations.keys.keys():
                logging.debug(f"added key id {keyid}")
                if delegation_key := delegations.keys[keyid]:
                    targets.signed.delegations.keys[keyid] = delegation_key
                else:
                    raise ValueError(f"role {role_name} has inconsistent keys")
            if keyid == self._online_key.keyid and role_metadata:
                logging.debug(f"role '{role_name}' using online key, signing")
                self._sign(role_metadata)

    def _update_delegated_roles(
        self,
        targets: Metadata[Targets],
        updated_delegated: DelegatedRole,
        old_delegated: DelegatedRole,
    ):
        # NOTE: we don't support renaming and we verify it before
        role_name = updated_delegated.name
        # we can detect if keys are different, remove and add
        if updated_delegated.keyids != old_delegated.keyids:
            logging.debug("Identified different keys remove and add")

            # remove keys
            self._remove_delegated_role_keys(targets, old_delegated)
        else:
            logging.debug(f"role {role_name} has same keys")

        targets.signed.delegations.roles.pop(role_name)
        targets.signed.delegations.roles[role_name] = updated_delegated

        # update expire policy
        expires = updated_delegated.unrecognized_fields[
            "x-rstuf-expire-policy"
        ]
        if expires != self._settings.get_fresh(
            f"{role_name.upper()}_EXPIRATION"
        ):
            logging.debug(f"updating expire policy for role {role_name} ")
            self.write_repository_settings(
                f"{role_name.upper()}_EXPIRATION", expires
            )

    def _add_metadata_delegation(
        self,
        delegations: Delegations,
        targets: Optional[Metadata[Targets]] = None,
        persist_targets: Optional[bool] = True,
    ) -> Tuple[Dict[str, Metadata[Targets]], List[str]]:
        """Create a custom delegation role"""

        if targets is None:
            targets = self._storage_backend.get(Targets.type)

        if targets.signed.delegations.succinct_roles:
            raise RepositoryError(
                "Delegations already using hash-bins, cannot add custom roles"
            )

        success = {}
        failed = []
        db_roles = []

        logging.debug("adding roles to Targets delegations")
        for role in delegations.roles:
            if targets.signed.delegations.roles is None:
                logging.debug("initializing Target delegations")
                targets.signed.delegations.roles = {}

            if (
                role in targets.signed.delegations.roles
                or targets_crud.read_role_deactivated_by_rolename(
                    self._db, role
                )
            ):
                logging.info(f"Role '{role}' already exists, skipping")
                failed.append(
                    {
                        "role": role,
                        "reason": (
                            "role already exists or name used in the past",
                        ),
                    }
                )
                continue

            # create delegated target role
            role_metadata = Metadata(Targets(version=1))

            # save expiration settings
            expires = delegations.roles[role].unrecognized_fields[
                "x-rstuf-expire-policy"
            ]
            self.write_repository_settings(
                f"{role.upper()}_EXPIRATION", expires
            )

            # add keys to the delegated target role
            # if no key is assigned, use the online key
            if (
                len(delegations.roles[role].keyids) == 0
                and delegations.roles[role].threshold > 1
            ):
                failed.append(
                    {
                        "role": role,
                        "reason": "If no keys assigned threshold must be 1",
                    }
                )

            self._add_delegated_role_keys(
                targets, delegations, role, role_metadata
            )

            if role not in targets.signed.delegations.roles:
                logging.info(f"Role '{role}' added to Targets delegations")
                targets.signed.delegations.roles[role] = delegations.roles[
                    role
                ]

            success[role] = role_metadata

            logging.debug(f"creating role db '{role}' schema")
            db_roles = targets_schema.RSTUFTargetRoleCreate(
                rolename=role, version=role_metadata.signed.version
            )
            targets_crud.create_roles(self._db, [db_roles])
            self._db.commit()

        if persist_targets and len(success) > 0:
            self._bump_and_persist(targets, Targets.type)
            self._update_timestamp(
                self._update_snapshot(only_target=True), skip=True
            )

        return (success, failed)

    def _delete_metadata_delegation(
        self,
        delegations: List[str],
    ) -> Tuple[Dict[str, Metadata[Targets]], List[str]]:
        """Create a custom delegation role"""

        targets = self._storage_backend.get(Targets.type)
        snapshot = self._storage_backend.get(Snapshot.type)
        success = []
        failed = []

        if targets.signed.delegations.succinct_roles:
            raise RepositoryError(
                "Delegations already using hash-bins, cannot delete custom "
                "roles"
            )

        # remove role from Targets delegations and mapping role unique keys
        for role in delegations.get("roles"):
            rolename = role["name"]
            if rolename not in targets.signed.delegations.roles:
                logging.info(f"Role '{rolename}' does not exists, skipping")
                failed.append(
                    {
                        "role": rolename,
                        "reason": f"Role '{rolename}' does not exists",
                    }
                )
                continue
            delegated_role = targets.signed.delegations.roles[rolename]
            self._remove_delegated_role_keys(targets, delegated_role)

            logging.debug(f"removing role '{rolename}'")
            targets.signed.delegations.roles.pop(rolename)
            logging.debug(
                f"role '{rolename}' removed from Targets delegations"
            )
            snapshot.signed.meta.pop(f"{rolename}.json", None)
            self.write_repository_settings(f"{rolename.upper()}_SIGNING", None)
            db_role = targets_crud.read_role_by_rolename(self._db, rolename)
            targets_crud.update_role_to_deactivated(self._db, db_role)
            self._db.commit()
            success.append(rolename)

        if success:
            self._bump_and_persist(targets, Targets.type)
            self._update_timestamp(
                self._update_snapshot(only_target=True), skip=True
            )

        return (success, failed)

    def _update_metadata_delegation(
        self,
        delegations: Delegations,
    ) -> Tuple[Dict[str, Metadata[Targets]], List[str]]:
        """Update a custom delegation role"""

        targets = self._storage_backend.get(Targets.type)

        if targets.signed.delegations.succinct_roles:
            raise RepositoryError(
                "Delegations already using hash-bins, cannot update"
                "custom roles"
            )

        success = {}
        failed = []
        u_role: DelegatedRole  # updated role
        o_role: DelegatedRole  # old role
        logging.debug("updating roles in Targets delegations")
        current_delegations = copy.deepcopy(targets.signed.delegations)
        for u_role in delegations.roles.values():
            for o_role in current_delegations.roles.values():
                if u_role.name == o_role.name:
                    if len(u_role.keyids) == 0 and u_role.threshold > 1:
                        logging.debug(f"failed {u_role} due invalid threshold")
                        failed.append(
                            {
                                "role": u_role.name,
                                "reason": (
                                    "If no keys assigned threshold must be 1"
                                ),
                            }
                        )
                        continue

                    self._update_delegated_roles(targets, u_role, o_role)

                    self._add_delegated_role_keys(
                        targets, delegations, u_role.name
                    )

                    # not need the role metadata (update later by timestamp)
                    success[u_role.name] = None
                else:
                    logging.debug(f"failed role {u_role.name} doesn't exist")
                    failed.append(
                        {
                            "role": u_role.name,
                            "reason": f"role {u_role} doesn't exist.",
                        }
                    )

        if success:
            self._bump_and_persist(targets, Targets.type)
            self._update_timestamp(
                self._update_snapshot(
                    target_roles=[r for r in success], only_target=True
                ),
                skip=True,
            )

        return (success, failed)

    def _bootstrap_online_roles(
        self,
        delegations: Optional[Delegations] = None,
    ):
        """
        Bootstrap the roles that uses the online key
        """
        # Top level roles (`Targets`, `Timestamp``, `Snapshot`) initialization
        logging.info("Bootstrap online roles")
        targets: Metadata[Targets] = Metadata(Targets())
        targets.signed.delegations = Delegations({}, {})
        snapshot: Metadata[Snapshot] = Metadata(Snapshot())
        snapshot.signed.meta[f"{Targets.type}.json"] = MetaFile()
        timestamp: Metadata[Timestamp] = Metadata(Timestamp())

        if self._online_key.keyid not in targets.signed.delegations.keys:
            logging.debug("online key not in targets, adding key")
            targets.signed.delegations.keys[self._online_key.keyid] = (
                self._online_key
            )

        online_roles = {
            Targets.type: targets,
            Snapshot.type: snapshot,
            Timestamp.type: timestamp,
        }

        if delegations:
            logging.info("Bootstrap using custom delegations")
            success, _ = self._add_metadata_delegation(
                delegations, targets, persist_targets=False
            )

            logging.debug("verifying delegations threshold")
            for role in success:
                if self._validate_threshold(success[role], targets, role):
                    # If the role uses online key it was signed by while
                    # adding the role by self._add_metadata_delegation.
                    # if the threshold is met, role is full signed
                    logging.debug(f"role '{role}' uses only online key")
                    snapshot.signed.meta[f"{role}.json"] = MetaFile(
                        success[role].signed.version
                    )
                    online_roles[role] = success[role]

                else:
                    logging.debug(f"adding role '{role}'for signing")
                    self.write_repository_settings(
                        f"{role.upper()}_SIGNING",
                        success[role].to_dict(),
                    )

        else:
            logging.info("Bootstrap using custom hash bin delegations")
            self._add_metadata_hashbin_delegations(targets)

        # Update expire, sign and persist the top level roles (`Targets`,
        # `Timestamp``, `Snapshot`) in the backend storage service.
        for role in online_roles:
            self._bump_expiry(online_roles[role], role)
            self._sign(online_roles[role])
            self._persist(online_roles[role], role)

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
            last_update=datetime.now(timezone.utc),
        )
        return asdict(result)

    def _bootstrap_finalize(self, root: Metadata[Root], task_id: str):
        """
        Register the bootstrap finished.
        """
        pending_delegations = self._settings.get_fresh("DELEGATIONS")
        if pending_delegations:
            delegations = Delegations.from_dict(pending_delegations)
        else:
            delegations = None
        # All roles except root share the same one key and it doesn't matter
        # from which role we will get the key.
        keyid: str = root.signed.roles["timestamp"].keyids[0]
        self._online_key = root.signed.keys[keyid]
        self._bootstrap_online_roles(delegations=delegations)
        self.write_repository_settings("ROOT_SIGNING", None)
        self._persist(root, Root.type)
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

        roles_info: Dict[str, Any] = tuf_settings["roles"]
        if roles_info.get("delegated_roles") and roles_info.get("bins"):
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
        self.save_settings(root, roles_info)
        task_id: str = payload["task_id"]

        signed = self._validate_threshold(root)
        if signed:
            self._bootstrap_finalize(root, task_id)
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
            updated_roles: List[str] = []
            invalid_roles: List[str] = []
            for role in tuf_settings["expiration"]:
                expiration_str = f"{role.upper()}_EXPIRATION"

                curr_expiration = self._settings.get_fresh(expiration_str)
                if curr_expiration is not None:
                    # This means this role has been added before and it's a
                    # valid role.
                    self.write_repository_settings(
                        expiration_str,
                        tuf_settings["expiration"][role],
                    )
                    updated_roles.append(role)
                else:
                    # curr_expiration = None => the role have not been added
                    # before which makes it invalid.
                    invalid_roles.append(role)

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

    def publish_artifacts(
        self,
        payload: Optional[Dict[str, Any]] = None,
        update_state: Optional[
            Task.update_state
        ] = None,  # It is required (see: app.py)
    ):
        """
        Publish artifacts as persistent TUF Metadata in the backend storage,
        updating Snapshot and Timestamp.
        """
        logging.debug(f"Configured timeout: {self._timeout}")
        lock_status_targets = False
        # Lock to avoid race conditions. See `LOCK_TIMEOUT` in the Worker guide
        # documentation.
        try:
            with self._redis.lock(LOCK_TARGETS, timeout=self._timeout):
                # get all delegated role names with unpublished targets
                if payload is None or payload.get("delegated_targets") is None:
                    db_roles = targets_crud.read_roles_with_unpublished_files(
                        self._db
                    )
                    if db_roles is None:
                        delegated_targets = []
                    else:
                        delegated_targets = [
                            targets_role[0] for targets_role in db_roles
                        ]
                else:
                    delegated_targets: List[str] = payload.get(
                        "delegated_targets"
                    )

                if len(delegated_targets) == 0:
                    logging.debug(
                        "No new artifacts in delegated target roles. Finishing"
                    )
                    return self._task_result(
                        task=TaskName.PUBLISH_ARTIFACTS,
                        message="Publish Artifacts Processed",
                        error=None,
                        details={"target_roles": None},
                    )

                self._update_timestamp(
                    self._update_snapshot(target_roles=delegated_targets),
                    skip=True,
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
                logging.error("The task to publish artifacts exceeded timeout")
                raise redis.exceptions.LockError(
                    "RSTUF: Task exceed `LOCK_TIMEOUT` "
                    f"({self._timeout} seconds)"
                )

        logging.debug("Artifacts published")
        return self._task_result(
            task=TaskName.PUBLISH_ARTIFACTS,
            message="Publish Artifacts Processed",
            error=None,
            details={
                "target_roles": delegated_targets,
            },
        )

    def add_artifacts(
        self, payload: Dict[str, Any], update_state: Task.update_state
    ) -> Optional[Dict[str, Any]]:
        """
        Add or update the new artifact in the SQL DB and submit the task for
        `update_targets`

        Check the artifact(s) in the SQL DB; if it doesn't exist, create a new
        entry or update it as not published.
        After changing the SQL DB submit a new `publish_artifacts` task.
        This function will wait until all the artifacts are published.
        """
        artifacts = payload.get("artifacts")
        if artifacts is None:
            return self._task_result(
                task=TaskName.ADD_ARTIFACTS,
                message="Adding artifact(s) Failed",
                error="No 'artifacts' in the payload",
                details=None,
            )
        # The task id required by `_send_publish_artifacts_task` (sub-task).
        task_id = payload.get("task_id")
        added_artifacts: List[str] = []
        invalid_paths: List[str] = []
        # Group target files by responsible delegated role.
        # This will be used to by `_update_task` for updating task status.
        roles_artifacts: Dict[str, List[targets_models.RSTUFTargetFiles]] = {}
        for artifact in artifacts:
            delegated_role = self._get_role_for_artifact_path(artifact["path"])
            if delegated_role is None:
                invalid_paths.append(artifact["path"])
                continue

            db_target_file = targets_crud.read_file_by_path(
                self._db, artifact.get("path")
            )
            if db_target_file is None:
                db_target_file = targets_crud.create_file(
                    self._db,
                    targets_schema.RSTUFTargetFileCreate(
                        path=artifact.get("path"),
                        info=artifact.get("info"),
                        published=False,
                        action=targets_schema.TargetAction.ADD,
                    ),
                    target_role=targets_crud.read_role_by_rolename(
                        self._db, delegated_role
                    ),
                )
            else:
                db_target_file = targets_crud.update_file_path_and_info(
                    self._db,
                    db_target_file,
                    artifact.get("path"),
                    artifact.get("info"),
                )

            added_artifacts.append(artifact["path"])
            if delegated_role not in roles_artifacts:
                roles_artifacts[delegated_role] = []

            roles_artifacts[delegated_role].append(db_target_file)

        # If publish_artifacts doesn't exists it will be True by default.
        publish_artifacts = payload.get("publish_artifacts", True)
        subtask = None
        if publish_artifacts is True and len(added_artifacts) > 0:
            subtask = self._send_publish_artifacts_task(
                task_id, [t_role for t_role in roles_artifacts]
            )

        self._update_task(roles_artifacts, update_state, subtask)

        updated_roles = [t_role for t_role in roles_artifacts]

        logging.debug(
            f"Added artifacts: {added_artifacts} on Roles {updated_roles}"
        )
        return self._task_result(
            task=TaskName.ADD_ARTIFACTS,
            message="Artifact(s) Added",
            error=None,
            details={
                "added_artifacts": added_artifacts,
                "invalid_paths": invalid_paths,
                "target_roles": updated_roles,
            },
        )

    def remove_artifacts(
        self, payload: Dict[str, Any], update_state: Task.update_state
    ) -> Dict[str, Any]:
        """
        Remove artifacts from the metadata roles.
        """
        artifacts = payload.get("artifacts")
        if artifacts is None:
            return self._task_result(
                task=TaskName.REMOVE_ARTIFACTS,
                message="Removing artifact(s) Failed",
                error="No 'artifacts' in the payload",
                details=None,
            )
        task_id = payload.get("task_id")

        if len(artifacts) == 0:
            return self._task_result(
                task=TaskName.REMOVE_ARTIFACTS,
                message="Removing artifact(s) Failed",
                error="At list one artifact is required",
                details=None,
            )

        deleted_artifacts: List[str] = []
        not_found_artifacts: List[str] = []

        # Group target files by responsible delegated role.
        # This will be used to by `publish_artifacts`
        roles_artifacts: Dict[str, List[targets_models.RSTUFTargetFiles]] = {}
        for artifact in artifacts:
            delegated_role = self._get_role_for_artifact_path(artifact)
            if delegated_role is None:
                not_found_artifacts.append(artifact)
                continue

            db_target = targets_crud.read_file_by_path(self._db, artifact)
            if db_target is None or (
                db_target.action == targets_schema.TargetAction.REMOVE
                and db_target.published is True
            ):
                # not found targets or targets already remove action and
                # published are not found.
                not_found_artifacts.append(artifact)
            else:
                db_target = targets_crud.update_file_action_to_remove(
                    self._db, db_target
                )
                deleted_artifacts.append(artifact)

                if delegated_role not in roles_artifacts:
                    roles_artifacts[delegated_role] = []

                roles_artifacts[delegated_role].append(db_target)

        # If publish_artifacts doesn't exists it will be True by default.
        publish_artifacts = payload.get("publish_artifacts", True)
        subtask = None
        if len(deleted_artifacts) > 0 and publish_artifacts is True:
            subtask = self._send_publish_artifacts_task(
                task_id, [t_role for t_role in roles_artifacts]
            )

        self._update_task(roles_artifacts, update_state, subtask)

        logging.debug(
            f"Deleted artifacts: {deleted_artifacts}. "
            f"Not found artifacts: {not_found_artifacts}"
        )

        return self._task_result(
            task=TaskName.REMOVE_ARTIFACTS,
            message="Artifact(s) removed",
            error=None,
            details={
                "deleted_artifacts": deleted_artifacts,
                "not_found_artifacts": not_found_artifacts,
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

        today = datetime.now(timezone.utc)
        if self._settings.get_fresh("TARGETS_ONLINE_KEY") is None:
            logging.critical("No configuration found for TARGETS_ONLINE_KEY")

        elif self._settings.get_fresh("TARGETS_ONLINE_KEY") is False:
            logging.warning(
                f"{Targets.type} don't use online key, skipping 'Targets' role"
            )
        else:
            targets: Metadata[Targets] = self._storage_backend.get(
                Targets.type
            )
            if force or (targets.signed.expires - today) < timedelta(
                hours=self._hours_before_expire
            ):
                self._update_targets_delegations_key(targets)
                self._bump_and_persist(targets, Targets.type)
                logging.info("Bumped version of 'Targets' role")

        if force:
            # Updating all delegated target roles.
            self._update_timestamp(
                self._update_snapshot(bump_all=True, only_target=True)
            )
            logging.info("Targets and delegated Targets roles version bumped")
        else:
            # Updating only those delegated roles that have expired.
            targets: Metadata[Targets] = self._storage_backend.get(
                Targets.type
            )
            delegated_roles: List[str] = []
            if targets.signed.delegations.succinct_roles:
                s_roles = targets.signed.delegations.succinct_roles.get_roles()
                delegated_roles = [r for r in s_roles]
            else:
                delegated_roles = list(targets.signed.delegations.roles.keys())

            for role in delegated_roles:
                if targets_crud.read_role_deactivated_by_rolename(
                    self._db, role
                ):
                    delegated_roles.remove(role)
                    logging.debug(f"Role '{role}' is deactivated, skipping")
                    continue

                try:
                    role_md: Metadata[Targets] = self._storage_backend.get(
                        role
                    )
                except StorageError as err:
                    if delegation_signing := self._settings.get_fresh(
                        f"{role.upper()}_SIGNING"
                    ):
                        role_md = Metadata[Targets].from_dict(
                            delegation_signing
                        )
                    else:
                        raise err

                if (role_md.signed.expires - today) < timedelta(
                    hours=self._hours_before_expire
                ):
                    continue
                else:
                    delegated_roles.remove(role)

            if len(delegated_roles) > 0:
                self._update_timestamp(
                    self._update_snapshot(target_roles=delegated_roles),
                    skip=True,
                )
                roles = ",".join(delegated_roles)
                logging.info(f"Bumped versions of expired roles: {roles}")
            else:
                logging.debug(
                    "[scheduled bump] All delegated roles have more than "
                    f"{self._hours_before_expire} hour(s) to expire, "
                    "skipping"
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
        if (snapshot.signed.expires - datetime.now(timezone.utc)) < timedelta(
            hours=self._hours_before_expire
        ) or force:
            timestamp = self._update_timestamp(
                self._update_snapshot(only_snapshot=True)
            )
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
        bootstrap = self._settings.get_fresh("BOOTSTRAP")
        if bootstrap is None or "pre-" in bootstrap or "signing-" in bootstrap:
            logging.info(
                "[automatic_version_bump] Bootstrap not completed, skipping..."
            )
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

    def _run_force_online_metadata_update(self, roles: List[str]) -> List[str]:
        "Run the actual metadata update for set of online roles."
        roles_diff: List[str] = []
        delegated_roles: List[str] = []
        if Roles.BINS.value in roles:
            delegated_roles = [Roles.BINS.value]
        else:
            delegated_roles = [r for r in roles if not Roles.is_role(r)]

        if Targets.type in roles or len(delegated_roles) > 0:
            roles_diff = [Snapshot.type, Timestamp.type]
            if Targets.type in roles:
                targets = self._storage_backend.get(Targets.type)
                self._bump_and_persist(targets, Targets.type)
                roles_diff += [Targets.type]

            if delegated_roles == [Roles.BINS.value]:
                self._update_timestamp(self._update_snapshot(bump_all=True))
            else:
                self._update_timestamp(
                    self._update_snapshot(target_roles=delegated_roles)
                )

            roles_diff += [*delegated_roles]

        elif Snapshot.type in roles:
            self.bump_snapshot(force=True)
            roles_diff = [Snapshot.type, Timestamp.type]

        elif Timestamp.type in roles:
            snapshot = self._storage_backend.get(Snapshot.type)
            self._update_timestamp(snapshot.signed.version)
            roles_diff = [Timestamp.type]

        return roles_diff

    def force_online_metadata_update(
        self,
        payload: Dict[str, Any],
        update_state: Optional[
            Task.update_state
        ] = None,  # It is required (see: app.py)
    ) -> Dict[str, Any]:
        """Force metadata update on given online roles."""
        bootstrap = self._settings.get_fresh("BOOTSTRAP")
        if bootstrap is None or "pre-" in bootstrap or "signing-" in bootstrap:
            return self._task_result(
                TaskName.FORCE_ONLINE_METADATA_UPDATE,
                "Force new online metadata update failed",
                "New metadata updates requre completed bootstrap",
                details=None,
            )

        # There is a specific order in which we should update the online roles:
        # 1. targets and all other target roles (like bins)
        # 2. snapshot
        # 3. timestamp
        # If a user requests an update of role from step X, then all other
        # roles from step X+1, X+2, etc. MUST be updated as well.
        roles_updated: List[str]
        status_lock_targets = False
        # Lock to avoid race conditions. See `LOCK_TIMEOUT` in the Worker guide
        # documentation.
        try:
            with self._redis.lock(LOCK_TARGETS, timeout=self._timeout):
                roles_updated = self._run_force_online_metadata_update(
                    payload["roles"]
                )

            status_lock_targets = True
        except redis.exceptions.LockNotOwnedError:
            # The LockNotOwnedError happens when the task exceeds the timeout,
            # and another task owns the lock.
            # If the task time out, the lock is released. If it doesn't finish
            # properly, it will raise (fail) the task. Otherwise, the ignores
            # the error because another task didn't lock it.
            if status_lock_targets is False:
                error = (
                    "The task to update online roles exceeded the "
                    f"timeout of {self._timeout} seconds."
                )
                return self._task_result(
                    TaskName.FORCE_ONLINE_METADATA_UPDATE,
                    "Force new online metadata update failed",
                    error,
                    details=None,
                )

        return self._task_result(
            TaskName.FORCE_ONLINE_METADATA_UPDATE,
            "Force new online metadata update succeeded",
            error=None,
            details={
                "updated_roles": roles_updated,
            },
        )

    def _verify_new_root_signing(
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
            self._verify_new_root_signing(current_root, new_root)

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
        current_keyid = current_root.signed.roles[Timestamp.type].keyids[0]
        new_keyid = new_root.signed.roles[Timestamp.type].keyids[0]
        if current_keyid == new_keyid:
            # online key is not changed, persist the new root
            self._persist(new_root, Root.type)
            logging.info(f"Updating root metadata: {new_root.signed.version}")

        else:
            # We lock this action to stop all new tasks that publish artifacts
            # (`publish_artifacts`) to avoid inconsistencies happening to the
            # TUF clients.
            # It is required lock with LOCK_TARGETS before persisting the root
            # metadata.
            status_lock_targets = False
            try:
                with self._redis.lock(LOCK_TARGETS, timeout=self._timeout):
                    curr_online_key = self._online_key
                    self._online_key = new_root.signed.keys[new_keyid]

                    try:
                        self._run_online_roles_bump(force=True)
                        logging.info("Updating all targets metadata")
                    except Exception as e:
                        # Recover to correct online key state.
                        self._online_key = curr_online_key
                        raise e

                    # root metadata and online key are updated
                    # 1. persist the new root
                    # 2. bump all target roles
                    self._persist(new_root, Root.type)
                    logging.info(
                        f"Updating root metadata: {new_root.signed.version}"
                    )
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

    def metadata_delegation(
        self,
        payload: Dict[str, Any],
        targets: Optional[Metadata[Targets]] = None,
        update_state: Optional[
            Task.update_state
        ] = None,  # It is required (see: app.py)
    ):
        """
        Add delegation roles to the metadata.

        Args:
            payload: contains new metadata
                Supported metadata types: Targets
                example: {"metadata": {"targets": Any}}

            targets: optional argument to pass the current targets metadata
        """
        action = payload.get("action")

        match action:
            case "add":
                delegations: Delegations = Delegations.from_dict(
                    payload["delegations"]
                )
                targets = self._storage_backend.get(Targets.type)
                snapshot = self._storage_backend.get(Snapshot.type)
                success, failed = self._add_metadata_delegation(
                    delegations, targets, persist_targets=True
                )
                # NOTE: this portion of logic below cannot be part of the
                # helper function `_add_metadata_delegation` because while
                # running `_bootstrap_online_roles` targets still not exist
                # and require to be persisted before
                for role in success:
                    if self._validate_threshold(success[role], targets, role):
                        logging.debug(f"role '{role}' uses only online key")
                        snapshot.signed.meta[f"{role}.json"] = MetaFile(
                            success[role].signed.version
                        )
                        self._persist(success[role])

                    else:
                        logging.debug(f"adding role '{role}'for signing")
                        self.write_repository_settings(
                            f"{role.upper()}_SIGNING",
                            success[role].to_dict(),
                        )

            case "delete":
                delegations = payload["delegations"]
                try:
                    status_lock_targets = False
                    with self._redis.lock(LOCK_TARGETS, timeout=self._timeout):
                        success, failed = self._delete_metadata_delegation(
                            payload["delegations"]
                        )
                except redis.exceptions.LockNotOwnedError:
                    if status_lock_targets is False:
                        logging.error(
                            "The task to bump all online roles exceeded the "
                            f"timeout of {self._timeout} seconds."
                        )
                        raise redis.exceptions.LockError(
                            "RSTUF: Task exceed `LOCK_TIMEOUT` "
                            f"({self._timeout} seconds)"
                        )

            case "update":
                delegations: Delegations = Delegations.from_dict(
                    payload["delegations"]
                )
                success, failed = self._update_metadata_delegation(delegations)

            case _:
                raise ValueError(
                    "metadata delegation supports 'add', 'update', 'remove'"
                )

        return self._task_result(
            task=TaskName.METADATA_DELEGATION,
            message="Metadata Delegation Processed",
            error=None,
            details={
                "delegated_roles": [sd for sd in success] or success,
                "failed_roles": failed,
            },
        )

    @staticmethod
    def _validate_signature(
        metadata: Metadata,
        signature: Signature,
        delegator: Optional[Metadata] = None,
        rolename: Optional[str] = Root.type,
    ) -> bool:
        """
        Validate signature over metadata using appropriate delegator.
        If no delegator is passed, the metadata itself is used as delegator.
        """
        if delegator is None:
            delegator = metadata

        keyid = signature.keyid
        keyids: List[str] = []
        if metadata.signed.type == Root.type:
            keyids = delegator.signed.roles.get(rolename).keyids
            key = delegator.signed.keys.get(signature.keyid)

        elif metadata.signed.type == Targets.type:
            keyids = delegator.signed.delegations.roles.get(rolename).keyids
            key = delegator.signed.delegations.keys.get(signature.keyid)

        else:
            raise RepositoryError(
                f"Unsupported metadata type: {metadata.signed.Type}"
            )

        if keyid not in keyids:
            logging.info(f"signature '{keyid}' not authorized")
            return False

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
        metadata: Metadata,
        delegator: Optional[Metadata] = None,
        delegated_role: Optional[str] = Root.type,
    ) -> bool:
        """
        Validate signature threshold using appropriate delegator(s).
        If no delegator is passed, the metadata itself is used as delegator.
        """
        if delegator is None:
            delegator = metadata

        try:
            delegator.verify_delegate(delegated_role, metadata)

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

        # Assert pending signing event exists
        metadata_dict = self._settings.get_fresh(f"{rolename.upper()}_SIGNING")
        if metadata_dict is None:
            msg = f"No signatures pending for {rolename}"
            return _result(False, error=msg)

        metadata = Metadata.from_dict(metadata_dict)

        # If it isn't a "bootstrap" signing event, it must be "update metadata"
        bootstrap_state = self._settings.get_fresh("BOOTSTRAP")
        if metadata.signed.type == Root.type and "signing" in bootstrap_state:
            # Signature and threshold of initial root can only self-validate,
            # there is no "trusted root" at bootstrap time yet.
            if not self._validate_signature(metadata, signature):
                return _result(False, error="Invalid signature")

            metadata.signatures[signature.keyid] = signature
            if not self._validate_threshold(metadata):
                self.write_repository_settings(
                    "ROOT_SIGNING", metadata.to_dict()
                )
                msg = f"Root v{metadata.signed.version} is pending signatures"
                return _result(True, bootstrap=msg)

            bootstrap_task_id = bootstrap_state.split("signing-")[1]
            self._bootstrap_finalize(metadata, bootstrap_task_id)
            return _result(True, bootstrap="Bootstrap Finished")

        elif metadata.signed.type == Root.type:
            # We need the "trusted root" when updating to a new root:
            # - signature could come from a key, which is only in the trusted
            #   root, OR from a key, which is only in the new root
            # - threshold must validate with the threshold of keys as defined
            #   in the trusted root AND as defined in the new root
            trusted_root = self._storage_backend.get("root")
            is_valid_trusted = self._validate_signature(
                metadata, signature, trusted_root
            )
            is_valid_new = self._validate_signature(metadata, signature)

            if not (is_valid_trusted or is_valid_new):
                return _result(False, error="Invalid signature")

            metadata.signatures[signature.keyid] = signature
            trusted_threshold = self._validate_threshold(
                metadata, trusted_root
            )
            new_threshold = self._validate_threshold(metadata)
            if not (trusted_threshold and new_threshold):
                self.write_repository_settings(
                    "ROOT_SIGNING", metadata.to_dict()
                )
                msg = f"Root v{metadata.signed.version} is pending signatures"
                return _result(True, update=msg)

            # Threshold reached -> finalize event
            self._root_metadata_update_finalize(trusted_root, metadata)
            self.write_repository_settings("ROOT_SIGNING", None)
            return _result(True, update="Metadata update finished")

        else:
            targets = self._storage_backend.get(Targets.type)
            is_valid_trusted = self._validate_signature(
                metadata, signature, targets, rolename
            )

            if not is_valid_trusted:
                return _result(False, error="Invalid signature")

            metadata.signatures[signature.keyid] = signature
            trusted_threshold = self._validate_threshold(
                metadata, targets, rolename
            )
            if not trusted_threshold:
                self.write_repository_settings(
                    f"{rolename.upper()}_SIGNING", metadata.to_dict()
                )
                msg = (
                    f"{rolename} v{metadata.signed.version} is "
                    "pending signatures"
                )
                return _result(True, update=msg)

            # Threshold reached -> finalize event
            logging.debug(f"finalizing '{rolename}' metadata signing")
            snapshot = self._storage_backend.get(Snapshot.type)
            snapshot.signed.meta[f"{rolename}.json"] = MetaFile(
                version=metadata.signed.version,
            )
            self._bump_and_persist(snapshot, Snapshot.type)
            self._update_timestamp(snapshot.signed.version)
            self._persist(metadata, rolename)
            self.write_repository_settings(f"{rolename.upper()}_SIGNING", None)
            return _result(True, update=f"Role {rolename} signing complete")

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
