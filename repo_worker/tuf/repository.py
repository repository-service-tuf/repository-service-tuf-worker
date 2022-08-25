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


from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple

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

BIN = "bin"
BINS = "bins"
SPEC_VERSION: str = ".".join(SPECIFICATION_VERSION)


class MetadataRepository:
    """
    A repository service to create and maintain TUF role metadata.
    """

    def __init__(self, storage_service, keyvault_service, settings):
        self._storage_backend = storage_service
        self._key_storage_backend = keyvault_service
        self._settings = settings

    def _is_initialized(self) -> bool:
        """
        Returns True if any top-level role metadata exists, Falseotherwise.
        """
        try:
            if any(role for role in TOP_LEVEL_ROLE_NAMES if self._load(role)):
                return True
        except StorageError:
            pass

        return False

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
        # FIXME: Review calls to _bump_expiry. Currently, it is called in
        # every update-sign-persist cycle.
        # PEP 458 is unspecific about when to bump expiration, e.g. in the
        # course of a consistent snapshot only 'timestamp' is bumped:
        # https://www.python.org/dev/peps/pep-0458/#producing-consistent-snapshots
        role.signed.expires = datetime.now().replace(
            microsecond=0
        ) + timedelta(days=int(self._settings[f"{expiry_id}_EXPIRATION"]))

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

    def add_initial_metadata(
        self, metadata: Dict[str, Dict[str, Any]]
    ) -> bool:
        if self._is_initialized() is True:
            return False

        r = redis.StrictRedis.from_url("redis://redis")
        with r.lock("TUF_REPO_LOCK"):
            for role_name, data in metadata.items():
                metadata = Metadata.from_dict(data)
                metadata.to_file(
                    role_name, JSONSerializer(), self._storage_backend
                )

        return True

    def add_targets(self, targets):
        """
        Updates 'bins' roles metadata, assigning each passed target to the
        correct bin.

        Assignment is based on the hash prefix of the target file path. All
        metadata is signed and persisted using the configured key and storage
        services.

        Updating 'bins' also updates 'snapshot' and 'timestamp'.
        """
        r = redis.StrictRedis.from_url("redis://redis")
        with r.lock("TUF_REPO_LOCK"):
            # Group target files by responsible 'bins' roles
            bin = self._load(BIN)
            bin_succinct_roles = bin.signed.delegations.succinct_roles
            bin_target_groups = {}
            for target in targets:
                bins_name = bin_succinct_roles.get_role_for_target(
                    target["path"]
                )

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
                bins_role = self._load(bins_name)

                for target_file in target_files:
                    bins_role.signed.targets[target_file.path] = target_file

                self._bump_expiry(bins_role, BINS)
                self._bump_version(bins_role)
                self._sign(bins_role, BINS)
                self._persist(bins_role, bins_name)

                targets_meta.append((bins_name, bins_role.signed.version))

            self._update_timestamp(self._update_snapshot(targets_meta))

    def bump_bins_roles(self):
        """
        Bumps version and expiration date of 'bins' role metadata (multiple).

        The version numbers are incremented by one, the expiration dates are
        renewed using a configured expiration interval, and the metadata is
        signed and persisted using the configured key and storage services.

        Updating 'bins' also updates 'snapshot' and 'timestamp'.
        """
        hash_bins = self._get_hash_bins()
        targets_meta = []
        for bins_name, _ in hash_bins.generate():
            bins_role = self._load(bins_name)

            self._bump_expiry(bins_role, BINS)
            self._bump_version(bins_role)
            self._sign(bins_role, BINS)
            self._persist(bins_role, bins_name)

            targets_meta.append((bins_name, bins_role.signed.version))

        self._update_timestamp(self._update_snapshot(targets_meta))

    def bump_snapshot(self):
        """
        Bumps version and expiration date of TUF 'snapshot' role metadata.

        The version number is incremented by one, the expiration date renewed
        using a configured expiration interval, and the metadata is signed and
        persisted using the configured key and storage services.

        Updating 'snapshot' also updates 'timestamp'.
        """
        self._update_timestamp(self._update_snapshot([]))
