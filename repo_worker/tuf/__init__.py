import enum

from repo_worker.tuf.interfaces import IKeyVault, IStorage, ServiceSettings
from repo_worker.tuf.repository import (
    TOP_LEVEL_ROLE_NAMES,
    DelegatedRole,
    Key,
    Metadata,
    MetadataRepository,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)


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


__all__ = [
    IKeyVault,
    IStorage,
    Metadata,
    MetadataRepository,
    DelegatedRole,
    TOP_LEVEL_ROLE_NAMES,
    MetadataRepository,
    Timestamp,
    Targets.__name__,
    TargetFile,
    ServiceSettings,
    Key,
]
