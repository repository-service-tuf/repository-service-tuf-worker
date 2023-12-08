# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from repository_service_tuf_worker.models.targets import models, schemas


def create_roles(
    db: Session, target_roles: List[schemas.RSTUFTargetRoleCreate]
) -> List[models.RSTUFTargetRoles]:
    """
    Create a new set of Target roles in the DB.
    """
    db_delegated_roles_objects = [
        models.RSTUFTargetRoles(**role.dict()) for role in target_roles
    ]
    db.add_all(db_delegated_roles_objects)
    db.commit()

    return db_delegated_roles_objects


def create_file(
    db: Session,
    target_file: schemas.RSTUFTargetFileCreate,
    target_role: models.RSTUFTargetRoles,
) -> models.RSTUFTargetFiles:
    """
    Create a new Target file in the DB.
    """
    target_file = models.RSTUFTargetFiles(
        **target_file.dict(), targets_role=target_role.id
    )
    db.add(target_file)
    db.commit()
    db.refresh(target_file)

    return target_file


def read_roles_with_unpublished_files(db: Session) -> List[Tuple[str]]:
    """
    Read Target Roles containing unpublished Target Files.
    """
    return (
        db.query(
            models.RSTUFTargetRoles.rolename,
        )
        .join(models.RSTUFTargetFiles)
        .filter(
            models.RSTUFTargetFiles.published == False,  # noqa
        )
        .order_by(models.RSTUFTargetRoles.rolename)
        .distinct()
        .all()
    )


def read_file_by_path(
    db: Session, path: str
) -> Optional[models.RSTUFTargetFiles]:
    """
    Read a Target File by a given path (unique value).
    """
    return (
        db.query(models.RSTUFTargetFiles)
        .filter(models.RSTUFTargetFiles.path == path)
        .first()
    )


def read_role_by_rolename(
    db: Session, rolename: str
) -> Optional[models.RSTUFTargetRoles]:
    """
    Read a Target role by a given role name.
    """
    return (
        db.query(models.RSTUFTargetRoles)
        .filter(
            models.RSTUFTargetRoles.rolename == rolename,
        )
        .first()
    )


def read_all_roles(db: Session) -> List[models.RSTUFTargetRoles]:
    """
    Read a all Target bin roles.
    """
    return db.query(models.RSTUFTargetRoles).all()


def read_roles_joint_files(
    db: Session, rolenames: List[str]
) -> List[models.RSTUFTargetRoles]:
    """
    Read all roles with a name in 'rolenames' joining with
    RSTUFTargetFiles database in the process.
    """
    return (
        db.query(
            models.RSTUFTargetRoles,
        )
        .join(models.RSTUFTargetFiles)
        .filter(
            models.RSTUFTargetRoles.rolename.in_(rolenames),
        )
        .all()
    )


def update_file_path_and_info(
    db: Session,
    target: models.RSTUFTargetFiles,
    new_path: str,
    new_info: Dict[str, Any],
) -> models.RSTUFTargetFiles:
    """
    Update a Target (`path` and `info`)
    """
    target.action = schemas.TargetAction.ADD
    target.published = False
    target.path = new_path
    target.info = new_info
    target.last_update = datetime.now()
    db.add(target)
    db.commit()
    db.refresh(target)

    return target


def update_files_to_published(db: Session, paths: List[str]) -> None:
    """
    Update Target Files `published` attribute to `True`.
    """

    db.query(models.RSTUFTargetFiles).filter(
        models.RSTUFTargetFiles.published == False,  # noqa
        models.RSTUFTargetFiles.path.in_(paths),
    ).update(
        {
            models.RSTUFTargetFiles.published: True,
            models.RSTUFTargetFiles.last_update: datetime.now(),
        }
    )
    db.commit()


def update_roles_version(db: Session, bins_ids: List[int]) -> None:
    """
    Update Target roles version +1.
    """
    db.query(models.RSTUFTargetRoles).filter(
        models.RSTUFTargetRoles.id.in_(bins_ids)
    ).update(
        {
            models.RSTUFTargetRoles.version: models.RSTUFTargetRoles.version
            + 1,
            models.RSTUFTargetRoles.last_update: datetime.now(),
        }
    )
    db.commit()


def update_file_action_to_remove(
    db: Session, target: models.RSTUFTargetFiles
) -> models.RSTUFTargetFiles:
    """
    Update Target File `action` attribute to `REMOVE`.
    """
    target.published = False
    target.action = schemas.TargetAction.REMOVE
    target.last_update = datetime.now()
    db.add(target)
    db.commit()
    db.refresh(target)

    return target
