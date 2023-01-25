# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT
from datetime import datetime
from typing import Any, Dict, List, Tuple

from sqlalchemy.orm import Session

from repository_service_tuf_worker.models.targets import models, schemas


def create(db: Session, target: schemas.TargetsCreate):
    """
    Create a new Target entry in the DB.
    """
    db_target = models.RSTUFTargets(**target.dict())
    db.add(db_target)
    db.commit()
    db.refresh(db_target)

    return db_target


def read_unpublished_rolenames(db: Session) -> Tuple[bool, str]:
    """
    Read delegated role names that contains unpublished Targets.
    """
    return (
        db.query(models.RSTUFTargets.published, models.RSTUFTargets.rolename)
        .filter(
            models.RSTUFTargets.published == False,  # noqa
        )
        .order_by(models.RSTUFTargets.rolename)
        .distinct()
        .all()
    )


def read_by_path(db: Session, path: str) -> models.RSTUFTargets:
    """
    Read the Target based in the path (unique value).
    """
    return (
        db.query(models.RSTUFTargets)
        .filter(models.RSTUFTargets.path == path)
        .first()
    )


def read_by_rolename(db: Session, rolename: str) -> List[models.RSTUFTargets]:
    """
    Read all Targets by the delegated role name.
    """
    return (
        db.query(models.RSTUFTargets)
        .filter(
            models.RSTUFTargets.rolename == rolename,
        )
        .all()
    )


def read_unpublished_by_rolename(
    db: Session, rolename: str
) -> List[models.RSTUFTargets]:
    """
    Read all unpublished Targets by a delegated role name.
    """
    return (
        db.query(
            models.RSTUFTargets,
        )
        .filter(
            models.RSTUFTargets.published == False,  # noqa
            models.RSTUFTargets.rolename == rolename,
        )
        .all()
    )


def read_all_add_by_rolename(
    db: Session, rolename: str
) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Read all delegated role names `path` and `info` that contains targets
    with action 'ADD'.
    """
    return (
        db.query(
            models.RSTUFTargets.path,
            models.RSTUFTargets.info,
        )
        .filter(
            models.RSTUFTargets.rolename == rolename,
            models.RSTUFTargets.action == schemas.TargetAction.ADD,
        )
        .all()
    )


def update(
    db: Session,
    target: models.RSTUFTargets,
    new_path: str,
    new_info: Dict[str, Any],
):
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


def update_to_published(
    db: Session, target: models.RSTUFTargets
) -> models.RSTUFTargets:
    """
    Update Target to `published` to `True`.
    """
    target.published = True
    target.last_update = datetime.now()
    db.add(target)
    db.commit()
    db.refresh(target)

    return target


def update_action_remove(
    db: Session, target: models.RSTUFTargets
) -> models.RSTUFTargets:
    """
    Update Target to `action` to `REMOVE`.
    """
    target.published = False
    target.action = schemas.TargetAction.REMOVE
    target.last_update = datetime.now()
    db.add(target)
    db.commit()
    db.refresh(target)

    return target
