# SPDX-FileCopyrightText: 2023-2025 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
from datetime import datetime, timedelta, timezone

import pytest

from repository_service_tuf_worker.models.targets import models, schemas


def test_target_role_create_last_update_is_set_at_creation():
    before = datetime.now(timezone.utc)
    role = schemas.RSTUFTargetRoleCreate(
        rolename="bins-0",
        version=1,
        expires=before + timedelta(days=1),
    )
    after = datetime.now(timezone.utc)

    assert before <= role.last_update <= after


def test_target_file_create_last_update_is_set_at_creation():
    before = datetime.now(timezone.utc)
    target_file = schemas.RSTUFTargetFileCreate(
        path="file.tar.gz",
        info={"length": 1},
        published=False,
        action=schemas.TargetAction.ADD,
    )
    after = datetime.now(timezone.utc)

    assert before <= target_file.last_update <= after


def test_target_role_create_last_update_can_be_given():
    last_update = datetime(2020, 1, 1, tzinfo=timezone.utc)
    role = schemas.RSTUFTargetRoleCreate(
        rolename="bins-0",
        version=1,
        expires=last_update + timedelta(days=1),
        last_update=last_update,
    )

    assert role.last_update == last_update


@pytest.mark.parametrize(
    "model", [models.RSTUFTargetFiles, models.RSTUFTargetRoles]
)
def test_last_update_default_is_evaluated_for_each_row(model):
    default = model.__table__.c.last_update.default

    before = datetime.now(timezone.utc)
    last_update = default.arg(None)
    after = datetime.now(timezone.utc)

    assert before <= last_update <= after
