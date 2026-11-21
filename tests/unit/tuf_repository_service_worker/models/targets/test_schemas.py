# SPDX-FileCopyrightText: 2023-2025 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT
import datetime

from repository_service_tuf_worker.models.targets.schemas import (
    RSTUFTargetFileCreate,
    RSTUFTargetRoleCreate,
    TargetAction,
)


class TestSchemas:
    def test_rstuf_target_role_create(self):
        role_create = RSTUFTargetRoleCreate(
            rolename="test-role",
            version=1,
            expires=datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc),
        )
        assert role_create.rolename == "test-role"
        assert role_create.version == 1
        assert role_create.expires == datetime.datetime(
            2027, 1, 1, tzinfo=datetime.timezone.utc
        )
        assert role_create.active is True
        assert isinstance(role_create.last_update, datetime.datetime)

    def test_rstuf_target_file_create(self):
        file_create = RSTUFTargetFileCreate(
            path="file.txt",
            info={"length": 123},
            published=False,
            action=TargetAction.ADD,
        )
        assert file_create.path == "file.txt"
        assert file_create.info == {"length": 123}
        assert file_create.published is False
        assert file_create.action == TargetAction.ADD
        assert isinstance(file_create.last_update, datetime.datetime)
