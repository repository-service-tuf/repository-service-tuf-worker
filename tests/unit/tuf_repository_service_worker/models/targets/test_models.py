# SPDX-FileCopyrightText: 2023-2025 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT
import datetime

from repository_service_tuf_worker.models.targets.models import (
    RSTUFTargetFiles,
    RSTUFTargetRoles,
)
from repository_service_tuf_worker.models.targets.schemas import TargetAction


class TestModels:
    def test_rstuf_target_roles(self):
        role = RSTUFTargetRoles(
            rolename="test-role",
            version=1,
            expires=datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc),
            active=True,
        )
        assert role.rolename == "test-role"
        assert role.version == 1
        assert role.expires == datetime.datetime(
            2027, 1, 1, tzinfo=datetime.timezone.utc
        )
        assert role.active is True

    def test_rstuf_target_files(self):
        file_obj = RSTUFTargetFiles(
            path="file.txt",
            info={"length": 123},
            published=False,
            action=TargetAction.ADD,
        )
        assert file_obj.path == "file.txt"
        assert file_obj.info == {"length": 123}
        assert file_obj.published is False
        assert file_obj.action == TargetAction.ADD
