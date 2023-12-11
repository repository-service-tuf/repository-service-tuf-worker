# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
import datetime

import pretend

from repository_service_tuf_worker.models.targets import crud


class TestCrud:
    def test_create_roles(self, monkeypatch):
        monkeypatch.setattr(
            crud.models,
            "RSTUFTargetRoles",
            pretend.call_recorder(lambda *a, **kw: "test_target_roles"),
        )
        mocked_db = pretend.stub(
            add_all=pretend.call_recorder(lambda *a: None),
            commit=pretend.call_recorder(lambda: None),
        )
        test_target = crud.schemas.RSTUFTargetRoleCreate(
            rolename="bins-0",
            version=1,
        )
        test_result = crud.create_roles(mocked_db, [test_target])
        assert test_result == ["test_target_roles"]
        assert crud.models.RSTUFTargetRoles.calls == [
            pretend.call(
                rolename=test_target.rolename, version=test_target.version
            )
        ]
        assert mocked_db.add_all.calls == [pretend.call(["test_target_roles"])]
        assert mocked_db.commit.calls == [pretend.call()]

    def test_create_file(self, monkeypatch):
        monkeypatch.setattr(
            crud.models,
            "RSTUFTargetFiles",
            pretend.call_recorder(lambda *a, **kw: "test_target_files"),
        )
        mocked_db = pretend.stub(
            add=pretend.call_recorder(lambda *a: None),
            commit=pretend.call_recorder(lambda: None),
            refresh=pretend.call_recorder(lambda *a: None),
        )
        last_updated = datetime.datetime.now()
        test_target_file = crud.schemas.RSTUFTargetFileCreate(
            path="file1.tar.gz",
            info={"info": {"k": "v"}},
            published=False,
            action=crud.schemas.TargetAction.ADD,
            last_update=last_updated,
        )
        test_target_role = pretend.stub(id=256)

        test_result = crud.create_file(
            mocked_db, test_target_file, test_target_role
        )
        assert test_result == "test_target_files"
        assert crud.models.RSTUFTargetFiles.calls == [
            pretend.call(
                path=test_target_file.path,
                info=test_target_file.info,
                published=False,
                action=crud.schemas.TargetAction.ADD,
                last_update=last_updated,
                targets_role=256,
            )
        ]
        assert mocked_db.add.calls == [pretend.call("test_target_files")]
        assert mocked_db.commit.calls == [pretend.call()]
        assert mocked_db.refresh.calls == [pretend.call("test_target_files")]

    def test_read_roles_with_unpublished_files(self, monkeypatch):
        monkeypatch.setattr(
            crud.models, "RSTUFTargetFiles", pretend.stub(published=False)
        )
        monkeypatch.setattr(
            crud.models, "RSTUFTargetRoles", pretend.stub(rolename="bins-0")
        )
        mocked_all = pretend.stub(
            all=pretend.call_recorder(
                lambda: [(False, "bins-e"), (False, "bins-3")]
            )
        )
        mocked_distinct = pretend.stub(
            distinct=pretend.call_recorder(lambda: mocked_all)
        )
        mocked_order_by = pretend.stub(
            order_by=pretend.call_recorder(lambda *a: mocked_distinct)
        )
        mocked_filter = pretend.stub(
            filter=pretend.call_recorder(lambda *a: mocked_order_by)
        )
        mocked_join = pretend.stub(
            join=pretend.call_recorder(lambda *a: mocked_filter)
        )
        mocked_db = pretend.stub(
            query=pretend.call_recorder(lambda *a: mocked_join)
        )

        test_result = crud.read_roles_with_unpublished_files(mocked_db)

        assert test_result == [(False, "bins-e"), (False, "bins-3")]
        assert mocked_db.query.calls == [pretend.call("bins-0")]
        assert mocked_join.join.calls == [
            pretend.call(crud.models.RSTUFTargetFiles)
        ]
        assert mocked_filter.filter.calls == [pretend.call(True)]
        assert mocked_order_by.order_by.calls == [pretend.call("bins-0")]
        assert mocked_distinct.distinct.calls == [pretend.call()]
        assert mocked_all.all.calls == [pretend.call()]

    def test_read_file_by_path(self, monkeypatch):
        monkeypatch.setattr(
            crud.models, "RSTUFTargetFiles", pretend.stub(path="file1.tar.gz")
        )
        mocked_first = pretend.stub(
            first=pretend.call_recorder(lambda: crud.models.RSTUFTargetFiles)
        )
        mocked_filter = pretend.stub(
            filter=pretend.call_recorder(lambda *a: mocked_first)
        )
        mocked_db = pretend.stub(
            query=pretend.call_recorder(lambda *a: mocked_filter)
        )

        test_result = crud.read_file_by_path(mocked_db, "file1.tar.gz")

        assert test_result == crud.models.RSTUFTargetFiles
        assert mocked_db.query.calls == [
            pretend.call(crud.models.RSTUFTargetFiles)
        ]
        assert mocked_filter.filter.calls == [pretend.call(True)]
        assert mocked_first.first.calls == [pretend.call()]

    def test_read_role_by_rolename(self, monkeypatch):
        monkeypatch.setattr(
            crud.models, "RSTUFTargetRoles", pretend.stub(rolename="bins-0")
        )
        mocked_first = pretend.stub(
            first=pretend.call_recorder(lambda: [crud.models.RSTUFTargetRoles])
        )
        mocked_filter = pretend.stub(
            filter=pretend.call_recorder(lambda *a: mocked_first)
        )
        mocked_db = pretend.stub(
            query=pretend.call_recorder(lambda *a: mocked_filter)
        )

        test_result = crud.read_role_by_rolename(mocked_db, "bins-0")

        assert test_result == [crud.models.RSTUFTargetRoles]
        assert mocked_db.query.calls == [
            pretend.call(crud.models.RSTUFTargetRoles)
        ]
        assert mocked_filter.filter.calls == [pretend.call(True)]
        assert mocked_first.first.calls == [pretend.call()]

    def test_read_all_roles(self):
        mocked_all = pretend.stub(
            all=pretend.call_recorder(lambda: [crud.models.RSTUFTargetRoles])
        )
        mocked_db = pretend.stub(
            query=pretend.call_recorder(lambda *a: mocked_all)
        )
        test_result = crud.read_all_roles(mocked_db)
        assert test_result == [crud.models.RSTUFTargetRoles]
        assert mocked_db.query.calls == [
            pretend.call(crud.models.RSTUFTargetRoles)
        ]
        assert mocked_all.all.calls == [pretend.call()]

    def test_read_roles_joint_files(self):
        crud.models.RSTUFTargetRoles = pretend.stub(
            rolename=pretend.stub(in_=pretend.call_recorder(lambda *a: True))
        )
        mocked_all = pretend.stub(
            all=pretend.call_recorder(lambda: [crud.models.RSTUFTargetRoles])
        )
        mocked_filter = pretend.stub(
            filter=pretend.call_recorder(lambda *a: mocked_all)
        )
        mocked_join = pretend.stub(
            join=pretend.call_recorder(lambda *a: mocked_filter)
        )
        mocked_db = pretend.stub(
            query=pretend.call_recorder(lambda *a: mocked_join)
        )

        test_result = crud.read_roles_joint_files(mocked_db, "bins-0")

        assert test_result == [crud.models.RSTUFTargetRoles]
        assert mocked_db.query.calls == [
            pretend.call(crud.models.RSTUFTargetRoles)
        ]
        assert mocked_filter.filter.calls == [pretend.call(True)]
        assert crud.models.RSTUFTargetRoles.rolename.in_.calls == [
            pretend.call("bins-0")
        ]
        assert mocked_join.join.calls == [
            pretend.call(crud.models.RSTUFTargetFiles)
        ]
        assert mocked_all.all.calls == [pretend.call()]

    def test_update_file_path_and_info(self, monkeypatch):
        mocked_db = pretend.stub(
            add=pretend.call_recorder(lambda *a: None),
            commit=pretend.call_recorder(lambda: None),
            refresh=pretend.call_recorder(lambda *a: None),
        )

        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.models.targets.crud.datetime",
            fake_datetime,
        )

        test_target_file = crud.schemas.RSTUFTargetFileCreate(
            path="file1.tar.gz",
            info={"info": {"k": "v"}},
            rolename="bins-0",
            published=False,
            action=crud.schemas.TargetAction.ADD,
        )

        new_path = "file1_v2.tar.gz"
        new_info = {"info": {"new_k": "new_v"}}

        test_result = crud.update_file_path_and_info(
            mocked_db, test_target_file, new_path, new_info
        )

        assert test_result.path == new_path
        assert test_result.info == new_info
        assert test_result.last_update == fake_time
        assert test_result.action == crud.schemas.TargetAction.ADD
        assert test_result.published is False
        assert mocked_db.add.calls == [pretend.call(test_target_file)]
        assert mocked_db.commit.calls == [pretend.call()]
        assert mocked_db.refresh.calls == [pretend.call(test_target_file)]
        assert fake_datetime.now.calls == [pretend.call()]

    def test_update_files_to_published(self, monkeypatch):
        test_targets = ["path/file1", "path.file2"]
        monkeypatch.setattr(
            crud.models,
            "RSTUFTargetFiles",
            pretend.stub(
                path=pretend.stub(
                    in_=pretend.call_recorder(lambda *a: test_targets)
                ),
                published="published",
                last_update="last_update",
            ),
        )
        mocked_update = pretend.stub(
            update=pretend.call_recorder(
                lambda *a: crud.models.RSTUFTargetRoles
            )
        )
        mocked_filter = pretend.stub(
            filter=pretend.call_recorder(lambda *a: mocked_update)
        )
        mocked_db = pretend.stub(
            query=pretend.call_recorder(lambda *a: mocked_filter),
            commit=pretend.call_recorder(lambda: None),
        )
        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.models.targets.crud.datetime",
            fake_datetime,
        )

        test_result = crud.update_files_to_published(mocked_db, test_targets)

        assert test_result is None
        assert mocked_db.query.calls == [
            pretend.call(crud.models.RSTUFTargetFiles)
        ]
        assert crud.models.RSTUFTargetFiles.path.in_.calls == [
            pretend.call(test_targets)
        ]
        assert mocked_filter.filter.calls == [
            pretend.call(False, test_targets)
        ]
        assert mocked_update.update.calls == [
            pretend.call({"published": True, "last_update": fake_time})
        ]
        assert mocked_db.commit.calls == [pretend.call()]
        assert fake_datetime.now.calls == [pretend.call()]

    def test_update_roles_version(self, monkeypatch):
        monkeypatch.setattr(
            crud.models,
            "RSTUFTargetRoles",
            pretend.stub(
                id=pretend.stub(in_=pretend.call_recorder(lambda *a: 4)),
                version=19,
                last_update="last_update",
            ),
        )
        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.models.targets.crud.datetime",
            fake_datetime,
        )
        mocked_update = pretend.stub(
            update=pretend.call_recorder(
                lambda *a: crud.models.RSTUFTargetRoles
            )
        )
        mocked_filter = pretend.stub(
            filter=pretend.call_recorder(lambda *a: mocked_update)
        )
        mocked_db = pretend.stub(
            query=pretend.call_recorder(lambda *a: mocked_filter),
            commit=pretend.call_recorder(lambda: None),
        )
        test_result = crud.update_roles_version(mocked_db, [4])
        assert test_result is None
        assert mocked_db.query.calls == [
            pretend.call(crud.models.RSTUFTargetRoles)
        ]
        assert crud.models.RSTUFTargetRoles.id.in_.calls == [pretend.call([4])]
        assert mocked_filter.filter.calls == [pretend.call(4)]
        assert mocked_update.update.calls == [
            pretend.call(
                {
                    19: crud.models.RSTUFTargetRoles.version + 1,
                    "last_update": fake_time,
                }
            )
        ]
        assert mocked_db.commit.calls == [pretend.call()]
        assert fake_datetime.now.calls == [pretend.call()]

    def test_update_file_action_to_remove(self, monkeypatch):
        mocked_db = pretend.stub(
            add=pretend.call_recorder(lambda *a: None),
            commit=pretend.call_recorder(lambda: None),
            refresh=pretend.call_recorder(lambda *a: None),
        )

        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.models.targets.crud.datetime",
            fake_datetime,
        )

        test_target = crud.schemas.RSTUFTargetFileCreate(
            path="file1.tar.gz",
            info={"info": {"k": "v"}},
            rolename="bins-0",
            published=True,
            action=crud.schemas.TargetAction.ADD,
        )

        test_result = crud.update_file_action_to_remove(mocked_db, test_target)

        assert test_result.path == "file1.tar.gz"
        assert test_result.info == {"info": {"k": "v"}}
        assert test_result.action == crud.schemas.TargetAction.REMOVE
        assert test_result.last_update == fake_time
        assert test_result.published is False
        assert mocked_db.add.calls == [pretend.call(test_target)]
        assert mocked_db.commit.calls == [pretend.call()]
        assert mocked_db.refresh.calls == [pretend.call(test_target)]
        assert fake_datetime.now.calls == [pretend.call()]
