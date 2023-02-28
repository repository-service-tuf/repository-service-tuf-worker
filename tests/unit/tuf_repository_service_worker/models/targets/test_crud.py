# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
import datetime

import pretend

from repository_service_tuf_worker.models.targets import crud


class TestTargetsCrud:
    def test_create(self):
        crud.models.RSTUFTargets = pretend.call_recorder(
            lambda *a, **kw: "fake_db_target"
        )
        mocked_db = pretend.stub(
            add=pretend.call_recorder(lambda *a: None),
            commit=pretend.call_recorder(lambda: None),
            refresh=pretend.call_recorder(lambda *a: None),
        )
        test_target = crud.schemas.TargetsCreate(
            path="file1.tar.gz",
            info={"info": {"k": "v"}},
            rolename="bins-0",
            published=False,
            action=crud.schemas.TargetAction.ADD,
        )

        test_result = crud.create(mocked_db, test_target)
        assert test_result == "fake_db_target"
        assert mocked_db.add.calls == [pretend.call("fake_db_target")]
        assert mocked_db.commit.calls == [pretend.call()]
        assert mocked_db.refresh.calls == [pretend.call("fake_db_target")]

    def test_read_unpublished_rolenames(self):

        crud.models.RSTUFTargets = pretend.stub(
            published=False, rolename="all-bins"
        )

        mocked_all = pretend.stub(
            all=pretend.call_recorder(
                lambda: [(False, "bin-e"), (False, "bin-3")]
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
        mocked_db = pretend.stub(
            query=pretend.call_recorder(lambda *a: mocked_filter)
        )

        test_result = crud.read_unpublished_rolenames(mocked_db)

        assert test_result == [(False, "bin-e"), (False, "bin-3")]
        assert mocked_db.query.calls == [pretend.call(False, "all-bins")]
        assert mocked_filter.filter.calls == [pretend.call(True)]
        assert mocked_order_by.order_by.calls == [pretend.call("all-bins")]
        assert mocked_distinct.distinct.calls == [pretend.call()]
        assert mocked_all.all.calls == [pretend.call()]

    def test_read_by_path(self):

        crud.models.RSTUFTargets = pretend.stub(path="file1.tar.gz")
        mocked_first = pretend.stub(
            first=pretend.call_recorder(lambda: crud.models.RSTUFTargets)
        )
        mocked_filter = pretend.stub(
            filter=pretend.call_recorder(lambda *a: mocked_first)
        )
        mocked_db = pretend.stub(
            query=pretend.call_recorder(lambda *a: mocked_filter)
        )

        test_result = crud.read_by_path(mocked_db, "file1.tar.gz")

        assert test_result == crud.models.RSTUFTargets
        assert mocked_db.query.calls == [
            pretend.call(crud.models.RSTUFTargets)
        ]
        assert mocked_filter.filter.calls == [pretend.call(True)]
        assert mocked_first.first.calls == [pretend.call()]

    def test_read_by_rolename(self):

        crud.models.RSTUFTargets = pretend.stub(rolename="bin-0")
        mocked_all = pretend.stub(
            all=pretend.call_recorder(lambda: [crud.models.RSTUFTargets])
        )
        mocked_filter = pretend.stub(
            filter=pretend.call_recorder(lambda *a: mocked_all)
        )
        mocked_db = pretend.stub(
            query=pretend.call_recorder(lambda *a: mocked_filter)
        )

        test_result = crud.read_by_rolename(mocked_db, "bin-0")

        assert test_result == [crud.models.RSTUFTargets]
        assert mocked_db.query.calls == [
            pretend.call(crud.models.RSTUFTargets)
        ]
        assert mocked_filter.filter.calls == [pretend.call(True)]
        assert mocked_all.all.calls == [pretend.call()]

    def test_read_unpublished_by_rolename(self):

        crud.models.RSTUFTargets = pretend.stub(
            published=False, rolename="bin-0"
        )
        mocked_all = pretend.stub(
            all=pretend.call_recorder(lambda: [crud.models.RSTUFTargets])
        )
        mocked_filter = pretend.stub(
            filter=pretend.call_recorder(lambda *a: mocked_all)
        )
        mocked_db = pretend.stub(
            query=pretend.call_recorder(lambda *a: mocked_filter)
        )

        test_result = crud.read_unpublished_by_rolename(mocked_db, "bin-0")

        assert test_result == [crud.models.RSTUFTargets]
        assert mocked_db.query.calls == [
            pretend.call(crud.models.RSTUFTargets)
        ]
        assert mocked_filter.filter.calls == [pretend.call(True, True)]
        assert mocked_all.all.calls == [pretend.call()]

    def test_read_all_add_by_rolename(self):

        crud.models.RSTUFTargets = pretend.stub(
            path="file2.tar.gz",
            info={"info": {"k": "v"}},
            rolename="bin-0",
            action=crud.schemas.TargetAction.ADD,
        )
        mocked_all = pretend.stub(
            all=pretend.call_recorder(
                lambda: [
                    (
                        crud.models.RSTUFTargets.path,
                        crud.models.RSTUFTargets.info,
                    )
                ]
            )
        )
        mocked_filter = pretend.stub(
            filter=pretend.call_recorder(lambda *a: mocked_all)
        )
        mocked_db = pretend.stub(
            query=pretend.call_recorder(lambda *a: mocked_filter)
        )

        test_result = crud.read_all_add_by_rolename(mocked_db, "bin-0")

        assert test_result == [("file2.tar.gz", {"info": {"k": "v"}})]
        assert mocked_db.query.calls == [
            pretend.call(
                crud.models.RSTUFTargets.path,
                crud.models.RSTUFTargets.info,
            )
        ]
        assert mocked_filter.filter.calls == [pretend.call(True, True)]
        assert mocked_all.all.calls == [pretend.call()]

    def test_update(self, monkeypatch):

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

        test_target = crud.schemas.TargetsCreate(
            path="file1.tar.gz",
            info={"info": {"k": "v"}},
            rolename="bins-0",
            published=False,
            action=crud.schemas.TargetAction.ADD,
        )

        new_path = "file1_v2.tar.gz"
        new_info = {"info": {"new_k": "new_v"}}

        test_result = crud.update(mocked_db, test_target, new_path, new_info)

        assert test_result.path == new_path
        assert test_result.info == new_info
        assert test_result.last_update == fake_time
        assert test_result.action == crud.schemas.TargetAction.ADD
        assert test_result.published is False
        assert mocked_db.add.calls == [pretend.call(test_target)]
        assert mocked_db.commit.calls == [pretend.call()]
        assert mocked_db.refresh.calls == [pretend.call(test_target)]
        assert fake_datetime.now.calls == [pretend.call()]

    def test_update_to_published(self, monkeypatch):
        test_targets = ["path/file1", "path.file2"]
        crud.models.RSTUFTargets = pretend.stub(
            path=pretend.stub(
                in_=pretend.call_recorder(lambda *a: test_targets)
            ),
            published="published",
            last_update="last_update",
        )
        mocked_update = pretend.stub(
            update=pretend.call_recorder(lambda *a: crud.models.RSTUFTargets)
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

        test_result = crud.update_to_published(mocked_db, test_targets)

        assert test_result is None
        assert mocked_db.query.calls == [
            pretend.call(crud.models.RSTUFTargets)
        ]
        assert mocked_filter.filter.calls == [pretend.call(test_targets)]
        assert mocked_update.update.calls == [
            pretend.call({"published": True, "last_update": fake_time})
        ]
        assert mocked_db.commit.calls == [pretend.call()]
        assert fake_datetime.now.calls == [pretend.call()]

    def test_update_action_remove(self, monkeypatch):

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

        test_target = crud.schemas.TargetsCreate(
            path="file1.tar.gz",
            info={"info": {"k": "v"}},
            rolename="bins-0",
            published=True,
            action=crud.schemas.TargetAction.ADD,
        )

        test_result = crud.update_action_remove(mocked_db, test_target)

        assert test_result.path == "file1.tar.gz"
        assert test_result.info == {"info": {"k": "v"}}
        assert test_result.action == crud.schemas.TargetAction.REMOVE
        assert test_result.last_update == fake_time
        assert test_result.published is False
        assert mocked_db.add.calls == [pretend.call(test_target)]
        assert mocked_db.commit.calls == [pretend.call()]
        assert mocked_db.refresh.calls == [pretend.call(test_target)]
        assert fake_datetime.now.calls == [pretend.call()]
