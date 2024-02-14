# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import datetime
from contextlib import contextmanager
from math import log
from typing import Iterator

import pretend
import pytest
from celery.exceptions import ChordError
from celery.result import states
from securesystemslib.exceptions import StorageError
from tuf.api.metadata import (
    DelegatedRole,
    Delegations,
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    SuccinctRoles,
    Targets,
    Timestamp,
)

from repository_service_tuf_worker import Dynaconf, repository
from repository_service_tuf_worker.models import targets_schema


class TestMetadataRepository:
    def test_basic_init(self, monkeypatch):
        fake_configure = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(
            "repository_service_tuf_worker.services.keyvault.local.LocalKeyVault.configure",  # noqa
            fake_configure,
        )
        test_repo = repository.MetadataRepository()
        assert isinstance(test_repo, repository.MetadataRepository) is True

    def test_init_with_no_keyvault(self, monkeypatch):
        settings = repository.get_worker_settings()
        del settings.KEYVAULT_BACKEND

        monkeypatch.setattr(
            repository, "get_worker_settings", lambda: settings
        )
        test_repo = repository.MetadataRepository()
        assert "KEYVAULT" not in test_repo.refresh_settings()

    def test_create_service(self, test_repo):
        assert isinstance(test_repo, repository.MetadataRepository) is True

    def test__settings(self, monkeypatch, test_repo):
        fake_settings = pretend.stub()
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        result = test_repo._settings

        assert result == fake_settings

    def test_refresh_settings_with_none_arg(self, test_repo):
        test_repo.refresh_settings()

        assert (
            isinstance(test_repo._worker_settings, repository.Dynaconf) is True
        )

    def test_refresh_settings_with_worker_settings_arg(self, test_repo):
        FAKE_SETTINGS_FILE_PATH = "/data/mysettings.ini"
        fake_worker_settings = Dynaconf(
            settings_files=[FAKE_SETTINGS_FILE_PATH],
            envvar_prefix="RSTUF",
        )

        test_repo.refresh_settings(fake_worker_settings)

        assert (
            test_repo._worker_settings.to_dict()
            == fake_worker_settings.to_dict()
        )

    def test_refresh_settings_with_invalid_storage_backend(self, test_repo):
        fake_worker_settings = pretend.stub(
            STORAGE_BACKEND="INVALID_STORAGE_BACKEND"
        )

        with pytest.raises(ValueError):
            test_repo.refresh_settings(fake_worker_settings)

    def test_write_repository_settings(self, monkeypatch, test_repo):
        fake_settings = Dynaconf()
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        repository.redis_loader.write = pretend.call_recorder(lambda *a: None)
        result = test_repo.write_repository_settings("key", "value")

        assert result is None
        assert repository.redis_loader.write.calls == [
            pretend.call(fake_settings, {"key": "value"})
        ]

    def test_refresh_settings_with_sql_user_password(self, test_repo):
        test_repo._worker_settings.SQL_SERVER = "fake-sql:5433"
        test_repo._worker_settings.SQL_USER = "psql"
        test_repo._worker_settings.SQL_PASSWORD = "psqlpass"
        fake_sql = pretend.stub()
        repository.rstuf_db = pretend.call_recorder(lambda *a: fake_sql)

        test_repo.refresh_settings()

        assert test_repo._worker_settings.SQL == fake_sql
        assert repository.rstuf_db.calls == [
            pretend.call("postgresql://psql:psqlpass@fake-sql:5433")
        ]

    def test_refresh_settings_with_sql_user_missing_password(self, test_repo):
        test_repo._worker_settings.SQL_SERVER = "fake-sql:5433"
        test_repo._worker_settings.SQL_USER = "psql"

        with pytest.raises(AttributeError) as e:
            test_repo.refresh_settings()

        assert "'Settings' object has no attribute 'SQL_PASSWORD'" in str(e)

    def test_refresh_settings_with_sql_user_password_secrets(
        self, test_repo, monkeypatch
    ):
        test_repo._worker_settings.SQL_SERVER = "fake-sql:5433"
        test_repo._worker_settings.SQL_USER = "psql"
        test_repo._worker_settings.SQL_PASSWORD = "/run/secrets/SQL_PASSWORD"
        fake_data = pretend.stub(
            read=pretend.call_recorder(lambda: "psqlpass\n")
        )
        fake_file_obj = pretend.stub(
            __enter__=pretend.call_recorder(lambda: fake_data),
            __exit__=pretend.call_recorder(lambda *a: None),
            close=pretend.call_recorder(lambda: None),
        )
        monkeypatch.setitem(
            repository.__builtins__, "open", lambda *a: fake_file_obj
        )
        fake_sql = pretend.stub()
        repository.rstuf_db = pretend.call_recorder(lambda *a: fake_sql)

        test_repo.refresh_settings()

        assert test_repo._worker_settings.SQL == fake_sql
        assert repository.rstuf_db.calls == [
            pretend.call("postgresql://psql:psqlpass@fake-sql:5433")
        ]

    def test_refresh_settings_with_sql_user_password_secrets_OSError(
        self, test_repo, monkeypatch, caplog
    ):
        caplog.set_level(repository.logging.ERROR)
        test_repo._worker_settings.SQL_SERVER = "fake-sql:5433"
        test_repo._worker_settings.SQL_USER = "psql"
        test_repo._worker_settings.SQL_PASSWORD = "/run/secrets/SQL_PASSWORD"
        monkeypatch.setitem(
            repository.__builtins__,
            "open",
            pretend.raiser(PermissionError("No permission /run/secrets/*")),
        )

        with pytest.raises(OSError) as e:
            test_repo.refresh_settings()

        assert "No permission /run/secrets/*" in str(e)
        assert "No permission /run/secrets/*" == caplog.messages[0]

    def test__sign(self, test_repo):
        fake_role = pretend.stub(keyids=["keyid_1"])
        fake_md = pretend.stub(
            signatures=pretend.stub(clear=pretend.call_recorder(lambda: None)),
            sign=pretend.call_recorder(lambda *a, **kw: None),
            signed=pretend.stub(
                roles={"timestamp": fake_role},
                keys={"keyid_1": {}},
            ),
        )
        test_repo._storage_backend = pretend.stub(
            get=pretend.call_recorder(lambda *a: fake_md)
        )
        test_repo._signer_store = pretend.stub(
            get=pretend.call_recorder(lambda *a: "key_signer_1")
        )

        test_result = test_repo._sign(fake_md)

        assert test_result is None
        assert test_repo._signer_store.get.calls == [pretend.call({})]
        assert fake_md.signatures.clear.calls == [pretend.call()]
        assert test_repo._storage_backend.get.calls == [pretend.call("root")]
        assert fake_md.sign.calls == [
            pretend.call("key_signer_1", append=True),
        ]

    def _test_helper_persist(
        self, test_repo, role, version, expected_file_name
    ):
        fake_bytes = b""

        fake_role = pretend.stub(
            signed=pretend.stub(version=version),
            to_bytes=pretend.call_recorder(lambda *a, **kw: fake_bytes),
            to_dict=pretend.call_recorder(lambda: None),
        )

        repository.JSONSerializer = pretend.call_recorder(lambda: None)

        test_repo._storage_backend = pretend.stub(
            put=pretend.call_recorder(lambda *a: None)
        )
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )

        test_result = test_repo._persist(fake_role, role)
        assert test_result == expected_file_name
        assert fake_role.to_bytes.calls == [
            pretend.call(repository.JSONSerializer())
        ]
        assert test_repo._storage_backend.put.calls == [
            pretend.call(
                fake_bytes,
                expected_file_name,
            )
        ]
        if role == Root.type:
            assert test_repo.write_repository_settings.calls == [
                pretend.call("TRUSTED_ROOT", None)
            ]
            assert fake_role.to_dict.calls == [pretend.call()]
        else:
            assert test_repo.write_repository_settings.calls == []
            assert fake_role.to_dict.calls == []

    def test__persist(self, test_repo):
        self._test_helper_persist(test_repo, "snapshot", 2, "2.snapshot.json")

    def test__persist_file_has_version(self, test_repo):
        self._test_helper_persist(
            test_repo, "1.snapshot", 1, "1.snapshot.json"
        )

    def test__persist_file_has_number_name(self, test_repo):
        self._test_helper_persist(test_repo, "bin-3", 2, "2.bin-3.json")

    def test__persist_timestamp(self, test_repo):
        self._test_helper_persist(test_repo, "timestamp", 2, "timestamp.json")

    def test__persist_root(self, test_repo):
        self._test_helper_persist(test_repo, "root", 2, "2.root.json")

    def test_bump_expiry(self, monkeypatch, test_repo, mocked_datetime):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: 1460)
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        fake_role = pretend.stub(
            signed=pretend.stub(expires=mocked_datetime.now()),
        )

        result = test_repo._bump_expiry(fake_role, "root")
        assert result is None
        assert fake_role.signed.expires == datetime.datetime(
            2023, 6, 15, 9, 5, 1
        )

    def test__bump_version(self, test_repo):
        role = pretend.stub(
            signed=pretend.stub(version=2),
        )
        result = test_repo._bump_version(role)

        assert result is None
        assert role.signed.version == 3

    def test__bump_and_persist(self, test_repo):
        test_repo._bump_expiry = pretend.call_recorder(lambda *a: None)
        test_repo._bump_version = pretend.call_recorder(lambda *a: None)
        test_repo._sign = pretend.call_recorder(lambda a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)

        timestamp = Metadata(Timestamp(expires=datetime.datetime.now()))
        result = test_repo._bump_and_persist(timestamp, Timestamp.type)

        assert result is None
        assert test_repo._bump_expiry.calls == [
            pretend.call(timestamp, Timestamp.type)
        ]
        assert test_repo._bump_version.calls == [pretend.call(timestamp)]
        assert test_repo._sign.calls == [pretend.call(timestamp)]
        assert test_repo._persist.calls == [
            pretend.call(timestamp, Timestamp.type)
        ]

    def test__bump_and_persist_without_persist(self, test_repo):
        test_repo._bump_expiry = pretend.call_recorder(lambda *a: None)
        test_repo._bump_version = pretend.call_recorder(lambda *a: None)
        test_repo._sign = pretend.call_recorder(lambda a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)

        timestamp = Metadata(Timestamp(expires=datetime.datetime.now()))
        result = test_repo._bump_and_persist(timestamp, Timestamp.type, False)

        assert result is None
        assert test_repo._bump_expiry.calls == [
            pretend.call(timestamp, Timestamp.type)
        ]
        assert test_repo._bump_version.calls == [pretend.call(timestamp)]
        assert test_repo._sign.calls == [pretend.call(timestamp)]
        assert test_repo._persist.calls == []

    def test__update_timestamp(self, monkeypatch, test_repo):
        snapshot_version = 3
        timestamp_version = 5
        fake_metafile = pretend.call_recorder(
            lambda *a, **kw: snapshot_version
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.MetaFile", fake_metafile
        )

        mocked_timestamp = pretend.stub(
            signed=pretend.stub(snapshot_meta=2, version=timestamp_version)
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: mocked_timestamp
        )

        def fake__bump_and_persist(md, role, **kw):
            md.signed.version += 1

        test_repo._bump_and_persist = pretend.call_recorder(
            fake__bump_and_persist
        )

        test_repo._update_timestamp(snapshot_version)

        assert mocked_timestamp.signed.version == timestamp_version + 1
        assert mocked_timestamp.signed.snapshot_meta == snapshot_version
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Roles.TIMESTAMP.value, None)
        ]
        assert test_repo._bump_and_persist.calls == [
            pretend.call(mocked_timestamp, repository.Roles.TIMESTAMP.value)
        ]

    def test__update_snapshot(self, test_repo):
        snapshot_version = 3
        targets_version = 4
        mocked_snapshot = pretend.stub(
            signed=pretend.stub(
                meta={},
                version=snapshot_version,
            )
        )
        mocked_targets = pretend.stub(
            signed=pretend.stub(
                version=targets_version,
                delegations=pretend.stub(succinct_roles=True),
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda rolename: mocked_snapshot
            if rolename == Snapshot.type
            else mocked_targets
        )

        def fake__bump_and_persist(md, role, **kw):
            md.signed.version += 1

        test_repo._bump_and_persist = pretend.call_recorder(
            fake__bump_and_persist
        )

        result = test_repo._update_snapshot()

        assert result == snapshot_version + 1
        assert mocked_snapshot.signed.version == snapshot_version + 1
        assert mocked_snapshot.signed.meta == {
            "targets.json": MetaFile(version=targets_version)
        }
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Roles.SNAPSHOT.value),
            pretend.call(repository.Roles.TARGETS.value),
        ]
        assert test_repo._bump_and_persist.calls == [
            pretend.call(mocked_snapshot, repository.Roles.SNAPSHOT.value)
        ]

    def test__update_snapshot_specific_targets(self, test_repo, monkeypatch):
        test_repo._db = pretend.stub()
        repository.TargetFile.from_dict = pretend.call_recorder(
            lambda *a: a[0]
        )
        snapshot_version = 3
        bins_a_version = 4
        bins_e_version = 4
        targets_version = 3
        # Test that only "bins-e" is updated. "bins-a" doesn't require update.
        mocked_snapshot = pretend.stub(
            signed=pretend.stub(
                meta={
                    "bins-a.json": bins_a_version,
                    "bins-e.json": bins_e_version,
                },
                version=snapshot_version,
            )
        )
        mocked_bins_md = pretend.stub(
            signed=pretend.stub(targets={"k": "v"}, version=bins_e_version)
        )
        mocked_targets = pretend.stub(
            signed=pretend.stub(
                version=targets_version,
                delegations=pretend.stub(succinct_roles=True),
            )
        )

        def get(rolename: str):
            if rolename == Snapshot.type:
                return mocked_snapshot
            elif rolename == Targets.type:
                return mocked_targets
            else:
                return mocked_bins_md

        test_repo._storage_backend.get = pretend.call_recorder(
            lambda rolename: get(rolename)
        )
        fake_bins_e = pretend.stub(
            rolename="bins-e",
            target_files=[
                pretend.stub(
                    path="k1",
                    info="f1",
                    action=repository.targets_schema.TargetAction.ADD,
                ),
                pretend.stub(
                    path="k2",
                    info="f2",
                    action=repository.targets_schema.TargetAction.REMOVE,
                ),
            ],
            id=5,
        )
        fake_bins_targets = [fake_bins_e]

        monkeypatch.setattr(
            repository.targets_crud,
            "read_roles_joint_files",
            pretend.call_recorder(lambda *a: fake_bins_targets),
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "update_files_to_published",
            pretend.call_recorder(lambda *a: None),
        )
        repository.MetaFile = pretend.call_recorder(lambda **kw: kw["version"])
        monkeypatch.setattr(
            repository.targets_crud,
            "update_roles_version",
            pretend.call_recorder(lambda *a: None),
        )

        def fake__bump_and_persist(md, role, **kw):
            md.signed.version += 1

        test_repo._bump_and_persist = pretend.call_recorder(
            fake__bump_and_persist
        )
        test_repo._persist = pretend.call_recorder(lambda *a: None)

        targets = ["bins-e"]
        result = test_repo._update_snapshot(targets)

        assert result == snapshot_version + 1
        assert mocked_snapshot.signed.version == snapshot_version + 1
        assert mocked_snapshot.signed.meta == {
            "bins-a.json": bins_a_version,
            "bins-e.json": bins_a_version + 1,
            "targets.json": targets_version,
        }
        assert mocked_bins_md.signed.targets == {"k1": "f1"}
        assert repository.targets_crud.read_roles_joint_files.calls == [
            pretend.call(test_repo._db, targets)
        ]
        assert repository.TargetFile.from_dict.calls == [
            pretend.call("f1", "k1"),
        ]
        assert repository.targets_crud.update_files_to_published.calls == [
            pretend.call(
                test_repo._db, [file.path for file in fake_bins_e.target_files]
            )
        ]
        assert repository.MetaFile.calls == [
            pretend.call(version=mocked_bins_md.signed.version),
            pretend.call(version=mocked_targets.signed.version),
        ]
        assert repository.targets_crud.update_roles_version.calls == [
            pretend.call(
                test_repo._db, [int(bins.id) for bins in fake_bins_targets]
            )
        ]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Roles.SNAPSHOT.value),
            pretend.call(repository.Roles.TARGETS.value),
            pretend.call("bins-e"),
        ]
        assert test_repo._bump_and_persist.calls == [
            pretend.call(
                mocked_bins_md, repository.Roles.BINS.value, persist=False
            ),
            pretend.call(mocked_snapshot, repository.Roles.SNAPSHOT.value),
        ]
        assert test_repo._persist.calls == [
            pretend.call(mocked_bins_md, "bins-e"),
        ]

    def test__update_snapshot_specific_targets_custom_delegation_used(
        self, test_repo, monkeypatch
    ):
        test_repo._db = pretend.stub()
        repository.TargetFile.from_dict = pretend.call_recorder(
            lambda *a: a[0]
        )
        snapshot_version = 3
        foo_project_version = 4
        second_project_version = 4
        targets_version = 3
        # Test that only "second_project" is updated. "foo_project" doesn't
        # require update.
        mocked_snapshot = pretend.stub(
            signed=pretend.stub(
                meta={
                    "foo_project.json": foo_project_version,
                    "second_project.json": second_project_version,
                },
                version=snapshot_version,
            )
        )
        mocked_delegation_md = pretend.stub(
            signed=pretend.stub(
                targets={"k": "v"},
                version=second_project_version,
            )
        )
        mocked_targets = pretend.stub(
            signed=pretend.stub(
                version=targets_version,
                delegations=pretend.stub(succinct_roles=None),
            )
        )

        def get(rolename: str):
            if rolename == Snapshot.type:
                return mocked_snapshot
            elif rolename == Targets.type:
                return mocked_targets
            else:
                return mocked_delegation_md

        test_repo._storage_backend.get = pretend.call_recorder(
            lambda rolename: get(rolename)
        )
        fake_delegation = pretend.stub(
            rolename="second_project",
            target_files=[
                pretend.stub(
                    path="k1",
                    info="f1",
                    action=repository.targets_schema.TargetAction.ADD,
                ),
                pretend.stub(
                    path="k2",
                    info="f2",
                    action=repository.targets_schema.TargetAction.REMOVE,
                ),
            ],
            id=5,
        )
        fake_delegations = [fake_delegation]

        monkeypatch.setattr(
            repository.targets_crud,
            "read_roles_joint_files",
            pretend.call_recorder(lambda *a: fake_delegations),
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "update_files_to_published",
            pretend.call_recorder(lambda *a: None),
        )
        repository.MetaFile = pretend.call_recorder(lambda **kw: kw["version"])
        monkeypatch.setattr(
            repository.targets_crud,
            "update_roles_version",
            pretend.call_recorder(lambda *a: None),
        )

        def fake__bump_and_persist(md, role, **kw):
            md.signed.version += 1

        test_repo._bump_and_persist = pretend.call_recorder(
            fake__bump_and_persist
        )
        test_repo._persist = pretend.call_recorder(lambda *a: None)

        targets = ["second_project"]
        result = test_repo._update_snapshot(targets)

        assert result == snapshot_version + 1
        assert mocked_snapshot.signed.version == snapshot_version + 1
        assert mocked_snapshot.signed.meta == {
            "foo_project.json": foo_project_version,
            "second_project.json": second_project_version + 1,
            "targets.json": targets_version,
        }
        assert mocked_delegation_md.signed.targets == {"k1": "f1"}
        assert repository.targets_crud.read_roles_joint_files.calls == [
            pretend.call(test_repo._db, targets)
        ]
        assert repository.TargetFile.from_dict.calls == [
            pretend.call("f1", "k1"),
        ]
        assert repository.targets_crud.update_files_to_published.calls == [
            pretend.call(
                test_repo._db,
                [file.path for file in fake_delegation.target_files],
            )
        ]
        assert repository.MetaFile.calls == [
            pretend.call(version=mocked_delegation_md.signed.version),
            pretend.call(version=mocked_targets.signed.version),
        ]
        assert repository.targets_crud.update_roles_version.calls == [
            pretend.call(
                test_repo._db, [int(deleg.id) for deleg in fake_delegations]
            )
        ]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Roles.SNAPSHOT.value),
            pretend.call(repository.Roles.TARGETS.value),
            pretend.call("second_project"),
        ]
        assert test_repo._bump_and_persist.calls == [
            pretend.call(
                mocked_delegation_md, "second_project", persist=False
            ),
            pretend.call(mocked_snapshot, repository.Roles.SNAPSHOT.value),
        ]
        assert test_repo._persist.calls == [
            pretend.call(mocked_delegation_md, "second_project"),
        ]

    def test__update_snapshot_bump_all(self, test_repo, monkeypatch):
        snapshot_version = 3
        targets_version = 4
        mocked_snapshot = pretend.stub(
            signed=pretend.stub(
                meta={"bins-e.json": 2, "bins-f.json": 6},
                version=snapshot_version,
            )
        )
        mocked_bins = {
            "bins-e": pretend.stub(
                signed=pretend.stub(targets={"k": "v"}, version=2)
            ),
            "bins-f": pretend.stub(
                signed=pretend.stub(targets={"k": "v"}, version=6)
            ),
        }
        mocked_targets = pretend.stub(
            signed=pretend.stub(
                version=targets_version,
                delegations=pretend.stub(succinct_roles=True),
            )
        )

        def get(rolename: str):
            if rolename == Snapshot.type:
                return mocked_snapshot
            elif rolename == Targets.type:
                return mocked_targets
            else:
                return mocked_bins[rolename]

        test_repo._storage_backend.get = pretend.call_recorder(
            lambda rolename: get(rolename)
        )
        fake_bins = [
            pretend.stub(rolename="bins-e", id=3),
            pretend.stub(rolename="bins-f", id=4),
        ]
        fake_read_all_roles = pretend.call_recorder(lambda *a: fake_bins)
        test_repo._db = pretend.stub()
        repository.MetaFile = pretend.call_recorder(lambda **kw: kw["version"])
        monkeypatch.setattr(
            repository.targets_crud,
            "read_all_roles",
            fake_read_all_roles,
        )

        def fake__bump_and_persist(md, role, **kw):
            md.signed.version += 1

        test_repo._bump_and_persist = pretend.call_recorder(
            fake__bump_and_persist
        )
        test_repo._persist = pretend.call_recorder(lambda *a: None)
        fake_update_roles_version = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(
            repository.targets_crud,
            "update_roles_version",
            fake_update_roles_version,
        )
        result = test_repo._update_snapshot(bump_all=True)

        assert result == snapshot_version + 1
        assert mocked_snapshot.signed.version == snapshot_version + 1
        assert mocked_snapshot.signed.meta == {
            "bins-e.json": mocked_bins["bins-e"].signed.version,
            "bins-f.json": mocked_bins["bins-f"].signed.version,
            "targets.json": mocked_targets.signed.version,
        }
        assert fake_read_all_roles.calls == [pretend.call(test_repo._db)]
        assert test_repo._bump_and_persist.calls == [
            pretend.call(mocked_bins["bins-e"], "bins", persist=False),
            pretend.call(mocked_bins["bins-f"], "bins", persist=False),
            pretend.call(mocked_snapshot, "snapshot"),
        ]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Snapshot.type),
            pretend.call(Targets.type),
            pretend.call("bins-e"),
            pretend.call("bins-f"),
        ]
        assert test_repo._persist.calls == [
            pretend.call(mocked_bins["bins-e"], "bins-e"),
            pretend.call(mocked_bins["bins-f"], "bins-f"),
        ]
        assert fake_update_roles_version.calls == [
            pretend.call(test_repo._db, [3, 4])
        ]
        assert repository.MetaFile.calls == [
            pretend.call(version=mocked_bins["bins-e"].signed.version),
            pretend.call(version=mocked_bins["bins-f"].signed.version),
            pretend.call(version=mocked_targets.signed.version),
        ]

    def test__update_snapshot_bump_all_custom_delegation(
        self, test_repo, monkeypatch
    ):
        snapshot_version = 3
        targets_version = 4
        mocked_snapshot = pretend.stub(
            signed=pretend.stub(
                meta={"project_1.json": 2, "project_2.json": 6},
                version=snapshot_version,
            )
        )
        mocked_delegations = {
            "project_1": pretend.stub(
                signed=pretend.stub(targets={"k": "v"}, version=2)
            ),
            "project_2": pretend.stub(
                signed=pretend.stub(targets={"k": "v"}, version=6)
            ),
        }
        mocked_targets = pretend.stub(
            signed=pretend.stub(
                version=targets_version,
                delegations=pretend.stub(succinct_roles=True),
            )
        )

        def get(rolename: str):
            if rolename == Snapshot.type:
                return mocked_snapshot
            elif rolename == Targets.type:
                return mocked_targets
            else:
                return mocked_delegations[rolename]

        test_repo._storage_backend.get = pretend.call_recorder(
            lambda rolename: get(rolename)
        )
        fake_bins = [
            pretend.stub(rolename="project_1", id=3),
            pretend.stub(rolename="project_2", id=4),
        ]
        fake_read_all_roles = pretend.call_recorder(lambda *a: fake_bins)
        test_repo._db = pretend.stub()
        repository.MetaFile = pretend.call_recorder(lambda **kw: kw["version"])
        monkeypatch.setattr(
            repository.targets_crud,
            "read_all_roles",
            fake_read_all_roles,
        )

        def fake__bump_and_persist(md, role, **kw):
            md.signed.version += 1

        test_repo._bump_and_persist = pretend.call_recorder(
            fake__bump_and_persist
        )
        test_repo._persist = pretend.call_recorder(lambda *a: None)
        fake_update_roles_version = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(
            repository.targets_crud,
            "update_roles_version",
            fake_update_roles_version,
        )
        result = test_repo._update_snapshot(bump_all=True)

        assert result == snapshot_version + 1
        assert mocked_snapshot.signed.version == snapshot_version + 1
        assert mocked_snapshot.signed.meta == {
            "project_1.json": mocked_delegations["project_1"].signed.version,
            "project_2.json": mocked_delegations["project_2"].signed.version,
            "targets.json": mocked_targets.signed.version,
        }
        assert fake_read_all_roles.calls == [pretend.call(test_repo._db)]
        assert test_repo._bump_and_persist.calls == [
            pretend.call(
                mocked_delegations["project_1"], "bins", persist=False
            ),
            pretend.call(
                mocked_delegations["project_2"], "bins", persist=False
            ),
            pretend.call(mocked_snapshot, "snapshot"),
        ]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Snapshot.type),
            pretend.call(Targets.type),
            pretend.call("project_1"),
            pretend.call("project_2"),
        ]
        assert test_repo._persist.calls == [
            pretend.call(mocked_delegations["project_1"], "project_1"),
            pretend.call(mocked_delegations["project_2"], "project_2"),
        ]
        assert fake_update_roles_version.calls == [
            pretend.call(test_repo._db, [3, 4])
        ]
        assert repository.MetaFile.calls == [
            pretend.call(
                version=mocked_delegations["project_1"].signed.version
            ),
            pretend.call(
                version=mocked_delegations["project_2"].signed.version
            ),
            pretend.call(version=mocked_targets.signed.version),
        ]

    def test__get_path_succinct_role(self, test_repo):
        fake_targets = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(
                    succinct_roles=pretend.stub(
                        get_role_for_target=pretend.call_recorder(
                            lambda *a: "bin-e"
                        )
                    )
                ),
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_targets
        )
        result = test_repo._get_path_succinct_role("v0.0.1/test_path.tar.gz")

        assert result == "bin-e"
        assert (
            fake_targets.signed.delegations.succinct_roles.get_role_for_target.calls  # noqa
            == [pretend.call("v0.0.1/test_path.tar.gz")]
        )
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Targets.type)
        ]

    def test__update_task(self, test_repo, mocked_datetime):
        test_repo._db = pretend.stub(
            refresh=pretend.call_recorder(lambda *a: None)
        )

        fake_target = pretend.stub(published=True)
        fake_bin_targets = {
            "bin-e": [fake_target],
            "bin-f": [fake_target, fake_target],
        }
        fake_update_state = pretend.call_recorder(lambda *a, **kw: None)
        fake_subtask = pretend.stub(status=states.SUCCESS)
        result = test_repo._update_task(
            fake_bin_targets, fake_update_state, fake_subtask
        )

        assert result is None
        assert test_repo._db.refresh.calls == [
            pretend.call(fake_target),
            pretend.call(fake_target),
            pretend.call(fake_target),
        ]
        assert fake_update_state.calls == [
            pretend.call(
                state="RUNNING",
                meta={
                    "details": {
                        "published_roles": ["bin-e"],
                        "roles_to_publish": "['bin-e', 'bin-f']",
                    },
                    "message": "Publishing",
                    "last_update": mocked_datetime.now(),
                    "exc_type": None,
                    "exc_message": None,
                },
            ),
        ]

    def test__update_task_subtask_failure(self, test_repo, mocked_datetime):
        test_repo._db = pretend.stub(
            refresh=pretend.call_recorder(lambda *a: None)
        )

        fake_target = pretend.stub(published=True)
        fake_bin_targets = {
            "bin-e": [fake_target],
            "bin-f": [fake_target, fake_target],
        }
        fake_update_state = pretend.call_recorder(lambda *a, **kw: None)
        fake_subtask = pretend.stub(
            status=states.FAILURE,
            task_id="publish_targets-fakeid",
            result=PermissionError("failed to write in the storage"),
        )

        with pytest.raises(ChordError) as err:
            test_repo._update_task(
                fake_bin_targets, fake_update_state, fake_subtask
            )

        assert "Failed to execute publish_targets-fakeid" in str(err)
        assert test_repo._db.refresh.calls == [
            pretend.call(fake_target),
            pretend.call(fake_target),
        ]
        assert fake_update_state.calls == [
            pretend.call(
                state=states.FAILURE,
                meta={
                    "details": {
                        "published_roles": ["bin-e"],
                        "roles_to_publish": "['bin-e', 'bin-f']",
                    },
                    "message": "Publishing",
                    "last_update": mocked_datetime.now(),
                    "exc_type": "PermissionError",
                    "exc_message": ["failed to write in the storage"],
                },
            ),
        ]

    def test_save_settings_bins(self, test_repo):
        fake_root_md = pretend.stub(
            type="root",
            signatures=[{"keyid": "sig1"}, {"keyid": "sig2"}],
            signed=pretend.stub(
                roles={"root": pretend.stub(threshold=1)},
            ),
        )
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )
        payload_settings = {
            "roles": {
                "root": {"expiration": 365},
                "targets": {"expiration": 365},
                "snapshot": {"expiration": 1},
                "timestamp": {"expiration": 1},
                "bins": {"expiration": 30, "number_of_delegated_bins": 4},
            }
        }

        result = test_repo.save_settings(fake_root_md, payload_settings)
        assert result is None
        assert test_repo.write_repository_settings.calls == [
            pretend.call("ROOT_EXPIRATION", 365),
            pretend.call("ROOT_THRESHOLD", 1),
            pretend.call("ROOT_NUM_KEYS", 2),
            pretend.call("SNAPSHOT_EXPIRATION", 1),
            pretend.call("SNAPSHOT_THRESHOLD", 1),
            pretend.call("SNAPSHOT_NUM_KEYS", 1),
            pretend.call("TARGETS_EXPIRATION", 365),
            pretend.call("TARGETS_THRESHOLD", 1),
            pretend.call("TARGETS_NUM_KEYS", 1),
            pretend.call("TIMESTAMP_EXPIRATION", 1),
            pretend.call("TIMESTAMP_THRESHOLD", 1),
            pretend.call("TIMESTAMP_NUM_KEYS", 1),
            pretend.call("TARGETS_ONLINE_KEY", True),
            pretend.call("BINS_EXPIRATION", 30),
            pretend.call("BINS_THRESHOLD", 1),
            pretend.call("BINS_NUM_KEYS", 1),
            pretend.call("NUMBER_OF_DELEGATED_BINS", 4),
        ]

    def test_save_settings_custom_targets(self, test_repo):
        fake_root_md = pretend.stub(
            type="root",
            signatures=[{"keyid": "sig1"}, {"keyid": "sig2"}],
            signed=pretend.stub(
                roles={"root": pretend.stub(threshold=1)},
            ),
        )
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )
        payload_settings = {
            "roles": {
                "root": {"expiration": 365},
                "targets": {"expiration": 365},
                "snapshot": {"expiration": 1},
                "timestamp": {"expiration": 1},
                "delegated_roles": {
                    "foo": {"expiration": 30, "path_patterns": ["project/f"]},
                    "bar": {"expiration": 60, "path_patterns": ["project/b"]},
                },
            }
        }

        result = test_repo.save_settings(fake_root_md, payload_settings)
        assert result is None
        assert test_repo.write_repository_settings.calls == [
            pretend.call("ROOT_EXPIRATION", 365),
            pretend.call("ROOT_THRESHOLD", 1),
            pretend.call("ROOT_NUM_KEYS", 2),
            pretend.call("SNAPSHOT_EXPIRATION", 1),
            pretend.call("SNAPSHOT_THRESHOLD", 1),
            pretend.call("SNAPSHOT_NUM_KEYS", 1),
            pretend.call("TARGETS_EXPIRATION", 365),
            pretend.call("TARGETS_THRESHOLD", 1),
            pretend.call("TARGETS_NUM_KEYS", 1),
            pretend.call("TIMESTAMP_EXPIRATION", 1),
            pretend.call("TIMESTAMP_THRESHOLD", 1),
            pretend.call("TIMESTAMP_NUM_KEYS", 1),
            pretend.call("TARGETS_ONLINE_KEY", True),
            pretend.call("FOO_EXPIRATION", 30),
            pretend.call("FOO_THRESHOLD", 1),
            pretend.call("FOO_NUM_KEYS", 1),
            pretend.call("FOO_PATH_PATTERNS", ["project/f"]),
            pretend.call("BAR_EXPIRATION", 60),
            pretend.call("BAR_THRESHOLD", 1),
            pretend.call("BAR_NUM_KEYS", 1),
            pretend.call("BAR_PATH_PATTERNS", ["project/b"]),
        ]

    def test__setup_targets_delegations_custom_targets(self, test_repo):
        fake_pub_online_key = pretend.stub(
            key_dict={"keyid": "id", "keytype": "rsa"}, keyid="id"
        )

        repository.Targets.add_key = pretend.call_recorder(lambda *a: None)

        test_repo._bump_expiry = pretend.call_recorder(lambda *a: None)
        test_repo._sign = pretend.call_recorder(lambda *a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)

        fake_targets = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(roles={}),
                add_key=pretend.call_recorder(lambda *a: None),
            )
        )

        custom_targets = {
            "role1": {"expiration": 30, "path_prefixes": "role1/"},
            "role2": {"expiration": 300, "path_prefixes": "role2/"},
        }

        result = test_repo._setup_targets_delegations(
            fake_pub_online_key, fake_targets, custom_targets
        )
        assert result is None
        assert fake_targets.signed.add_key.calls == [
            pretend.call(fake_pub_online_key, "role1"),
            pretend.call(fake_pub_online_key, "role2"),
        ]
        call_id = 0
        for role_name in custom_targets.keys():
            call = test_repo._bump_expiry.calls[call_id]
            assert len(call.args) == 2
            assert isinstance(call.args[0], repository.Metadata)
            assert call.args[1] == role_name

            call = test_repo._sign.calls[call_id]
            assert len(call.args) == 1
            assert isinstance(call.args[0], repository.Metadata)

            call = test_repo._persist.calls[call_id]
            assert len(call.args) == 2
            assert isinstance(call.args[0], repository.Metadata)
            assert call.args[1] == role_name

            call_id += 1

    def test__setup_targets_delegations_hash_bins_delegations(
        self, test_repo, monkeypatch
    ):
        fake_pub_online_key = pretend.stub(
            key_dict={"keyid": "id", "keytype": "rsa"}, keyid="id"
        )
        repository.Targets.add_key = pretend.call_recorder(lambda *a: None)

        get_fresh_resp = 2
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: get_fresh_resp)
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        test_repo._bump_expiry = pretend.call_recorder(lambda *a: None)
        test_repo._sign = pretend.call_recorder(lambda *a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)

        fake_targets = pretend.stub(
            signed=pretend.stub(
                delegations=None,
                add_key=pretend.call_recorder(lambda *a: None),
            )
        )

        result = test_repo._setup_targets_delegations(
            fake_pub_online_key,
            fake_targets,
        )
        assert result is None
        assert fake_settings.get_fresh.calls == [
            pretend.call("NUMBER_OF_DELEGATED_BINS")
        ]
        for idx, call in enumerate(repository.Targets.add_key.calls):
            assert call.args[1] == fake_pub_online_key
            assert call.args[2] == f"bins-{idx}"

        bit_length = log(get_fresh_resp, 2)
        call_id = 0
        while call_id < bit_length:
            call = test_repo._bump_expiry.calls[call_id]
            assert len(call.args) == 2
            assert isinstance(call.args[0], repository.Metadata)
            assert call.args[1] == repository.BINS

            call = test_repo._sign.calls[call_id]
            assert len(call.args) == 1
            assert isinstance(call.args[0], repository.Metadata)

            call = test_repo._persist.calls[call_id]
            assert len(call.args) == 2
            assert isinstance(call.args[0], repository.Metadata)
            assert call.args[1] == f"{repository.BINS}-{call_id}"

            call_id += 1

    def test__get_delegation_roles_succinct_roles(self, test_repo):
        targets: Metadata[Targets] = Metadata(Targets())
        succinct_roles = SuccinctRoles([], 1, 1, repository.BINS)
        targets.signed.delegations = Delegations(
            keys={}, succinct_roles=succinct_roles
        )

        expected_result = ["bins-0", "bins-1"]
        test_result = []
        for role_name in test_repo._get_delegation_roles(targets):
            test_result.append(role_name)

        assert test_result == expected_result

    def test__get_delegation_roles_custom_targets(self, test_repo):
        targets: Metadata[Targets] = Metadata(Targets())
        targets.signed.delegations = Delegations(
            keys={},
            roles={
                "role1": DelegatedRole("role1", [], 1, 1, "role1/"),
                "role2": DelegatedRole("role2", [], 1, 1, "role2/"),
            },
        )

        expected_result = ["role1", "role2"]
        test_result = []
        for role_name in test_repo._get_delegation_roles(targets):
            test_result.append(role_name)

        assert test_result == expected_result

    def test__bootstrap_online_roles(self, test_repo, monkeypatch):
        fake_root_md = pretend.stub(
            type="root",
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["online_key_id"])},
                keys={"online_key_id": "online_public_key"},
            ),
        )
        test_repo._setup_targets_delegations = pretend.call_recorder(
            lambda *a: None
        )

        def fake_delegation_roles() -> Iterator:
            bins = ["bins-0", "bins-1"]
            for bin in bins:
                yield bin

        test_repo._get_delegation_roles = pretend.call_recorder(
            lambda *a: fake_delegation_roles()
        )
        repository.MetaFile = pretend.call_recorder(lambda: "name")

        monkeypatch.setattr(
            repository.targets_crud,
            "create_roles",
            pretend.call_recorder(lambda *a: None),
        )
        test_repo._db = "db_session"
        test_repo._bump_expiry = pretend.call_recorder(lambda *a: None)
        test_repo._sign = pretend.call_recorder(lambda *a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)

        result = test_repo._bootstrap_online_roles(fake_root_md)
        assert result is None
        assert len(test_repo._setup_targets_delegations.calls) == 1
        call = test_repo._setup_targets_delegations.calls[0]
        assert call.args[0] == "online_public_key"
        assert isinstance(call.args[1], Metadata)
        assert call.args[2] is None

        for call in test_repo._get_delegation_roles.calls:
            assert isinstance(call.args[0], Metadata)

        assert repository.targets_crud.create_roles.calls == [
            pretend.call(
                "db_session",
                [
                    repository.targets_schema.RSTUFTargetRoleCreate(
                        rolename="bins-0", version=1
                    ),
                    repository.targets_schema.RSTUFTargetRoleCreate(
                        rolename="bins-1", version=1
                    ),
                ],
            )
        ]
        # Special checks as calls use metadata object instances
        # Assert that calls contain two args and 'role' argument is a
        # 'Metadata'.
        call_id = 0
        for md_cls in [Targets, Snapshot, Timestamp]:
            call = test_repo._bump_expiry.calls[call_id]
            assert len(call.args) == 2
            assert isinstance(call.args[0], repository.Metadata)
            assert isinstance(call.args[0].signed, md_cls)
            assert call.args[1] == md_cls.type

            call = test_repo._sign.calls[call_id]
            assert len(call.args) == 1
            assert isinstance(call.args[0], repository.Metadata)
            assert isinstance(call.args[0].signed, md_cls)

            call = test_repo._persist.calls[call_id]
            assert len(call.args) == 2
            assert isinstance(call.args[0], repository.Metadata)
            assert isinstance(call.args[0].signed, md_cls)
            assert call.args[1] == md_cls.type

            call_id += 1

    def test_update_settings(self, test_repo, mocked_datetime):
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )
        TARGETS_EXP = 100
        SNAPSHOT_EXP = 50
        TIMESTAMP_EXP = 20
        BINS_EXP = 5
        BINS = repository.Roles.BINS.value

        payload = {
            "settings": {
                "expiration": {
                    Targets.type: TARGETS_EXP,
                    Snapshot.type: SNAPSHOT_EXP,
                    Timestamp.type: TIMESTAMP_EXP,
                    BINS: BINS_EXP,
                }
            }
        }
        result = test_repo.update_settings(payload)
        assert result == {
            "task": "update_settings",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Update Settings Succeded",
            "error": None,
            "details": {
                "invalid_roles": [],
                "updated_roles": ["targets", "snapshot", "timestamp", "bins"],
            },
        }

        BINS_CONFIG_NAME = f"{BINS.upper()}_EXPIRATION"
        TIMESTAMP_CONFIG_NAME = f"{Timestamp.type.upper()}_EXPIRATION"

        assert test_repo.write_repository_settings.calls == [
            pretend.call(f"{Targets.type.upper()}_EXPIRATION", TARGETS_EXP),
            pretend.call(f"{Snapshot.type.upper()}_EXPIRATION", SNAPSHOT_EXP),
            pretend.call(TIMESTAMP_CONFIG_NAME, TIMESTAMP_EXP),
            pretend.call(BINS_CONFIG_NAME, BINS_EXP),
        ]

    def test_update_settings_no_settings(self, test_repo, mocked_datetime):
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )

        result = test_repo.update_settings(payload={})
        assert result == {
            "task": "update_settings",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Update Settings Failed",
            "error": "No 'settings' in the payload",
            "details": None,
        }

    def test_update_settings_no_expiration(self, test_repo, mocked_datetime):
        result = test_repo.update_settings(payload={"settings": {}})
        assert result == {
            "task": "update_settings",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Update Settings Failed",
            "error": "No 'expiration' in the payload",
            "details": None,
        }

    def test_update_settings_no_role_in_expiration(
        self, test_repo, mocked_datetime
    ):
        result = test_repo.update_settings(
            payload={"settings": {"expiration": {}}}
        )
        assert result == {
            "task": "update_settings",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Update Settings Failed",
            "error": "No role provided for expiration policy change",
            "details": None,
        }

    def test_update_settings_no_valid_role_in_expiration(
        self, test_repo, mocked_datetime
    ):
        result = test_repo.update_settings(
            payload={"settings": {"expiration": {"foo": 1}}}
        )
        assert result == {
            "task": "update_settings",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Update Settings Succeded",
            "error": None,
            "details": {
                "invalid_roles": ["foo"],
                "updated_roles": [],
            },
        }

    def test_update_settings_valid_and_invalid_roles(
        self, test_repo, mocked_datetime
    ):
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )
        TARGETS_EXP = 100
        SNAPSHOT_EXP = 50
        payload = {
            "settings": {
                "expiration": {
                    Targets.type: TARGETS_EXP,
                    Snapshot.type: SNAPSHOT_EXP,
                    "foo": 1,
                    "bar": 2,
                }
            }
        }

        result = test_repo.update_settings(payload)
        assert result == {
            "task": "update_settings",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Update Settings Succeded",
            "error": None,
            "details": {
                "invalid_roles": ["foo", "bar"],
                "updated_roles": ["targets", "snapshot"],
            },
        }
        assert test_repo.write_repository_settings.calls == [
            pretend.call(f"{Targets.type.upper()}_EXPIRATION", TARGETS_EXP),
            pretend.call(f"{Snapshot.type.upper()}_EXPIRATION", SNAPSHOT_EXP),
        ]

    def test__bootstrap_finalize(self, test_repo):
        test_repo._persist = pretend.call_recorder(lambda *a: None)
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )
        test_repo._bootstrap_online_roles = pretend.call_recorder(
            lambda *a: None
        )
        fake_roles = pretend.stub(get=pretend.call_recorder(lambda a: None))
        fake_settings = {"roles": fake_roles}

        result = test_repo._bootstrap_finalize(
            "fake_root", "task_id", fake_settings
        )

        assert result is None
        assert test_repo._persist.calls == [
            pretend.call("fake_root", repository.Root.type)
        ]
        assert test_repo.write_repository_settings.calls == [
            pretend.call("ROOT_SIGNING", None),
            pretend.call("BOOTSTRAP", "task_id"),
        ]
        assert fake_roles.get.calls == [pretend.call("delegated_roles")]
        assert test_repo._bootstrap_online_roles.calls == [
            pretend.call("fake_root", None)
        ]

    def test_bootstrap(self, monkeypatch, test_repo, mocked_datetime):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: "pre-<task-id>")
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        fake_root_md = pretend.stub(
            signatures={"keyid1": "sig1", "key2": "sig2"},
            type="root",
            signed=pretend.stub(
                roles={
                    "root": pretend.stub(
                        keyids=["keyid1", "keyid2"], threshold=2
                    ),
                    "timestamp": pretend.stub(
                        keyids=["online_key_id"], threshold=2
                    ),
                },
                keys={"online_key_id": "online_public_key"},
            ),
        )
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_root_md
        )
        test_repo._validate_signature = pretend.call_recorder(lambda *a: True)
        test_repo._validate_threshold = pretend.call_recorder(lambda *a: True)
        test_repo.save_settings = pretend.call_recorder(lambda *a: None)
        test_repo._bootstrap_finalize = pretend.call_recorder(lambda *a: None)

        payload = {
            "settings": {"services": {"number_of_delegated_bins": 2}},
            "metadata": {
                "root": {"md_k1": "md_v1"},
            },
            "task_id": "fake_task_id",
        }

        result = test_repo.bootstrap(payload)
        assert result == {
            "status": True,
            "task": "bootstrap",
            "message": "Bootstrap Processed",
            "error": None,
            "details": {
                "bootstrap": "Bootstrap finished fake_task_id",
            },
            "last_update": mocked_datetime.now(),
        }
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]
        assert repository.Metadata.from_dict.calls == [
            pretend.call(payload["metadata"]["root"])
        ]
        assert test_repo._validate_signature.calls == [
            pretend.call(fake_root_md, "sig1"),
            pretend.call(fake_root_md, "sig2"),
        ]
        assert test_repo._validate_threshold.calls == [
            pretend.call(fake_root_md)
        ]
        assert test_repo.save_settings.calls == [
            pretend.call(fake_root_md, payload["settings"])
        ]
        assert test_repo._bootstrap_finalize.calls == [
            pretend.call(fake_root_md, payload["task_id"], payload["settings"])
        ]

    def test_bootstrap_no_signatures(
        self, monkeypatch, test_repo, mocked_datetime
    ):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: "pre-<task-id>")
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        fake_root_md = pretend.stub(
            signatures=[],
            type="root",
            signed=pretend.stub(
                roles={
                    "root": pretend.stub(
                        keyids=["keyid1", "keyid2"], threshold=2
                    ),
                    "timestamp": pretend.stub(
                        keyids=["online_key_id"], threshold=2
                    ),
                },
                keys={"online_key_id": "online_public_key"},
            ),
            verify_delegate=pretend.call_recorder(lambda *a: None),
        )
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_root_md
        )
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )

        payload = {
            "settings": {"services": {"number_of_delegated_bins": 2}},
            "metadata": {
                "root": {"md_k1": "md_v1"},
            },
            "task_id": "fake_task_id",
        }

        result = test_repo.bootstrap(payload)
        assert result == {
            "task": "bootstrap",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Bootstrap Failed",
            "error": "Metadata requires at least one valid signature",
            "details": None,
        }
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]
        assert fake_root_md.verify_delegate.calls == []
        assert repository.Metadata.from_dict.calls == [
            pretend.call(payload["metadata"]["root"])
        ]
        assert test_repo.write_repository_settings.calls == [
            pretend.call("BOOTSTRAP", None),
        ]

    def test_bootstrap_invalid_signatures(
        self, monkeypatch, test_repo, mocked_datetime
    ):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: "pre-<task-id>")
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        fake_root_md = pretend.stub(
            signatures={"keyid1": "sig1", "key2": "sig2"},
            type="root",
            signed=pretend.stub(
                roles={
                    "root": pretend.stub(
                        keyids=["keyid1", "keyid2"], threshold=2
                    ),
                    "timestamp": pretend.stub(
                        keyids=["online_key_id"], threshold=2
                    ),
                },
                keys={"online_key_id": "online_public_key"},
            ),
        )
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_root_md
        )
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )
        test_repo._validate_signature = pretend.call_recorder(lambda *a: False)

        payload = {
            "settings": {"services": {"number_of_delegated_bins": 2}},
            "metadata": {
                "root": {"md_k1": "md_v1"},
            },
            "task_id": "fake_task_id",
        }

        result = test_repo.bootstrap(payload)
        assert result == {
            "task": "bootstrap",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Bootstrap Failed",
            "error": "Bootstrap has invalid signature(s)",
            "details": None,
        }
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]
        assert repository.Metadata.from_dict.calls == [
            pretend.call(payload["metadata"]["root"])
        ]
        assert test_repo._validate_signature.calls == [
            pretend.call(fake_root_md, "sig1"),
        ]
        assert test_repo.write_repository_settings.calls == [
            pretend.call("BOOTSTRAP", None),
        ]

    def test_bootstrap_with_custom_targets_and_hash_bin_delegation(
        self, monkeypatch, test_repo, mocked_datetime
    ):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: "pre-<task-id>")
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        fake_root_md = pretend.stub(
            signatures={"keyid1": "sig1", "key2": "sig2"},
        )
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_root_md
        )
        test_repo._validate_signature = pretend.call_recorder(lambda *a: True)

        payload = {
            "settings": {
                "services": {"number_of_delegated_bins": 2},
                "custom_targets": {
                    "RSTUF": {"expiration": 30, "path_prefixes": "project/a"},
                },
            },
            "metadata": {
                "root": {"md_k1": "md_v1"},
            },
            "task_id": "fake_task_id",
        }

        result = test_repo.bootstrap(payload)
        assert result == {
            "task": repository.TaskName.BOOTSTRAP,
            "status": False,
            "message": "Bootstrap Failed",
            "error": (
                "Bootstrap cannot use both hash bin delegation and"
                " custom target delegations"
            ),
            "details": None,
            "last_update": mocked_datetime.now(),
        }
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]
        assert repository.Metadata.from_dict.calls == [
            pretend.call(payload["metadata"]["root"])
        ]
        assert test_repo._validate_signature.calls == [
            pretend.call(fake_root_md, "sig1"),
            pretend.call(fake_root_md, "sig2"),
        ]

    def test_bootstrap_distributed_async_sign(
        self, monkeypatch, test_repo, mocked_datetime
    ):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: "pre-<task-id>")
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        fake_root_md = pretend.stub(
            signatures={"keyid1": "sig1", "key2": "sig2"},
            type="root",
            signed=pretend.stub(
                roles={
                    "root": pretend.stub(
                        keyids=["keyid1", "keyid2"], threshold=2
                    ),
                    "timestamp": pretend.stub(
                        keyids=["online_key_id"], threshold=2
                    ),
                },
                version=1,
                keys={"online_key_id": "online_public_key"},
            ),
            to_dict=pretend.call_recorder(lambda: "fake_metadata"),
        )
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_root_md
        )
        test_repo._validate_signature = pretend.call_recorder(lambda *a: True)
        test_repo._validate_threshold = pretend.call_recorder(lambda *a: False)
        test_repo.save_settings = pretend.call_recorder(lambda *a: None)
        test_repo._bootstrap_finalize = pretend.call_recorder(lambda *a: None)
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )

        payload = {
            "settings": {"services": {"number_of_delegated_bins": 2}},
            "metadata": {
                "root": {"md_k1": "md_v1"},
            },
            "task_id": "fake_task_id",
        }

        result = test_repo.bootstrap(payload)
        assert result == {
            "task": "bootstrap",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Bootstrap Processed",
            "error": None,
            "details": {
                "bootstrap": "Root v1 is pending signature",
            },
        }
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]
        assert repository.Metadata.from_dict.calls == [
            pretend.call(payload["metadata"]["root"])
        ]
        assert test_repo._validate_signature.calls == [
            pretend.call(fake_root_md, "sig1"),
            pretend.call(fake_root_md, "sig2"),
        ]
        assert test_repo._validate_threshold.calls == [
            pretend.call(fake_root_md)
        ]
        assert test_repo.save_settings.calls == [
            pretend.call(fake_root_md, payload["settings"])
        ]
        assert test_repo._bootstrap_finalize.calls == []
        assert test_repo.write_repository_settings.calls == [
            pretend.call("ROOT_SIGNING", "fake_metadata"),
            pretend.call("BOOTSTRAP", "signing-fake_task_id"),
        ]

    def test_bootstrap_when_bootstrap_started(
        self, monkeypatch, test_repo, mocked_datetime
    ):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: "signing-task_id")
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )

        payload = {
            "settings": {"services": {"number_of_delegated_bins": 2}},
            "metadata": {
                "root": {"md_k1": "md_v1"},
            },
            "task_id": "fake_task_id",
        }

        result = test_repo.bootstrap(payload)
        assert result == {
            "task": "bootstrap",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Bootstrap Failed",
            "error": "Bootstrap state is signing-task_id",
            "details": None,
        }
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]
        assert test_repo.write_repository_settings.calls == []

    def test_bootstrap_missing_settings(self, test_repo, mocked_datetime):
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )

        payload = {
            "metadata": {
                "root": {"md_k1": "md_v1"},
            },
        }
        result = test_repo.bootstrap(payload)
        assert result == {
            "task": "bootstrap",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Bootstrap Failed",
            "error": "No 'settings' in the payload",
            "details": None,
        }
        assert test_repo.write_repository_settings.calls == []

    def test_bootstrap_missing_metadata(self, test_repo, mocked_datetime):
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )

        payload = {
            "settings": {"k": "v"},
        }
        result = test_repo.bootstrap(payload)

        assert result == {
            "task": "bootstrap",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Bootstrap Failed",
            "error": "No 'metadata' in the payload",
            "details": None,
        }
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )
        assert test_repo.write_repository_settings.calls == []

    def test_publish_targets(self, test_repo, monkeypatch, mocked_datetime):
        @contextmanager
        def mocked_lock(lock, timeout):
            yield lock, timeout

        test_repo._db = pretend.stub()
        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
        )

        fake_crud_read_roles_with_unpublished_files = pretend.call_recorder(
            lambda *a: [("bins-0",), ("bins-e",)]
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "read_roles_with_unpublished_files",
            fake_crud_read_roles_with_unpublished_files,
        )
        test_repo._update_snapshot = pretend.call_recorder(lambda *a: 3)
        test_repo._update_timestamp = pretend.call_recorder(lambda *a: None)

        result = test_repo.publish_targets()

        assert result == {
            "task": "publish_targets",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Publish Targets Processed",
            "error": None,
            "details": {
                "target_roles": ["bins-0", "bins-e"],
            },
        }
        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=60.0),
        ]
        assert fake_crud_read_roles_with_unpublished_files.calls == [
            pretend.call(test_repo._db)
        ]
        assert test_repo._update_snapshot.calls == [
            pretend.call(["bins-0", "bins-e"])
        ]
        assert test_repo._update_timestamp.calls == [pretend.call(3)]

    def test_publish_targets_payload_bins_targets_empty(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        @contextmanager
        def mocked_lock(lock, timeout):
            yield lock, timeout

        test_repo._db = pretend.stub()
        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
        )

        fake_crud_read_roles_with_unpublished_files = pretend.call_recorder(
            lambda *a: [("bins-0",), ("bins-e",)]
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "read_roles_with_unpublished_files",
            fake_crud_read_roles_with_unpublished_files,
        )
        test_repo._update_snapshot = pretend.call_recorder(lambda *a: 3)
        test_repo._update_timestamp = pretend.call_recorder(lambda *a: None)

        payload = {"bins_targets": None}
        result = test_repo.publish_targets(payload)

        assert result == {
            "task": "publish_targets",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Publish Targets Processed",
            "error": None,
            "details": {
                "target_roles": ["bins-0", "bins-e"],
            },
        }
        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=60.0),
        ]
        assert fake_crud_read_roles_with_unpublished_files.calls == [
            pretend.call(test_repo._db)
        ]
        assert test_repo._update_snapshot.calls == [
            pretend.call(["bins-0", "bins-e"])
        ]
        assert test_repo._update_timestamp.calls == [pretend.call(3)]

    def test_publish_targets_exception_LockNotOwnedError(self, test_repo):
        @contextmanager
        def mocked_lock(lock, timeout):
            raise repository.redis.exceptions.LockNotOwnedError("timeout")

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock)
        )

        with pytest.raises(repository.redis.exceptions.LockError) as e:
            test_repo.publish_targets()

        assert "RSTUF: Task exceed `LOCK_TIMEOUT` (60 seconds)" in str(e)
        assert test_repo._redis.lock.calls == [
            pretend.call("LOCK_TARGETS", timeout=60)
        ]

    def test_publish_targets_without_targets_to_publish(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        @contextmanager
        def mocked_lock(lock, timeout):
            yield lock, timeout

        test_repo._db = pretend.stub()
        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
        )
        fake_crud_read_roles_with_unpublished_files = pretend.call_recorder(
            lambda *a: None
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "read_roles_with_unpublished_files",
            fake_crud_read_roles_with_unpublished_files,
        )

        result = test_repo.publish_targets()
        assert result == {
            "task": "publish_targets",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Publish Targets Processed",
            "error": None,
            "details": {
                "target_roles": None,
            },
        }
        assert test_repo._redis.lock.calls == [
            pretend.call("LOCK_TARGETS", timeout=60.0)
        ]
        assert (
            repository.targets_crud.read_roles_with_unpublished_files.calls
            == [pretend.call(test_repo._db)]
        )

    def test_add_targets(self, test_repo, monkeypatch, mocked_datetime):
        test_repo._db = pretend.stub()
        test_repo._get_path_succinct_role = pretend.call_recorder(
            lambda *a: "bins-e"
        )

        def fake_target(key):
            if key == "path":
                return "fake_target1.tar.gz"
            if key == "info":
                return {"k": "v"}

        fake_db_target = pretend.stub(get=pretend.call_recorder(fake_target))

        monkeypatch.setattr(
            repository.targets_crud,
            "read_file_by_path",
            pretend.call_recorder(lambda *a: None),
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "create_file",
            pretend.call_recorder(lambda *a, **kw: fake_db_target),
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "read_role_by_rolename",
            pretend.call_recorder(lambda *a: "bins-e"),
        )
        test_repo._send_publish_targets_task = pretend.call_recorder(
            lambda *a: "fake_subtask"
        )
        test_repo._update_task = pretend.call_recorder(lambda *a: True)

        payload = {
            "targets": [
                {
                    "info": {
                        "length": 11342,
                        "hashes": {
                            "blake2b-256": "716f6e863f744b9ac22c97ec7b76ea5"
                        },
                        "custom": {"task_id": "12345"},
                    },
                    "path": "file1.tar.gz",
                },
            ],
            "task_id": "fake_task_id_xyz",
        }

        fake_update_state = pretend.stub()
        result = test_repo.add_targets(payload, update_state=fake_update_state)

        assert result == {
            "task": "add_targets",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Target(s) Added",
            "error": None,
            "details": {
                "targets": ["file1.tar.gz"],
                "target_roles": ["bins-e"],
            },
        }
        assert repository.targets_crud.read_file_by_path.calls == [
            pretend.call(test_repo._db, "file1.tar.gz")
        ]
        assert repository.targets_crud.create_file.calls == [
            pretend.call(
                test_repo._db,
                repository.targets_schema.RSTUFTargetFileCreate(
                    path="file1.tar.gz",
                    info={
                        "length": 11342,
                        "hashes": {
                            "blake2b-256": "716f6e863f744b9ac22c97ec7b76ea5"
                        },
                        "custom": {"task_id": "12345"},
                    },
                    published=False,
                    action=repository.targets_schema.TargetAction.ADD,
                ),
                target_role="bins-e",
            )
        ]
        assert repository.targets_crud.read_role_by_rolename.calls == [
            pretend.call(test_repo._db, "bins-e")
        ]
        assert test_repo._get_path_succinct_role.calls == [
            pretend.call("file1.tar.gz")
        ]
        assert test_repo._send_publish_targets_task.calls == [
            pretend.call("fake_task_id_xyz", ["bins-e"])
        ]
        assert test_repo._update_task.calls == [
            pretend.call(
                {"bins-e": [fake_db_target]}, fake_update_state, "fake_subtask"
            )
        ]

    def test_add_targets_exists(self, test_repo, monkeypatch, mocked_datetime):
        test_repo._db = pretend.stub()
        test_repo._get_path_succinct_role = pretend.call_recorder(
            lambda *a: "bins-e"
        )

        def fake_target(key):
            if key == "path":
                return "fake_target1.tar.gz"
            if key == "info":
                return {"k": "v"}

        fake_db_target = pretend.stub(get=pretend.call_recorder(fake_target))
        monkeypatch.setattr(
            repository.targets_crud,
            "read_file_by_path",
            pretend.call_recorder(lambda *a: fake_db_target),
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "update_file_path_and_info",
            pretend.call_recorder(lambda *a: fake_db_target),
        )
        test_repo._send_publish_targets_task = pretend.call_recorder(
            lambda *a: "fake_subtask"
        )
        test_repo._update_task = pretend.call_recorder(lambda *a: True)

        payload = {
            "targets": [
                {
                    "info": {
                        "length": 11342,
                        "hashes": {
                            "blake2b-256": "716f6e863f744b9ac22c97ec7b76ea5"
                        },
                        "custom": {"task_id": "12345"},
                    },
                    "path": "file1.tar.gz",
                },
            ],
            "task_id": "fake_task_id_xyz",
        }

        fake_update_state = pretend.stub()
        result = test_repo.add_targets(payload, update_state=fake_update_state)

        assert result == {
            "task": "add_targets",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Target(s) Added",
            "error": None,
            "details": {
                "targets": ["file1.tar.gz"],
                "target_roles": ["bins-e"],
            },
        }
        assert test_repo._get_path_succinct_role.calls == [
            pretend.call("file1.tar.gz")
        ]
        assert test_repo._send_publish_targets_task.calls == [
            pretend.call("fake_task_id_xyz", ["bins-e"])
        ]
        assert test_repo._update_task.calls == [
            pretend.call(
                {"bins-e": [fake_db_target]}, fake_update_state, "fake_subtask"
            )
        ]
        assert repository.targets_crud.read_file_by_path.calls == [
            pretend.call(test_repo._db, "file1.tar.gz")
        ]
        assert repository.targets_crud.update_file_path_and_info.calls == [
            pretend.call(
                test_repo._db,
                fake_db_target,
                payload["targets"][0].get("path"),
                payload["targets"][0].get("info"),
            )
        ]

    def test_add_targets_without_targets(self, test_repo, mocked_datetime):
        payload = {
            "artifacts": [
                {
                    "info": {
                        "length": 11342,
                        "hashes": {
                            "blake2b-256": "716f6e863f744b9ac22c97ec7b76ea5"
                        },
                        "custom": {"task_id": "12345"},
                    },
                    "path": "file1.tar.gz",
                },
            ]
        }

        result = test_repo.add_targets(payload, update_state=pretend.stub())
        assert result == {
            "task": "add_targets",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Adding target(s) Failed",
            "error": "No 'targets' in the payload",
            "details": None,
        }

    def test_add_targets_skip_publishing(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        test_repo._db = pretend.stub()
        test_repo._get_path_succinct_role = pretend.call_recorder(
            lambda *a: "bins-e"
        )

        def fake_target(key):
            if key == "path":
                return "fake_target1.tar.gz"
            if key == "info":
                return {"k": "v"}

        fake_db_target = pretend.stub(get=pretend.call_recorder(fake_target))

        monkeypatch.setattr(
            repository.targets_crud,
            "read_file_by_path",
            pretend.call_recorder(lambda *a: None),
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "create_file",
            pretend.call_recorder(lambda *a, **kw: fake_db_target),
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "read_role_by_rolename",
            pretend.call_recorder(lambda *a: "bins-e"),
        )
        test_repo._update_task = pretend.call_recorder(lambda *a: True)

        payload = {
            "targets": [
                {
                    "info": {
                        "length": 11342,
                        "hashes": {
                            "blake2b-256": "716f6e863f744b9ac22c97ec7b76ea5"
                        },
                        "custom": {"task_id": "12345"},
                    },
                    "path": "file1.tar.gz",
                },
            ],
            "publish_targets": False,
            "task_id": "fake_task_id_xyz",
        }

        fake_update_state = pretend.stub()
        result = test_repo.add_targets(payload, update_state=fake_update_state)

        assert result == {
            "task": "add_targets",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Target(s) Added",
            "error": None,
            "details": {
                "targets": ["file1.tar.gz"],
                "target_roles": ["bins-e"],
            },
        }
        assert repository.targets_crud.read_file_by_path.calls == [
            pretend.call(test_repo._db, "file1.tar.gz")
        ]
        assert repository.targets_crud.create_file.calls == [
            pretend.call(
                test_repo._db,
                repository.targets_schema.RSTUFTargetFileCreate(
                    path="file1.tar.gz",
                    info={
                        "length": 11342,
                        "hashes": {
                            "blake2b-256": "716f6e863f744b9ac22c97ec7b76ea5"
                        },
                        "custom": {"task_id": "12345"},
                    },
                    published=False,
                    action=repository.targets_schema.TargetAction.ADD,
                ),
                target_role="bins-e",
            )
        ]
        assert repository.targets_crud.read_role_by_rolename.calls == [
            pretend.call(test_repo._db, "bins-e")
        ]
        assert test_repo._get_path_succinct_role.calls == [
            pretend.call("file1.tar.gz")
        ]
        assert test_repo._update_task.calls == [
            pretend.call({"bins-e": [fake_db_target]}, fake_update_state, None)
        ]

    def test_remove_targets(self, test_repo, monkeypatch, mocked_datetime):
        test_repo._get_path_succinct_role = pretend.call_recorder(
            lambda *a: "bins-e"
        )
        fake_db_target = pretend.stub(action="REMOVE", published=False)
        monkeypatch.setattr(
            repository.targets_crud,
            "read_file_by_path",
            pretend.call_recorder(lambda *a: fake_db_target),
        )
        fake_db_target_removed = pretend.stub()
        monkeypatch.setattr(
            repository.targets_crud,
            "update_file_action_to_remove",
            pretend.call_recorder(lambda *a: fake_db_target_removed),
        )

        payload = {
            "targets": ["file1.tar.gz", "file2.tar.gz", "release-v0.1.0.yaml"],
            "task_id": "fake_task_id_xyz",
        }
        test_repo._send_publish_targets_task = pretend.call_recorder(
            lambda *a: "fake_subtask"
        )
        test_repo._update_task = pretend.call_recorder(lambda *a: None)

        fake_update_state = pretend.stub()
        result = test_repo.remove_targets(
            payload, update_state=fake_update_state
        )

        assert result == {
            "task": "remove_targets",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Target(s) removed",
            "error": None,
            "details": {
                "deleted_targets": [
                    "file1.tar.gz",
                    "file2.tar.gz",
                    "release-v0.1.0.yaml",
                ],
                "not_found_targets": [],
            },
        }
        assert test_repo._get_path_succinct_role.calls == [
            pretend.call("file1.tar.gz"),
            pretend.call("file2.tar.gz"),
            pretend.call("release-v0.1.0.yaml"),
        ]
        assert repository.targets_crud.read_file_by_path.calls == [
            pretend.call(test_repo._db, "file1.tar.gz"),
            pretend.call(test_repo._db, "file2.tar.gz"),
            pretend.call(test_repo._db, "release-v0.1.0.yaml"),
        ]
        assert test_repo._send_publish_targets_task.calls == [
            pretend.call("fake_task_id_xyz", ["bins-e"])
        ]
        assert repository.targets_crud.update_file_action_to_remove.calls == [
            pretend.call(test_repo._db, fake_db_target),
            pretend.call(test_repo._db, fake_db_target),
            pretend.call(test_repo._db, fake_db_target),
        ]
        assert test_repo._update_task.calls == [
            pretend.call(
                {
                    "bins-e": [
                        fake_db_target_removed,
                        fake_db_target_removed,
                        fake_db_target_removed,
                    ]
                },
                fake_update_state,
                "fake_subtask",
            )
        ]

    def test_remove_targets_skip_publishing(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        test_repo._get_path_succinct_role = pretend.call_recorder(
            lambda *a: "bins-e"
        )
        fake_db_target = pretend.stub(action="REMOVE", published=False)
        monkeypatch.setattr(
            repository.targets_crud,
            "read_file_by_path",
            pretend.call_recorder(lambda *a: fake_db_target),
        )
        fake_db_target_removed = pretend.stub()
        monkeypatch.setattr(
            repository.targets_crud,
            "update_file_action_to_remove",
            pretend.call_recorder(lambda *a: fake_db_target_removed),
        )

        payload = {
            "targets": ["file1.tar.gz", "file2.tar.gz", "release-v0.1.0.yaml"],
            "publish_targets": False,
            "task_id": "fake_task_id_xyz",
        }
        test_repo._update_task = pretend.call_recorder(lambda *a: None)

        fake_update_state = pretend.stub()
        result = test_repo.remove_targets(
            payload, update_state=fake_update_state
        )

        assert result == {
            "task": "remove_targets",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Target(s) removed",
            "error": None,
            "details": {
                "deleted_targets": [
                    "file1.tar.gz",
                    "file2.tar.gz",
                    "release-v0.1.0.yaml",
                ],
                "not_found_targets": [],
            },
        }
        assert test_repo._get_path_succinct_role.calls == [
            pretend.call("file1.tar.gz"),
            pretend.call("file2.tar.gz"),
            pretend.call("release-v0.1.0.yaml"),
        ]
        assert repository.targets_crud.read_file_by_path.calls == [
            pretend.call(test_repo._db, "file1.tar.gz"),
            pretend.call(test_repo._db, "file2.tar.gz"),
            pretend.call(test_repo._db, "release-v0.1.0.yaml"),
        ]
        assert test_repo._update_task.calls == [
            pretend.call(
                {
                    "bins-e": [
                        fake_db_target_removed,
                        fake_db_target_removed,
                        fake_db_target_removed,
                    ]
                },
                fake_update_state,
                None,
            )
        ]
        assert repository.targets_crud.update_file_action_to_remove.calls == [
            pretend.call(test_repo._db, fake_db_target),
            pretend.call(test_repo._db, fake_db_target),
            pretend.call(test_repo._db, fake_db_target),
        ]

    def test_remove_targets_all_none(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        test_repo._get_path_succinct_role = pretend.call_recorder(
            lambda *a: "bin-e"
        )

        monkeypatch.setattr(
            repository.targets_crud,
            "read_file_by_path",
            pretend.call_recorder(lambda *a: None),
        )

        payload = {
            "targets": ["file2.tar.gz", "file3.tar.gz", "release-v0.1.0.yaml"]
        }

        result = test_repo.remove_targets(payload, update_state=pretend.stub())

        assert result == {
            "task": "remove_targets",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Target(s) removed",
            "error": None,
            "details": {
                "deleted_targets": [],
                "not_found_targets": [
                    "file2.tar.gz",
                    "file3.tar.gz",
                    "release-v0.1.0.yaml",
                ],
            },
        }
        assert test_repo._get_path_succinct_role.calls == [
            pretend.call("file2.tar.gz"),
            pretend.call("file3.tar.gz"),
            pretend.call("release-v0.1.0.yaml"),
        ]
        assert repository.targets_crud.read_file_by_path.calls == [
            pretend.call(test_repo._db, "file2.tar.gz"),
            pretend.call(test_repo._db, "file3.tar.gz"),
            pretend.call(test_repo._db, "release-v0.1.0.yaml"),
        ]

    def test_remove_targets_action_remove_published_true(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        test_repo._get_path_succinct_role = pretend.call_recorder(
            lambda *a: "bin-e"
        )

        fake_db_target = pretend.stub(
            action=targets_schema.TargetAction.REMOVE, published=True
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "read_file_by_path",
            pretend.call_recorder(lambda *a: fake_db_target),
        )
        payload = {
            "targets": ["file2.tar.gz", "file3.tar.gz", "release-v0.1.0.yaml"]
        }

        result = test_repo.remove_targets(payload, update_state=pretend.stub())

        assert result == {
            "task": "remove_targets",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Target(s) removed",
            "error": None,
            "details": {
                "deleted_targets": [],
                "not_found_targets": [
                    "file2.tar.gz",
                    "file3.tar.gz",
                    "release-v0.1.0.yaml",
                ],
            },
        }
        assert test_repo._get_path_succinct_role.calls == [
            pretend.call("file2.tar.gz"),
            pretend.call("file3.tar.gz"),
            pretend.call("release-v0.1.0.yaml"),
        ]
        assert repository.targets_crud.read_file_by_path.calls == [
            pretend.call(test_repo._db, "file2.tar.gz"),
            pretend.call(test_repo._db, "file3.tar.gz"),
            pretend.call(test_repo._db, "release-v0.1.0.yaml"),
        ]

    def test_remove_targets_without_targets(self, test_repo, mocked_datetime):
        payload = {"paths": []}

        result = test_repo.remove_targets(payload, update_state=pretend.stub())

        assert result == {
            "task": "remove_targets",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Removing target(s) Failed",
            "error": "No 'targets' in the payload",
            "details": None,
        }

    def test_remove_targets_empty_targets(self, test_repo, mocked_datetime):
        payload = {"targets": []}

        result = test_repo.remove_targets(payload, update_state=pretend.stub())

        assert result == {
            "task": "remove_targets",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Removing target(s) Failed",
            "error": "At list one target is required",
            "details": None,
        }

    def test__run_online_roles_bump_only_expired(
        self, monkeypatch, test_repo, mocked_datetime, caplog
    ):
        caplog.set_level(repository.logging.INFO)
        fake_targets = pretend.stub(
            signed=pretend.stub(
                expires=mocked_datetime.now(),
                version=1,
            )
        )

        fake_bins = pretend.stub(
            signed=pretend.stub(
                targets={}, version=6, expires=mocked_datetime.now()
            )
        )

        test_repo._storage_backend.get = pretend.call_recorder(
            lambda rolename: fake_targets
            if rolename == Targets.type
            else fake_bins
        )
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda a: True)
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )

        def fake_delegation_roles() -> Iterator:
            bins = ["bin-a"]
            for bin in bins:
                yield bin

        test_repo._get_delegation_roles = pretend.call_recorder(
            lambda *a: fake_delegation_roles()
        )
        test_repo._bump_and_persist = pretend.call_recorder(lambda *a: None)
        test_repo._update_snapshot = pretend.call_recorder(
            lambda **kw: "fake_snapshot"
        )
        test_repo._update_timestamp = pretend.call_recorder(
            lambda a: pretend.stub(
                signed=pretend.stub(
                    snapshot_meta=pretend.stub(version=79),
                    version=87,
                    expires=datetime.datetime(2028, 6, 16, 9, 5, 1),
                )
            )
        )
        test_repo._run_online_roles_bump()
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Targets.type),
            pretend.call("bin-a"),
        ]
        assert test_repo._get_delegation_roles.calls == [
            pretend.call(fake_targets)
        ]
        assert test_repo._bump_and_persist.calls == [
            pretend.call(fake_targets, Targets.type),
        ]
        assert test_repo._update_snapshot.calls == [
            pretend.call(target_roles=["bin-a"])
        ]
        assert test_repo._update_timestamp.calls == [
            pretend.call("fake_snapshot")
        ]
        assert "Bumped version of 'Targets' role" == caplog.messages[0]
        msg_2 = "Bumped versions of expired roles: bin-a"
        assert msg_2 == caplog.messages[1]
        assert "Snapshot version bumped: 79" in caplog.messages[2]
        assert "Timestamp version bumped: 87" in caplog.messages[3]

    def test__run_online_roles_bump_force(
        self, monkeypatch, test_repo, caplog
    ):
        caplog.set_level(repository.logging.INFO)
        fake_targets = pretend.stub(
            signed=pretend.stub(
                version=1,
            )
        )

        test_repo._storage_backend.get = pretend.call_recorder(
            lambda a: fake_targets
        )
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda a: True)
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        test_repo._bump_and_persist = pretend.call_recorder(lambda *a: None)
        test_repo._update_snapshot = pretend.call_recorder(
            lambda **kw: "fake_snapshot"
        )
        test_repo._update_timestamp = pretend.call_recorder(
            lambda *a: pretend.stub(
                signed=pretend.stub(
                    snapshot_meta=pretend.stub(version=79),
                    version=87,
                    expires=datetime.datetime(2028, 6, 16, 9, 5, 1),
                )
            )
        )
        test_repo._run_online_roles_bump(force=True)
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Targets.type),
        ]
        assert test_repo._bump_and_persist.calls == [
            pretend.call(fake_targets, Targets.type),
        ]
        assert test_repo._update_snapshot.calls == [
            pretend.call(bump_all=True)
        ]
        assert test_repo._update_timestamp.calls == [
            pretend.call("fake_snapshot")
        ]
        assert "Bumped version of 'Targets' role" == caplog.messages[0]
        msg_2 = "Targets and delegated Targets roles version bumped"
        assert msg_2 == caplog.messages[1]
        assert "Snapshot version bumped: 79" in caplog.messages[2]
        assert "Timestamp version bumped: 87" in caplog.messages[3]

    def test__run_online_roles_bump_target_targets_online_key_config_false(
        self, monkeypatch, caplog, test_repo, mocked_datetime
    ):
        caplog.set_level(repository.logging.WARNING)
        fake_targets = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(
                    succinct_roles=pretend.stub(
                        get_roles=pretend.call_recorder(lambda *a: ["bin-a"])
                    )
                ),
            )
        )
        fake_bins = pretend.stub(
            signed=pretend.stub(
                targets={}, version=6, expires=mocked_datetime.now()
            )
        )

        test_repo._storage_backend.get = pretend.call_recorder(
            lambda rolename: fake_targets
            if rolename == Targets.type
            else fake_bins
        )
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: False)
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        test_repo._update_snapshot = pretend.call_recorder(
            lambda **kw: "fake_snapshot"
        )
        test_repo._update_timestamp = pretend.call_recorder(
            lambda *a: pretend.stub(
                signed=pretend.stub(
                    snapshot_meta=pretend.stub(version=79),
                    version=87,
                    expires=datetime.datetime(2028, 6, 16, 9, 5, 1),
                )
            )
        )
        test_repo._run_online_roles_bump()
        msg = "targets don't use online key, skipping 'Targets' role"
        assert msg == caplog.messages[0]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Targets.type),
            pretend.call("bin-a"),
        ]
        assert test_repo._update_snapshot.calls == [
            pretend.call(target_roles=["bin-a"])
        ]
        assert test_repo._update_timestamp.calls == [
            pretend.call("fake_snapshot")
        ]

    def test__run_online_roles_bump_warning_missing_config(
        self, caplog, test_repo, mocked_datetime
    ):
        caplog.set_level(repository.logging.CRITICAL)
        fake_targets = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(
                    succinct_roles=pretend.stub(
                        get_roles=pretend.call_recorder(lambda *a: ["bin-a"])
                    )
                ),
            )
        )

        fake_bins = pretend.stub(
            signed=pretend.stub(
                targets={}, version=6, expires=mocked_datetime.now()
            )
        )

        test_repo._storage_backend.get = pretend.call_recorder(
            lambda rolename: fake_targets
            if rolename == Targets.type
            else fake_bins
        )
        test_repo._settings.get_fresh = pretend.call_recorder(lambda *a: None)
        test_repo._update_snapshot = pretend.call_recorder(
            lambda *a, **kw: "fake_snapshot"
        )
        test_repo._update_timestamp = pretend.call_recorder(
            lambda *a: pretend.stub(
                signed=pretend.stub(
                    snapshot_meta=pretend.stub(version=79),
                    version=87,
                    expires=mocked_datetime.now(),
                )
            )
        )
        test_repo._run_online_roles_bump()
        msg = "No configuration found for TARGETS_ONLINE_KEY"
        assert msg == caplog.messages[0]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Targets.type),
            pretend.call("bin-a"),
        ]
        assert test_repo._update_snapshot.calls == [
            pretend.call(target_roles=["bin-a"])
        ]
        assert test_repo._update_timestamp.calls == [
            pretend.call("fake_snapshot")
        ]

    def test__run_online_roles_bump_no_changes(self, test_repo, caplog):
        caplog.set_level(repository.logging.DEBUG)
        fake_time = datetime.datetime(2054, 6, 16, 8, 5, 1)
        fake_targets = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(
                    succinct_roles=pretend.stub(
                        get_roles=pretend.call_recorder(lambda *a: ["bin-a"])
                    )
                ),
                expires=fake_time,
                version=1,
            )
        )

        fake_bins = pretend.stub(
            signed=pretend.stub(targets={}, version=6, expires=fake_time)
        )

        test_repo._storage_backend.get = pretend.call_recorder(
            lambda rolename: fake_targets
            if rolename == Targets.type
            else fake_bins
        )

        test_repo._run_online_roles_bump()
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Targets.type),
            pretend.call("bin-a"),
        ]
        msg_1 = "No configuration found for TARGETS_ONLINE_KEY"
        assert msg_1 == caplog.messages[0]
        msg_2 = "All delegated roles have more than 1 hour(s) to expire"
        assert msg_2 in caplog.messages[1]
        assert "Snapshot version bumped:" not in caplog.messages
        assert "Timestamp version bumped:" not in caplog.messages

    def test__run_online_roles_bump_StorageError(self, test_repo):
        test_repo._storage_backend.get = pretend.raiser(
            StorageError("Overwrite it")
        )

        with pytest.raises(StorageError):
            test_repo._run_online_roles_bump()

    def test_bump_snapshot(self, test_repo, mocked_datetime):
        fake_snapshot = pretend.stub(
            signed=pretend.stub(
                meta={},
                expires=mocked_datetime.now(),
                version=87,
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_snapshot
        )
        test_repo._update_snapshot = pretend.call_recorder(
            lambda *a: "fake_snapshot"
        )
        test_repo._update_timestamp = pretend.call_recorder(
            lambda *a: pretend.stub(
                signed=pretend.stub(
                    snapshot_meta=pretend.stub(version=79),
                    version=87,
                    expires=datetime.datetime(2028, 6, 16, 9, 5, 1),
                )
            )
        )

        test_repo.bump_snapshot()
        assert test_repo._storage_backend.get.calls == [
            pretend.call("snapshot")
        ]
        assert test_repo._update_snapshot.calls == [pretend.call()]
        assert test_repo._update_timestamp.calls == [
            pretend.call("fake_snapshot")
        ]

    def test_bump_snapshot_unexpired(self, test_repo):
        fake_snapshot = pretend.stub(
            signed=pretend.stub(
                meta={},
                expires=datetime.datetime(2080, 6, 16, 9, 5, 1),
                version=87,
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_snapshot
        )

        test_repo.bump_snapshot()
        assert test_repo._storage_backend.get.calls == [
            pretend.call("snapshot")
        ]

    def test_bump_snapshot_check_force_is_acknowledged(
        self, test_repo, caplog
    ):
        # Reproduce a bug where we checked if we need to update snapshot with:
        # if (snapshot.signed.expires - datetime.now()) < timedelta(
        #    hours=self._hours_before_expire or True
        # )
        # The problem is that `force` is used inside timedelta function call
        # which could potentially distort the end result.

        # In order to reproduce it we need to have such a high snapshot
        # expiration date, that this timedelta check cannot be true, but
        # because we pass "force=True" we expect that snapshot must be updated.
        # The current situation as described in the previous comment is that
        # in this case snapshot won't be updated.
        caplog.set_level(repository.logging.DEBUG)
        fake_snapshot = pretend.stub(
            signed=pretend.stub(
                expires=datetime.datetime(2080, 6, 16, 9, 5, 1),
                version=87,
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_snapshot
        )
        test_repo._update_snapshot = pretend.call_recorder(
            lambda *a: "fake_snapshot"
        )
        test_repo._update_timestamp = pretend.call_recorder(
            lambda *a: pretend.stub(
                signed=pretend.stub(
                    snapshot_meta=pretend.stub(version=79),
                    version=87,
                    expires=datetime.datetime(2028, 6, 16, 9, 5, 1),
                )
            )
        )

        test_repo.bump_snapshot(force=True)
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Snapshot.type)
        ]
        assert test_repo._update_snapshot.calls == [pretend.call()]
        assert test_repo._update_timestamp.calls == [
            pretend.call("fake_snapshot")
        ]

    def test_bump_snapshot_not_found(self, test_repo):
        test_repo._storage_backend.get = pretend.raiser(StorageError)
        with pytest.raises(StorageError):
            test_repo.bump_snapshot()

    def test_bump_online_roles(self, monkeypatch, test_repo):
        @contextmanager
        def mocked_lock(lock, timeout):
            yield lock, timeout

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock)
        )
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: "fake_bootstrap_id")
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        test_repo._run_online_roles_bump = pretend.call_recorder(
            lambda **kw: None
        )

        result = test_repo.bump_online_roles()
        assert result is True
        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=60)
        ]
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]
        assert test_repo._run_online_roles_bump.calls == [
            pretend.call(force=False)
        ]

    def test_bump_online_roles_when_no_bootstrap(self, monkeypatch, test_repo):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: None)
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        result = test_repo.bump_online_roles()
        assert result is False
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]

    def test_bump_online_roles_exception_LockNotOwnedError(
        self, monkeypatch, test_repo
    ):
        @contextmanager
        def mocked_lock(lock, timeout):
            raise repository.redis.exceptions.LockNotOwnedError("timeout")

        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: "fake_bootstrap_id")
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock)
        )
        with pytest.raises(repository.redis.exceptions.LockError) as e:
            test_repo.bump_online_roles()

        assert "RSTUF: Task exceed `LOCK_TIMEOUT` (60 seconds)" in str(e)
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]
        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=60)
        ]

    def test__trusted_root_update(self, test_repo):
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k1": "v1"})},
                version=2,
                type=repository.Root.type,
            ),
            verify_delegate=pretend.call_recorder(lambda *a: None),
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k1": "v1"})},
                version=1,
            ),
            verify_delegate=pretend.call_recorder(lambda *a: None),
        )

        result = test_repo._trusted_root_update(
            fake_old_root_md, fake_new_root_md
        )
        assert result is None
        assert fake_new_root_md.verify_delegate.calls == [
            pretend.call(repository.Root.type, fake_new_root_md)
        ]
        assert fake_old_root_md.verify_delegate.calls == [
            pretend.call(repository.Root.type, fake_new_root_md)
        ]

    def test__trusted_root_update_fail_current_verify_delegate(
        self, test_repo
    ):
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k1": "v1"})},
                version=2,
                type=repository.Root.type,
            ),
            verify_delegate=pretend.raiser(
                TypeError("Call is valid only on delegator metadata")
            ),
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k1": "v1"})},
                version=1,
            ),
            verify_delegate=pretend.call_recorder(lambda *a: None),
        )

        with pytest.raises(TypeError) as err:
            test_repo._trusted_root_update(fake_old_root_md, fake_new_root_md)
        assert "Call is valid only on delegator metadata" in str(err)

    def test__trusted_root_update_bad_version(self, test_repo):
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k1": "v1"})},
                version=4,
                type=repository.Root.type,
            ),
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k1": "v1"})},
                version=1,
            ),
        )

        with pytest.raises(repository.BadVersionNumberError) as err:
            test_repo._trusted_root_update(fake_old_root_md, fake_new_root_md)
        assert "Expected root version 2 instead got version 4" in str(err)

    def test__trusted_root_update_bad_type(self, test_repo):
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k1": "v1"})},
                version=2,
                type=repository.Snapshot.type,
            ),
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"root": pretend.stub(keyids={"k1": "v1"})},
                version=1,
            ),
        )

        with pytest.raises(repository.RepositoryError) as err:
            test_repo._trusted_root_update(fake_old_root_md, fake_new_root_md)
        assert "Expected 'root', got 'snapshot'" in str(err)

    def test__root_metadata_update(self, test_repo, mocked_datetime):
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k1": "v1"})},
                version=2,
            )
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k1": "v1"})},
                version=1,
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_old_root_md
        )
        test_repo._trusted_root_update = pretend.call_recorder(lambda *a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)

        result = test_repo._root_metadata_update(fake_new_root_md)

        assert result == {
            "task": "metadata_update",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Metadata Update Processed",
            "error": None,
            "details": {
                "role": "root",
            },
        }
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Root.type)
        ]
        assert test_repo._trusted_root_update.calls == [
            pretend.call(fake_old_root_md, fake_new_root_md)
        ]
        assert test_repo._persist.calls == [
            pretend.call(fake_new_root_md, repository.Root.type)
        ]

    def test__root_metadata_update_signatures_pending(
        self, test_repo, mocked_datetime
    ):
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k1": "v1"})},
                version=2,
            )
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k1": "v1"})},
                version=1,
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_old_root_md
        )
        test_repo._trusted_root_update = pretend.raiser(
            repository.UnsignedMetadataError()
        )

        fake_new_root_md.to_dict = pretend.call_recorder(lambda: "fake dict")
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: "fake"
        )

        result = test_repo._root_metadata_update(fake_new_root_md)

        assert result == {
            "task": "metadata_update",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Metadata Update Processed",
            "error": None,
            "details": {
                "role": "root",
                "update": "Root v2 is pending signatures",
            },
        }
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Root.type)
        ]
        assert test_repo.write_repository_settings.calls == [
            pretend.call("ROOT_SIGNING", "fake dict")
        ]

    def test__root_metadata_update_not_trusted(
        self, test_repo, mocked_datetime
    ):
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k1": "v1"})},
                version=2,
            )
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k1": "v1"})},
                version=1,
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_old_root_md
        )
        test_repo._trusted_root_update = pretend.raiser(
            repository.BadVersionNumberError("Version v3 instead v2")
        )

        result = test_repo._root_metadata_update(fake_new_root_md)

        assert result == {
            "task": "metadata_update",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Metadata Update Failed",
            "error": "Failed to verify the trust: Version v3 instead v2",
            "details": None,
        }
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Root.type)
        ]

    def test__root_metadata_update_online_key(
        self, test_repo, mocked_datetime
    ):
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k1": "v1"})},
                version=2,
            )
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k2": "v2"})},
                version=1,
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_old_root_md
        )
        test_repo._trusted_root_update = pretend.call_recorder(lambda *a: None)

        @contextmanager
        def mocked_lock(lock, timeout):
            yield lock, timeout

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
        )
        test_repo._persist = pretend.call_recorder(lambda *a: None)
        test_repo._run_online_roles_bump = pretend.call_recorder(
            lambda **kw: None
        )

        result = test_repo._root_metadata_update(fake_new_root_md)

        assert result == {
            "task": "metadata_update",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Metadata Update Processed",
            "error": None,
            "details": {
                "role": "root",
            },
        }
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Root.type)
        ]
        assert test_repo._trusted_root_update.calls == [
            pretend.call(fake_old_root_md, fake_new_root_md)
        ]
        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=60.0)
        ]
        assert test_repo._persist.calls == [
            pretend.call(fake_new_root_md, repository.Root.type)
        ]
        assert test_repo._run_online_roles_bump.calls == [
            pretend.call(force=True)
        ]

    def test__root_metadata_update_online_key_lock_timeout(
        self, monkeypatch, test_repo
    ):
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k1": "v1"})},
                version=2,
            )
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k2": "v2"})},
                version=1,
            )
        )
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: "fake_bootstrap_id")
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_old_root_md
        )
        test_repo._trusted_root_update = pretend.call_recorder(lambda *a: None)

        @contextmanager
        def mocked_lock(lock, timeout):
            raise repository.redis.exceptions.LockNotOwnedError("timeout")

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
        )
        with pytest.raises(repository.redis.exceptions.LockError) as e:
            test_repo._root_metadata_update(fake_new_root_md)

        assert "RSTUF: Task exceed `LOCK_TIMEOUT` (60 seconds)" in str(e)
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Root.type)
        ]
        assert test_repo._trusted_root_update.calls == [
            pretend.call(fake_old_root_md, fake_new_root_md)
        ]

    def test_metadata_update(self, monkeypatch, test_repo):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: "fake_bootstrap_id")
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: "fake_md"
        )
        test_repo._root_metadata_update = pretend.call_recorder(
            lambda *a: "fake_result"
        )

        payload = {"metadata": {"root": "root_metadata"}}
        result = test_repo.metadata_update(payload)

        assert result == "fake_result"
        assert repository.Metadata.from_dict.calls == [
            pretend.call("root_metadata")
        ]
        assert test_repo._root_metadata_update.calls == [
            pretend.call("fake_md")
        ]
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]

    def test_metadata_update_invalid_metadata_type(
        self, monkeypatch, test_repo, mocked_datetime
    ):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: "fake_bootstrap_id")
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )

        payload = {"metadata": {"bins": "bins_metadata"}}
        result = test_repo.metadata_update(payload)
        assert result == {
            "task": "metadata_update",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Metadata Update Failed",
            "error": "Unsupported Metadata type",
            "details": None,
        }
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]

    def test_metadata_update_no_metadata(
        self, monkeypatch, test_repo, mocked_datetime
    ):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: "fake_bootstrap_id")
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )

        payload = {}
        result = test_repo.metadata_update(payload)

        assert result == {
            "task": "metadata_update",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Metadata Update Failed",
            "error": "No 'metadata' in the payload",
            "details": None,
        }
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]

    def test_metadata_update_no_bootstrap(
        self, monkeypatch, test_repo, mocked_datetime
    ):
        payload = {"metadata": {"root": {}}}
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: None)
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )

        result = test_repo.metadata_update(payload)
        assert result == {
            "task": "metadata_update",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Metadata Update Failed",
            "error": "Metadata Update requires a completed bootstrap",
            "details": None,
        }
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]

    def test_metadata_rotation_deprecation_warning(self, test_repo, caplog):
        caplog.set_level(repository.logging.WARNING)
        payload = {"metadata": {"root": "fake_root"}}

        test_repo.metadata_update = pretend.call_recorder(lambda *a: "result")

        result = test_repo.metadata_rotation(payload)
        assert result == "result"
        assert test_repo.metadata_update.calls == [pretend.call(payload, None)]
        assert caplog.record_tuples == [
            (
                "root",
                30,
                (
                    "`metadata_rotation` is deprecated, use `metadata_update` "
                    "instead. It will be removed in version 1.0.0."
                ),
            )
        ]

    def test__validate_signature(self, test_repo):
        fake_root_md = pretend.stub(
            signatures=[{"keyid": "k1", "sig": "s1"}],
            type="root",
            signed=pretend.stub(
                roles={"root": pretend.stub(keyids={"k1": "s1", "k2": "s2"})},
                keys={
                    "k1": pretend.stub(
                        verify_signature=pretend.call_recorder(lambda *a: None)
                    )
                },
            ),
        )
        fake_signature = pretend.stub(keyid="k1")

        repository.CanonicalJSONSerializer = pretend.call_recorder(
            lambda: pretend.stub(
                serialize=pretend.call_recorder(lambda *a: b"signed_bytes")
            )
        )

        result = test_repo._validate_signature(fake_root_md, fake_signature)
        assert result is True
        assert fake_root_md.signed.keys["k1"].verify_signature.calls == [
            pretend.call(fake_signature, b"signed_bytes")
        ]

    def test__validate_signature_keyid_not_authorized(self, caplog, test_repo):
        caplog.set_level(repository.logging.INFO)
        fake_root_md = pretend.stub(
            signatures=[{"keyid": "k1", "sig": "s1"}],
            type="root",
            signed=pretend.stub(
                roles={"root": pretend.stub(keyids={"k1": "s1", "k2": "s2"})},
                keys={
                    "k1": pretend.stub(
                        verify_signature=pretend.call_recorder(lambda *a: None)
                    )
                },
            ),
        )
        fake_signature = pretend.stub(keyid="k3")

        repository.CanonicalJSONSerializer = pretend.call_recorder(
            lambda: pretend.stub(
                serialize=pretend.call_recorder(lambda *a: "signed_bytes")
            )
        )

        result = test_repo._validate_signature(fake_root_md, fake_signature)
        assert result is False
        assert caplog.record_tuples == [
            ("root", 20, "signature 'k3' not authorized")
        ]

    def test__validate_signature_no_key_for_keyid(self, caplog, test_repo):
        caplog.set_level(repository.logging.INFO)
        fake_root_md = pretend.stub(
            signatures=[{"keyid": "k1", "sig": "s1"}],
            type="root",
            signed=pretend.stub(
                roles={"root": pretend.stub(keyids={"k1": "s1", "k2": "s2"})},
                keys={
                    "k3": pretend.stub(
                        verify_signature=pretend.call_recorder(lambda *a: None)
                    )
                },
            ),
        )
        fake_signature = pretend.stub(keyid="k1")

        repository.CanonicalJSONSerializer = pretend.call_recorder(
            lambda: pretend.stub(
                serialize=pretend.call_recorder(lambda *a: "signed_bytes")
            )
        )

        result = test_repo._validate_signature(fake_root_md, fake_signature)
        assert result is False
        assert caplog.record_tuples == [
            ("root", 20, "no key for signature 'k1'")
        ]

    def test__validate_signature_invalid_signature(self, caplog, test_repo):
        caplog.set_level(repository.logging.INFO)
        fake_root_md = pretend.stub(
            signatures=[{"keyid": "k1", "sig": "s1"}],
            type="root",
            signed=pretend.stub(
                roles={"root": pretend.stub(keyids={"k1": "s1", "k2": "s2"})},
                keys={
                    "k1": pretend.stub(
                        verify_signature=pretend.raiser(
                            repository.UnverifiedSignatureError("invalid")
                        )
                    )
                },
            ),
        )
        fake_signature = pretend.stub(keyid="k1")

        repository.CanonicalJSONSerializer = pretend.call_recorder(
            lambda: pretend.stub(
                serialize=pretend.call_recorder(lambda *a: "signed_bytes")
            )
        )

        result = test_repo._validate_signature(fake_root_md, fake_signature)
        assert result is False
        assert caplog.record_tuples == [("root", 20, "signature 'k1' invalid")]

    def test__validate_threshold(self, test_repo):
        fake_metadata = pretend.stub(
            verify_delegate=pretend.call_recorder(lambda *a: None)
        )

        result = test_repo._validate_threshold(fake_metadata)

        assert result is True
        assert fake_metadata.verify_delegate.calls == [
            pretend.call(repository.Root.type, fake_metadata)
        ]

    def test__validate_threshold_missing_signatures(self, caplog, test_repo):
        caplog.set_level(repository.logging.INFO)
        fake_metadata = pretend.stub(
            verify_delegate=pretend.raiser(
                repository.UnsignedMetadataError("signed 1/2")
            )
        )

        result = test_repo._validate_threshold(fake_metadata)

        assert result is False
        assert caplog.record_tuples == [("root", 20, "signed 1/2")]

    def test_sign_metadata_finalize_bootstrap(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        def fake_get_fresh(key):
            if key == "BOOTSTRAP":
                return "signing-<task-id>"
            if key == "ROOT_SIGNING":
                return {"metadata": "fake"}

        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(fake_get_fresh),
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        fake_root_md = repository.Metadata(repository.Root())
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_root_md
        )
        fake_signature = pretend.stub(keyid="fake_sig")
        repository.Signature.from_dict = pretend.call_recorder(
            lambda *a: fake_signature
        )
        test_repo._validate_signature = pretend.call_recorder(lambda *a: True)
        test_repo._validate_threshold = pretend.call_recorder(lambda *a: True)
        test_repo._bootstrap_finalize = pretend.call_recorder(lambda *a: None)

        payload = {
            "role": "root",
            "signature": {"keyid": "keyid2", "sig": "sig2"},
        }
        result = test_repo.sign_metadata(payload)

        assert result == {
            "task": "sign_metadata",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Signature Processed",
            "error": None,
            "details": {
                "bootstrap": "Bootstrap Finished",
            },
        }
        assert fake_settings.get_fresh.calls == [
            pretend.call("ROOT_SIGNING"),
            pretend.call("BOOTSTRAP"),
        ]
        assert repository.Metadata.from_dict.calls == [
            pretend.call({"metadata": "fake"})
        ]
        assert test_repo._validate_signature.calls == [
            pretend.call(fake_root_md, fake_signature)
        ]
        assert test_repo._validate_threshold.calls == [
            pretend.call(fake_root_md)
        ]
        assert test_repo._bootstrap_finalize.calls == [
            pretend.call(fake_root_md, "<task-id>")
        ]

    def test_sign_metadata_no_role_signing(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: None),
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )

        payload = {
            "role": "root",
            "signature": {"keyid": "keyid2", "sig": "sig2"},
        }
        result = test_repo.sign_metadata(payload)

        assert result == {
            "task": "sign_metadata",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Signature Failed",
            "error": f"No signatures pending for {payload['role']}",
            "details": None,
        }
        assert fake_settings.get_fresh.calls == [
            pretend.call("ROOT_SIGNING"),
        ]

    def test_sign_metadata_invalid_role_type(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        def fake_get_fresh(key):
            if key == "BOOTSTRAP":
                return "signing-<task-id>"
            if key == "ROOT_SIGNING":
                return {"metadata": "fake"}

        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(fake_get_fresh),
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        fake_root_md = repository.Targets(version=2)
        fake_root_md.signed = repository.Targets()
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_root_md
        )

        payload = {
            "role": "root",
            "signature": {"keyid": "keyid2", "sig": "sig2"},
        }
        result = test_repo.sign_metadata(payload)

        assert result == {
            "task": "sign_metadata",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Signature Failed",
            "error": "Expected 'root', got 'targets'",
            "details": None,
        }
        assert fake_settings.get_fresh.calls == [
            pretend.call("ROOT_SIGNING"),
        ]

    def test_sign_metadata_invalid_signature(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        def fake_get_fresh(key):
            if key == "BOOTSTRAP":
                return "signing-<task-id>"
            if key == "ROOT_SIGNING":
                return {"metadata": "fake"}

        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(fake_get_fresh),
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        fake_root_md = repository.Metadata(repository.Root())
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_root_md
        )
        fake_signature = pretend.stub(keyid="fake_sig")
        repository.Signature.from_dict = pretend.call_recorder(
            lambda *a: fake_signature
        )
        test_repo._validate_signature = pretend.call_recorder(lambda *a: False)

        payload = {
            "role": "root",
            "signature": {"keyid": "keyid2", "sig": "sig2"},
        }
        result = test_repo.sign_metadata(payload)

        assert result == {
            "task": "sign_metadata",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Signature Failed",
            "error": "Invalid signature",
            "details": None,
        }
        assert fake_settings.get_fresh.calls == [
            pretend.call("ROOT_SIGNING"),
            pretend.call("BOOTSTRAP"),
        ]
        assert repository.Metadata.from_dict.calls == [
            pretend.call({"metadata": "fake"})
        ]
        assert test_repo._validate_signature.calls == [
            pretend.call(fake_root_md, fake_signature)
        ]

    def test_sign_metadata_bootstrap_unfinished(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        def fake_get_fresh(key):
            if key == "BOOTSTRAP":
                return "signing-<task-id>"
            if key == "ROOT_SIGNING":
                return {"metadata": "fake"}

        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(fake_get_fresh),
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        fake_root_md = repository.Metadata(repository.Root())
        fake_root_md.to_dict = pretend.call_recorder(lambda: "fake_metadata")
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_root_md
        )
        fake_signature = pretend.stub(keyid="fake_sig")
        repository.Signature.from_dict = pretend.call_recorder(
            lambda *a: fake_signature
        )
        test_repo._validate_signature = pretend.call_recorder(lambda *a: True)
        test_repo._validate_threshold = pretend.call_recorder(lambda *a: False)
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )

        payload = {
            "role": "root",
            "signature": {"keyid": "keyid2", "sig": "sig2"},
        }
        result = test_repo.sign_metadata(payload)

        assert result == {
            "task": "sign_metadata",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Signature Processed",
            "error": None,
            "details": {
                "bootstrap": (
                    f"Root v{fake_root_md.signed.version} is pending "
                    "signatures"
                ),
            },
        }
        assert fake_settings.get_fresh.calls == [
            pretend.call("ROOT_SIGNING"),
            pretend.call("BOOTSTRAP"),
        ]
        assert repository.Metadata.from_dict.calls == [
            pretend.call({"metadata": "fake"})
        ]
        assert test_repo._validate_signature.calls == [
            pretend.call(fake_root_md, fake_signature)
        ]
        assert test_repo._validate_threshold.calls == [
            pretend.call(fake_root_md)
        ]
        assert test_repo.write_repository_settings.calls == [
            pretend.call("ROOT_SIGNING", "fake_metadata")
        ]

    def test_sign_metadata__update__bad_role_type(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        fake_signature = pretend.stub(keyid="fake")
        repository.Signature.from_dict = pretend.call_recorder(
            lambda *a: fake_signature
        )
        payload = {"signature": "fake", "role": "foo"}
        result = test_repo.sign_metadata(payload)

        assert result == {
            "task": "sign_metadata",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Signature Failed",
            "error": "Expected 'root', got 'foo'",
            "details": None,
        }

    def test_sign_metadata__update__invalid_signature(
        self,
        test_repo,
        monkeypatch,
        mocked_datetime,
    ):
        def fake_get_fresh(key):
            if key == "BOOTSTRAP":
                return "<task-id>"
            if key == "ROOT_SIGNING":
                return {"metadata": "fake"}

        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(fake_get_fresh),
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        fake_signature = pretend.stub(keyid="fake")
        repository.Signature.from_dict = pretend.call_recorder(
            lambda *a: fake_signature
        )
        fake_trusted_root = repository.Metadata(
            signed=repository.Root(version=1)
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda r: fake_trusted_root
        )
        fake_new_root = repository.Metadata(signed=repository.Root(version=2))
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_new_root
        )

        # Use `next` below to mock subsequent calls
        fake_signature_result = iter((False, False))
        test_repo._validate_signature = pretend.call_recorder(
            lambda *a: next(fake_signature_result)
        )

        payload = {"signature": "fake", "role": "root"}
        result = test_repo.sign_metadata(payload)

        assert result == {
            "task": "sign_metadata",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Signature Failed",
            "error": "Invalid signature",
            "details": None,
        }

    def test_sign_metadata__update__invalid_threshold__trusted_and_new(
        self,
        test_repo,
        monkeypatch,
        mocked_datetime,
    ):
        def fake_get_fresh(key):
            if key == "BOOTSTRAP":
                return "<task-id>"
            if key == "ROOT_SIGNING":
                return {"metadata": "fake"}

        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(fake_get_fresh),
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        fake_signature = pretend.stub(keyid="fake")
        repository.Signature.from_dict = pretend.call_recorder(
            lambda *a: fake_signature
        )
        fake_trusted_root = repository.Metadata(
            signed=repository.Root(version=1)
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda r: fake_trusted_root
        )
        fake_new_root = repository.Metadata(signed=repository.Root(version=2))
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_new_root
        )
        fake_new_root.to_dict = pretend.call_recorder(lambda: "fake")
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: "fake"
        )

        # Use `next` below to mock subsequent calls
        fake_signature_result = iter((True, False))
        fake_threshold_result = iter((False, False))

        test_repo._validate_signature = pretend.call_recorder(
            lambda *a: next(fake_signature_result)
        )
        test_repo._validate_threshold = pretend.call_recorder(
            lambda *a: next(fake_threshold_result)
        )

        # Call sign_metadata with fake payload
        # All deserialization and validation is mocked
        payload = {"signature": "fake", "role": "root"}
        result = test_repo.sign_metadata(payload)

        assert result == {
            "task": "sign_metadata",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Signature Processed",
            "error": None,
            "details": {
                "update": "Root v2 is pending signatures",
            },
        }

    def test_sign_metadata__update__invalid_threshold__trusted(
        self,
        test_repo,
        monkeypatch,
        mocked_datetime,
    ):
        def fake_get_fresh(key):
            if key == "BOOTSTRAP":
                return "<task-id>"
            if key == "ROOT_SIGNING":
                return {"metadata": "fake"}

        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(fake_get_fresh),
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        fake_signature = pretend.stub(keyid="fake")
        repository.Signature.from_dict = pretend.call_recorder(
            lambda *a: fake_signature
        )
        fake_trusted_root = repository.Metadata(
            signed=repository.Root(version=1)
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda r: fake_trusted_root
        )
        fake_new_root = repository.Metadata(signed=repository.Root(version=2))
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_new_root
        )
        fake_new_root.to_dict = pretend.call_recorder(lambda: "fake")
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: "fake"
        )

        # Use `next` below to mock subsequent calls
        fake_signature_result = iter((False, True))
        fake_threshold_result = iter((False, True))

        test_repo._validate_signature = pretend.call_recorder(
            lambda *a: next(fake_signature_result)
        )
        test_repo._validate_threshold = pretend.call_recorder(
            lambda *a: next(fake_threshold_result)
        )

        # Call sign_metadata with fake payload
        # All deserialization and validation is mocked
        payload = {"signature": "fake", "role": "root"}
        result = test_repo.sign_metadata(payload)

        assert result == {
            "task": "sign_metadata",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Signature Processed",
            "error": None,
            "details": {
                "update": "Root v2 is pending signatures",
            },
        }

    def test_sign_metadata__update__invalid_threshold__new(
        self,
        test_repo,
        monkeypatch,
        mocked_datetime,
    ):
        """Test: New root does not meet signature threshold."""

        def fake_get_fresh(key):
            if key == "BOOTSTRAP":
                return "<task-id>"
            if key == "ROOT_SIGNING":
                return {"metadata": "fake"}

        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(fake_get_fresh),
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        fake_signature = pretend.stub(keyid="fake")
        repository.Signature.from_dict = pretend.call_recorder(
            lambda *a: fake_signature
        )
        fake_trusted_root = repository.Metadata(
            signed=repository.Root(version=1)
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda r: fake_trusted_root
        )
        fake_new_root = repository.Metadata(signed=repository.Root(version=2))
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_new_root
        )
        fake_new_root.to_dict = pretend.call_recorder(lambda: "fake")
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: "fake"
        )

        # Use `next` below to mock subsequent calls
        fake_signature_result = iter((True, True))
        fake_threshold_result = iter((True, False))

        test_repo._validate_signature = pretend.call_recorder(
            lambda *a: next(fake_signature_result)
        )
        test_repo._validate_threshold = pretend.call_recorder(
            lambda *a: next(fake_threshold_result)
        )

        # Call sign_metadata with fake payload
        # All deserialization and validation is mocked
        payload = {"signature": "fake", "role": "root"}
        result = test_repo.sign_metadata(payload)

        assert result == {
            "task": "sign_metadata",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Signature Processed",
            "error": None,
            "details": {
                "update": "Root v2 is pending signatures",
            },
        }

    def test_sign_metadata__update__valid_threshold(
        self,
        test_repo,
        monkeypatch,
        mocked_datetime,
    ):
        def fake_get_fresh(key):
            if key == "BOOTSTRAP":
                return "<task-id>"
            if key == "ROOT_SIGNING":
                return {"metadata": "fake"}

        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(fake_get_fresh),
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        fake_signature = pretend.stub(keyid="fake")
        repository.Signature.from_dict = pretend.call_recorder(
            lambda *a: fake_signature
        )
        fake_trusted_root = repository.Metadata(
            signed=repository.Root(version=1)
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda r: fake_trusted_root
        )
        fake_new_root = repository.Metadata(signed=repository.Root(version=2))
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_new_root
        )
        fake_new_root.to_dict = pretend.call_recorder(lambda: "fake")
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: "fake"
        )

        # Use `next` below to mock subsequent calls
        fake_signature_result = iter((True, True))
        fake_threshold_result = iter((True, True))

        test_repo._validate_signature = pretend.call_recorder(
            lambda *a: next(fake_signature_result)
        )
        test_repo._validate_threshold = pretend.call_recorder(
            lambda *a: next(fake_threshold_result)
        )

        # Call sign_metadata with fake payload
        # All deserialization and validation is mocked
        payload = {"signature": "fake", "role": "root"}
        result = test_repo.sign_metadata(payload)

        assert result == {
            "task": "sign_metadata",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Signature Processed",
            "error": None,
            "details": {
                "update": "Metadata update finished",
            },
        }

    def test_delete_sign_metadata_bootstrap_signing_state(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        def fake_get_fresh(key: str):
            if key == "BOOTSTRAP":
                return "signing-<task-id>"
            if key == "ROOT_SIGNING":
                return {"metadata": "fake"}

        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: fake_get_fresh(*a)),
        )
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(fake_get_fresh),
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )

        result = test_repo.delete_sign_metadata({"role": "root"})
        message = (
            "Deletion of root metadata successful, signing process stopped"
        )
        assert result == {
            "task": "delete_sign_metadata",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": message,
            "error": None,
            "details": {
                "bootstrap": "Bootstrap process has been stopped",
            },
        }
        assert fake_settings.get_fresh.calls == [
            pretend.call("ROOT_SIGNING"),
            pretend.call("BOOTSTRAP"),
        ]
        assert test_repo.write_repository_settings.calls == [
            pretend.call("ROOT_SIGNING", None),
            pretend.call("BOOTSTRAP", None),
        ]

    def test_delete_sign_metadata_bootstrap_finished_root_signing(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        def fake_get_fresh(key: str):
            if key == "BOOTSTRAP":
                # BOOTSTRAP has finished
                return "<task-id>"
            if key == "ROOT_SIGNING":
                return {"metadata": "fake"}

        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: fake_get_fresh(*a)),
        )
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(fake_get_fresh),
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )

        result = test_repo.delete_sign_metadata({"role": "root"})
        message = (
            "Deletion of root metadata successful, signing process stopped"
        )
        assert result == {
            "task": "delete_sign_metadata",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": message,
            "error": None,
            "details": None,
        }
        assert fake_settings.get_fresh.calls == [
            pretend.call("ROOT_SIGNING"),
            pretend.call("BOOTSTRAP"),
        ]
        assert test_repo.write_repository_settings.calls == [
            pretend.call("ROOT_SIGNING", None),
        ]

    def test_delete_sign_metadata_non_root(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        def fake_get_fresh(key: str):
            if key == "TARGETS_SIGNING":
                return {"metadata": "fake"}

        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: fake_get_fresh(*a)),
        )
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(fake_get_fresh),
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )

        result = test_repo.delete_sign_metadata({"role": "targets"})
        message = (
            "Deletion of targets metadata successful, signing process stopped"
        )
        assert result == {
            "task": "delete_sign_metadata",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": message,
            "error": None,
            "details": None,
        }
        assert fake_settings.get_fresh.calls == [
            pretend.call("TARGETS_SIGNING"),
        ]
        assert test_repo.write_repository_settings.calls == [
            pretend.call("TARGETS_SIGNING", None),
        ]

    def test_delete_sign_metadata_role_not_in_signing_status(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        def fake_get_fresh(key: str):
            if key == "ROOT_SIGNING":
                return None

        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: fake_get_fresh(*a)),
        )
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(fake_get_fresh),
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )

        result = test_repo.delete_sign_metadata({"role": "root"})
        assert result == {
            "task": "delete_sign_metadata",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Deletion of root metadata failed.",
            "error": "The root role is not in a signing process.",
            "details": None,
        }
        assert fake_settings.get_fresh.calls == [
            pretend.call("ROOT_SIGNING"),
        ]

    def test_delete_sign_metadata_no_role_is_given(
        self, test_repo, mocked_datetime
    ):
        result = test_repo.delete_sign_metadata({})
        assert result == {
            "task": "delete_sign_metadata",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Deletion of metadata pending signatures failed",
            "error": "No role provided for deletion.",
            "details": None,
        }
