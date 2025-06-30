# SPDX-FileCopyrightText: 2023-2025 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import datetime
from contextlib import contextmanager
from copy import copy, deepcopy
from datetime import timezone

import pretend
import pytest
from celery.exceptions import ChordError
from celery.result import states
from securesystemslib.exceptions import StorageError
from tuf.api.metadata import (
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    Targets,
    Timestamp,
)

from repository_service_tuf_worker import Dynaconf, repository
from repository_service_tuf_worker.models import targets_schema
from repository_service_tuf_worker.models.targets import crud

REPOSITORY_PATH = "repository_service_tuf_worker.repository"


class TestRoles:
    def test_is_role_true_all_roles(self):
        all = [Root.type, Targets.type, Snapshot.type, Timestamp.type, "bins"]
        for role in all:
            assert repository.Roles.is_role(role) is True

    def test_is_role_false_str(self):
        all_roles = ["root1", "1root", "root.json", "f", "bin", "bin0", ""]
        for role in all_roles:
            assert repository.Roles.is_role(role) is False

    def test_is_role_false_other_input(self):
        all_roles = [1, None, True, [], {}]
        for role in all_roles:
            assert repository.Roles.is_role(role) is False


class TestMetadataRepository:
    def test_basic_init(self, monkeypatch):
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

    def test_online_key_property_from_redis(self, test_repo, monkeypatch):
        fake_key_dict = {"keyval": "foo", "keyid": "key_id"}
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda a: copy(fake_key_dict))
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        key = pretend.stub(keyid="key_id")
        fake_key_obj = pretend.stub(
            from_dict=pretend.call_recorder(lambda *a: key)
        )
        monkeypatch.setattr(f"{REPOSITORY_PATH}.Key", fake_key_obj)
        result = test_repo._online_key
        assert result == key
        assert fake_settings.get_fresh.calls == [pretend.call("ONLINE_KEY")]
        assert fake_key_obj.from_dict.calls == [
            pretend.call(fake_key_dict.pop("keyid"), fake_key_dict)
        ]

    def test_online_key_property_from_storage(self, test_repo, monkeypatch):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda a: None)
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        key_dict = {"keyval": "old_bar"}
        expected_dict = copy(key_dict)
        key = pretend.stub(
            keyid="key_id", to_dict=pretend.call_recorder(lambda: key_dict)
        )
        fake_root = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["key_id"])},
                keys={"key_id": key},
                version=2,
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_root
        )
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )
        result = test_repo._online_key
        assert result == key
        assert fake_settings.get_fresh.calls == [pretend.call("ONLINE_KEY")]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Root.type)
        ]
        expected_dict["keyid"] = key.keyid
        assert key.to_dict.calls == [pretend.call()]
        assert test_repo.write_repository_settings.calls == [
            pretend.call("ONLINE_KEY", expected_dict)
        ]

    @pytest.mark.parametrize(
        "mock_setting, expected",
        [
            (
                None,
                None,
            ),
            (
                "pre-<somehash",
                "pre",
            ),
            ("signing", "signing"),
            (
                "anythingelse",
                "finished",
            ),
        ],
    )
    def test_bootstrap_state(
        self, monkeypatch, test_repo, mock_setting, expected
    ):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: mock_setting)
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        result = test_repo.bootstrap_state
        assert result == expected
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]

    @pytest.mark.parametrize(
        "mocked_targets, expected_result",
        [
            (
                Metadata(
                    Targets(
                        delegations=pretend.stub(succinct_roles=pretend.stub())
                    )
                ),
                True,
            ),
            (
                Metadata(
                    Targets(delegations=pretend.stub(succinct_roles=None))
                ),
                False,
            ),
        ],
    )
    def test_uses_succinct_roles(
        self, test_repo, mocked_targets, expected_result
    ):
        test_repo._storage_backend = pretend.stub(
            get=pretend.call_recorder(lambda *a: mocked_targets)
        )

        assert test_repo.uses_succinct_roles == expected_result
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Targets.type)
        ]

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
        test_repo._worker_settings.DB_SERVER = "postgresql://fake-sql:5433"
        test_repo._worker_settings.DB_USER = "psql"
        test_repo._worker_settings.DB_PASSWORD = "psqlpass"
        fake_sql = pretend.stub()
        repository.rstuf_db = pretend.call_recorder(lambda *a: fake_sql)

        test_repo.refresh_settings()

        assert test_repo._worker_settings.SQL == fake_sql
        assert repository.rstuf_db.calls == [
            pretend.call("postgresql://psql:psqlpass@fake-sql:5433")
        ]

    def test_refresh_settings_with_sql_user_missing_password(self, test_repo):
        test_repo._worker_settings.DB_SERVER = "postgresql://fake-sql:5433"
        test_repo._worker_settings.DB_USER = "psql"

        with pytest.raises(AttributeError) as e:
            test_repo.refresh_settings()

        assert "'Settings' object has no attribute 'RSTUF_DB_PASSWORD'" in str(
            e
        )

    def test_refresh_settings_with_sql_user_missing_scheme(self, test_repo):
        test_repo._worker_settings.DB_SERVER = "fake-sql"
        test_repo._worker_settings.DB_USER = "psql"

        with pytest.raises(AttributeError) as e:
            test_repo.refresh_settings()

        assert "'RSTUF_DB_SERVER' requires a scheme" in str(e)

    def test_refresh_settings_with_sql_user_password_secrets(
        self, test_repo, monkeypatch
    ):
        test_repo._worker_settings.DB_SERVER = "postgresql://fake-sql:5433"
        test_repo._worker_settings.DB_USER = "psql"
        test_repo._worker_settings.DB_PASSWORD = "/run/secrets/DB_PASSWORD"
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
        test_repo._worker_settings.DB_SERVER = "fake-sql:5433"
        test_repo._worker_settings.DB_USER = "psql"
        test_repo._worker_settings.DB_PASSWORD = "/run/secrets/DB_PASSWORD"
        monkeypatch.setitem(
            repository.__builtins__,
            "open",
            pretend.raiser(PermissionError("No permission /run/secrets/*")),
        )

        with pytest.raises(OSError) as e:
            test_repo.refresh_settings()

        assert "No permission /run/secrets/*" in str(e)
        assert "No permission /run/secrets/*" == caplog.messages[0]

    def test__sign(self, test_repo, monkeypatch):
        fake_key_dict = {"keyval": "foo", "keyid": "keyid"}
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda a: copy(fake_key_dict))
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        fake_key = pretend.stub(keyid="new_key")
        fake_key_obj = pretend.stub(
            from_dict=pretend.call_recorder(lambda *a: fake_key)
        )
        monkeypatch.setattr(f"{REPOSITORY_PATH}.Key", fake_key_obj)
        fake_md = pretend.stub(
            sign=pretend.call_recorder(lambda *a, **kw: None),
        )
        test_repo._signer_store = pretend.stub(
            get=pretend.call_recorder(lambda *a: "key_signer_1")
        )

        test_result = test_repo._sign(fake_md)

        assert test_result is None
        assert fake_settings.get_fresh.calls == [pretend.call("ONLINE_KEY")]
        assert fake_key_obj.from_dict.calls == [
            pretend.call(fake_key_dict.pop("keyid"), fake_key_dict)
        ]
        assert test_repo._signer_store.get.calls == [pretend.call(fake_key)]
        assert fake_md.sign.calls == [pretend.call("key_signer_1")]

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

    @pytest.mark.parametrize(
        "role, mocked_metadata, expected",
        [
            (
                "bins-0",
                pretend.stub(
                    signed=pretend.stub(
                        expires=datetime.datetime(
                            2015, 6, 16, 9, 5, 1, tzinfo=timezone.utc
                        )
                    )
                ),
                "bins-0",
            ),
            (
                "bins-1",
                pretend.stub(
                    signed=pretend.stub(
                        expires=datetime.datetime(
                            2029, 6, 16, 9, 5, 1, tzinfo=timezone.utc
                        )
                    )
                ),
                None,
            ),
        ],
    )
    def test__is_expired(
        self, mocked_metadata, role, expected, test_repo, mocked_datetime
    ):
        test_repo._storage_backend = pretend.stub(
            get=pretend.call_recorder(lambda *a: mocked_metadata)
        )

        result = test_repo._is_expired(role)

        assert result == expected
        assert test_repo._storage_backend.get.calls == [pretend.call(role)]

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
            2023, 6, 15, 9, 5, 1, tzinfo=timezone.utc
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
        test_repo._sign = pretend.call_recorder(lambda *a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)

        timestamp = Metadata(Timestamp(expires=datetime.datetime.now()))
        result = test_repo._bump_and_persist(timestamp, Timestamp.type)

        assert result is None
        assert test_repo._bump_expiry.calls == [
            pretend.call(timestamp, Timestamp.type, None)
        ]
        assert test_repo._bump_version.calls == [pretend.call(timestamp)]
        assert test_repo._sign.calls == [pretend.call(timestamp, None)]
        assert test_repo._persist.calls == [
            pretend.call(timestamp, Timestamp.type)
        ]

    def test__bump_and_persist_without_persist(self, test_repo):
        test_repo._bump_expiry = pretend.call_recorder(lambda *a: None)
        test_repo._bump_version = pretend.call_recorder(lambda *a: None)
        test_repo._sign = pretend.call_recorder(lambda *a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)

        timestamp = Metadata(Timestamp(expires=datetime.datetime.now()))
        result = test_repo._bump_and_persist(
            timestamp, Timestamp.type, persist=False
        )

        assert result is None
        assert test_repo._bump_expiry.calls == [
            pretend.call(timestamp, Timestamp.type, None)
        ]
        assert test_repo._bump_version.calls == [pretend.call(timestamp)]
        assert test_repo._sign.calls == [pretend.call(timestamp, None)]
        assert test_repo._persist.calls == []

    @pytest.mark.parametrize(
        "snapshot_meta, expired_snapshot, expected_result",
        [
            # Case 0: New snapshot meta and snapshot is not expired
            (
                {"bins-9.json": MetaFile(1)},
                False,
                Metadata(
                    Snapshot(
                        version=6,
                        expires=datetime.datetime(2035, 6, 16, 9, 5, 1),
                        meta={"bins-9.json": MetaFile(1)},
                    )
                ),
            ),
            # Case 1: New snapshot meta and snapshot is expired
            (
                {"bins-9.json": MetaFile(1)},
                True,
                Metadata(
                    Snapshot(
                        version=6,
                        expires=datetime.datetime(2035, 6, 16, 9, 5, 1),
                        meta={"bins-9.json": MetaFile(1)},
                    )
                ),
            ),
            # Case 2: No new snapshot meta and snapshot is not expired
            (
                None,
                False,
                Metadata(
                    Snapshot(
                        version=5,
                        expires=datetime.datetime(2019, 6, 16, 9, 5, 1),
                        meta={},
                    )
                ),
            ),
        ],
    )
    def test_update_snapshot(
        self,
        monkeypatch,
        test_repo,
        snapshot_meta,
        expired_snapshot,
        expected_result,
    ):

        monkeypatch.setattr(
            repository.targets_crud,
            "update_roles_expire_version_by_rolenames",
            pretend.call_recorder(lambda *a: None),
        )

        mocked_snapshot = Metadata(
            Snapshot(
                version=5,
                expires=datetime.datetime(2019, 6, 16, 9, 5, 1),
                meta={},
            )
        )
        test_repo._storage_backend = pretend.stub(
            get=pretend.call_recorder(lambda *a: mocked_snapshot)
        )

        def fake__bump_and_persist(md, role, **kw):
            md.signed.version += 1
            md.signed.expires = datetime.datetime(2035, 6, 16, 9, 5, 1)
            # md.signed.meta.update(snapshot_meta)

        test_repo._bump_and_persist = pretend.call_recorder(
            fake__bump_and_persist
        )
        test_repo._is_expired = pretend.call_recorder(
            lambda *a: expired_snapshot
        )

        result = test_repo.update_snapshot(snapshot_meta, {"database_meta"})

        assert result.to_dict() == expected_result.to_dict()
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Snapshot.type)
        ]
        if mocked_snapshot.signed.version == 5:
            assert test_repo._bump_and_persist.calls == []
            assert (
                repository.targets_crud.update_roles_expire_version_by_rolenames.calls  # noqa
                == []
            )
        else:
            assert test_repo._bump_and_persist.calls == [
                pretend.call(mocked_snapshot, Snapshot.type)
            ]
            assert (
                repository.targets_crud.update_roles_expire_version_by_rolenames.calls  # noqa
                == [pretend.call(test_repo._db, {"database_meta"})]
            )

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
            lambda rolename: (
                mocked_snapshot
                if rolename == Snapshot.type
                else mocked_targets
            )
        )

        def fake__bump_and_persist(md, role, **kw):
            md.signed.version += 1

        test_repo._bump_and_persist = pretend.call_recorder(
            fake__bump_and_persist
        )

        result = test_repo._update_snapshot()

        assert result is None
        assert mocked_snapshot.signed.version == snapshot_version
        assert mocked_snapshot.signed.meta == {}
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Roles.SNAPSHOT.value),
            pretend.call(repository.Roles.TARGETS.value),
        ]
        assert test_repo._bump_and_persist.calls == []

    def test__update_targets_delegations_key_bins(
        self, test_repo, monkeypatch
    ):
        fake_key_dict = {"keyval": "foo", "keyid": "keyid"}
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda a: copy(fake_key_dict))
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        fake_key = pretend.stub(keyid="new_key")
        fake_key_obj = pretend.stub(
            from_dict=pretend.call_recorder(lambda *a: fake_key)
        )
        monkeypatch.setattr(f"{REPOSITORY_PATH}.Key", fake_key_obj)
        fake_root = pretend.stub(
            signed=pretend.stub(
                roles={Targets.type: pretend.stub(keyids=["old_keyid"])}
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda a: fake_root
        )
        fake_targets = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(succinct_roles=True),
                revoke_key=pretend.call_recorder(lambda a: None),
                add_key=pretend.call_recorder(lambda a: None),
            )
        )

        result = test_repo._update_targets_delegations_key(fake_targets)
        assert result is None
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Root.type)
        ]
        assert fake_settings.get_fresh.calls == [pretend.call("ONLINE_KEY")]
        assert fake_key_obj.from_dict.calls == [
            pretend.call(fake_key_dict.pop("keyid"), fake_key_dict)
        ]
        assert fake_targets.signed.revoke_key.calls == [
            pretend.call("old_keyid")
        ]
        assert fake_targets.signed.add_key.calls == [pretend.call(fake_key)]

    def test__update_targets_delegations_online_key_not_changed(
        self, test_repo, monkeypatch
    ):
        fake_key_dict = {"keyval": "foo", "keyid": "keyid"}
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda a: copy(fake_key_dict))
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        fake_key = pretend.stub(keyid="online_key")
        fake_key_obj = pretend.stub(
            from_dict=pretend.call_recorder(lambda *a: fake_key)
        )
        monkeypatch.setattr(f"{REPOSITORY_PATH}.Key", fake_key_obj)
        fake_root = pretend.stub(
            signed=pretend.stub(
                roles={Targets.type: pretend.stub(keyids=["online_key"])}
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda a: fake_root
        )

        result = test_repo._update_targets_delegations_key("targets")
        assert result is None
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Root.type)
        ]
        assert fake_settings.get_fresh.calls == [pretend.call("ONLINE_KEY")]
        assert fake_key_obj.from_dict.calls == [
            pretend.call(fake_key_dict.pop("keyid"), fake_key_dict)
        ]

    @pytest.mark.parametrize(
        "expired, targets_expired, expected",
        [
            # Case 0: Role and Targets are expired
            (True, True, ["bins-0", "targets"]),
            # Case 1: Role is expired but Targets are not
            (True, False, ["bins-0"]),
            # Case 2: All roles
            (
                False,
                False,
                ["bins-0", "bins-1", "bins-2", "bins-3", "targets"],
            ),
        ],
    )
    def test_get_delegated_rolenames(
        self,
        monkeypatch,
        test_repo,
        expired,
        targets_expired,
        expected,
    ):
        monkeypatch.setattr(
            repository.targets_crud,
            "read_roles_rolenames_expired",
            pretend.call_recorder(lambda *a: ["bins-0"]),
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "read_all_roles_rolenames",
            pretend.call_recorder(
                lambda *a: ["bins-0", "bins-1", "bins-2", "bins-3"]
            ),
        )
        test_repo._is_expired = pretend.call_recorder(
            lambda a: targets_expired
        )

        result = test_repo.get_delegated_rolenames(expired)
        assert result == expected

    def test__get_role_for_artifact_path(self, test_repo):
        fake_targets = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(
                    get_roles_for_target=pretend.call_recorder(
                        lambda a: iter([("bins-e", False)])
                    )
                ),
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_targets
        )
        result = test_repo._get_role_for_artifact_path(
            "v0.0.1/test_path.tar.gz"
        )

        assert result == "bins-e"
        delegations = fake_targets.signed.delegations
        assert delegations.get_roles_for_target.calls == [
            pretend.call("v0.0.1/test_path.tar.gz")
        ]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Targets.type)
        ]

    def test__get_role_for_artifact_path_no_role_for_target(self, test_repo):
        fake_targets = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(
                    get_roles_for_target=pretend.call_recorder(
                        lambda a: iter([])
                    )
                ),
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_targets
        )
        result = test_repo._get_role_for_artifact_path(
            "v0.0.1/test_path.tar.gz"
        )

        assert result is None
        delegations = fake_targets.signed.delegations
        assert delegations.get_roles_for_target.calls == [
            pretend.call("v0.0.1/test_path.tar.gz")
        ]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Targets.type)
        ]

    def test__update_task(self, test_repo, mocked_datetime):
        test_repo._db = pretend.stub(
            refresh=pretend.call_recorder(lambda *a: None),
            bind=pretend.stub(
                url=pretend.stub(
                    drivername="mysql+pymysql",
                )
            ),
            commit=pretend.call_recorder(lambda: None),
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
        assert test_repo._db.commit.calls == [pretend.call(), pretend.call()]
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

    def test__update_task_when_postgresql(self, test_repo, mocked_datetime):
        test_repo._db = pretend.stub(
            refresh=pretend.call_recorder(lambda *a: None),
            bind=pretend.stub(
                url=pretend.stub(
                    drivername="postgresql",
                )
            ),
            commit=pretend.call_recorder(lambda: None),
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
        assert test_repo._db.commit.calls == []  # No commit for PostgreSQL
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
            refresh=pretend.call_recorder(lambda *a: None),
            bind=pretend.stub(
                url=pretend.stub(
                    drivername="postgresql",
                )
            ),
        )

        fake_target = pretend.stub(published=True)
        fake_bin_targets = {
            "bin-e": [fake_target],
            "bin-f": [fake_target, fake_target],
        }
        fake_update_state = pretend.call_recorder(lambda *a, **kw: None)
        fake_subtask = pretend.stub(
            status=states.FAILURE,
            task_id="publish_artifacts-fakeid",
            result=PermissionError("failed to write in the storage"),
        )

        with pytest.raises(ChordError) as err:
            test_repo._update_task(
                fake_bin_targets, fake_update_state, fake_subtask
            )

        assert "Failed to execute publish_artifacts-fakeid" in str(err)
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
            signatures=[{"keyid": "sig1"}, {"keyid": "sig2"}],
            signed=pretend.stub(
                type="root",
                roles={"root": pretend.stub(threshold=1)},
            ),
        )
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )
        payload = {
            "root": {"expiration": 365},
            "targets": {"expiration": 365},
            "snapshot": {"expiration": 1},
            "timestamp": {"expiration": 1},
            "bins": {"expiration": 30, "number_of_delegated_bins": 4},
        }

        result = test_repo.save_settings(fake_root_md, payload)
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

    def test_update_settings(self, test_repo, mocked_datetime, monkeypatch):
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )
        TARGETS_EXP = 100
        SNAPSHOT_EXP = 50
        TIMESTAMP_EXP = 20
        BINS_EXP = 5
        BINS = repository.Roles.BINS.value

        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: 30)
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )

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
        assert fake_settings.get_fresh.calls == [
            pretend.call(f"{Targets.type.upper()}_EXPIRATION"),
            pretend.call(f"{Snapshot.type.upper()}_EXPIRATION"),
            pretend.call(f"{Timestamp.type.upper()}_EXPIRATION"),
            pretend.call(f"{BINS.upper()}_EXPIRATION"),
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
        self, test_repo, mocked_datetime, monkeypatch
    ):
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )
        TARGETS_EXP = 100
        SNAPSHOT_EXP = 50

        def _get_fresh(expiration_str: str):
            if expiration_str == "TARGETS_EXPIRATION":
                return TARGETS_EXP
            elif expiration_str == "SNAPSHOT_EXPIRATION":
                return SNAPSHOT_EXP
            else:
                return None

        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda a: _get_fresh(a))
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )

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
        assert fake_settings.get_fresh.calls == [
            pretend.call(f"{Targets.type.upper()}_EXPIRATION"),
            pretend.call(f"{Snapshot.type.upper()}_EXPIRATION"),
            pretend.call("FOO_EXPIRATION"),
            pretend.call("BAR_EXPIRATION"),
        ]
        assert test_repo.write_repository_settings.calls == [
            pretend.call(f"{Targets.type.upper()}_EXPIRATION", TARGETS_EXP),
            pretend.call(f"{Snapshot.type.upper()}_EXPIRATION", SNAPSHOT_EXP),
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
            signed=pretend.stub(
                type="root",
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
            "settings": {
                "roles": {
                    "root": {"expiration": 365},
                    "targets": {"expiration": 365},
                    "snapshot": {"expiration": 1},
                    "timestamp": {"expiration": 1},
                    "bins": {"expiration": 30, "number_of_delegated_bins": 4},
                }
            },
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
            pretend.call(fake_root_md, payload["settings"]["roles"])
        ]
        assert test_repo._bootstrap_finalize.calls == [
            pretend.call(fake_root_md, payload["task_id"])
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
            signed=pretend.stub(
                type="root",
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
            "settings": {
                "roles": {
                    "root": {"expiration": 365},
                    "targets": {"expiration": 365},
                    "snapshot": {"expiration": 1},
                    "timestamp": {"expiration": 1},
                    "bins": {"expiration": 30, "number_of_delegated_bins": 4},
                }
            },
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
            signed=pretend.stub(
                type="root",
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
            "settings": {
                "roles": {
                    "root": {"expiration": 365},
                    "targets": {"expiration": 365},
                    "snapshot": {"expiration": 1},
                    "timestamp": {"expiration": 1},
                    "bins": {"expiration": 30, "number_of_delegated_bins": 4},
                }
            },
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
                "roles": {
                    "root": {"expiration": 365},
                    "targets": {"expiration": 365},
                    "snapshot": {"expiration": 1},
                    "timestamp": {"expiration": 1},
                    "bins": {"expiration": 30, "number_of_delegated_bins": 4},
                    "delegated_roles": {
                        "foo": {
                            "expiration": 30,
                            "path_patterns": ["project/f"],
                        },
                        "bar": {
                            "expiration": 60,
                            "path_patterns": ["project/b"],
                        },
                    },
                }
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
            signed=pretend.stub(
                type="root",
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
            "settings": {
                "roles": {
                    "root": {"expiration": 365},
                    "targets": {"expiration": 365},
                    "snapshot": {"expiration": 1},
                    "timestamp": {"expiration": 1},
                    "bins": {"expiration": 30, "number_of_delegated_bins": 4},
                }
            },
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
            pretend.call(fake_root_md, payload["settings"]["roles"])
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
            "settings": {
                "roles": {
                    "root": {"expiration": 365},
                    "targets": {"expiration": 365},
                    "snapshot": {"expiration": 1},
                    "timestamp": {"expiration": 1},
                    "bins": {"expiration": 30, "number_of_delegated_bins": 4},
                }
            },
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

    def test_publish_artifacts(self, test_repo, monkeypatch, mocked_datetime):
        @contextmanager
        def mocked_lock(lock, timeout):
            yield lock, timeout

        test_repo._db = pretend.stub(
            bind=pretend.stub(url=pretend.stub(drivername="postgresql"))
        )
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
        test_repo._update_snapshot = pretend.call_recorder(lambda *a, **kw: 3)
        test_repo._update_timestamp = pretend.call_recorder(
            lambda *a, **kw: None
        )

        result = test_repo.publish_artifacts()

        assert result == {
            "task": "publish_artifacts",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Publish Artifacts Processed",
            "error": None,
            "details": {
                "target_roles": ["bins-0", "bins-e"],
            },
        }
        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=500.0),
        ]
        assert fake_crud_read_roles_with_unpublished_files.calls == [
            pretend.call(test_repo._db)
        ]
        assert test_repo._update_snapshot.calls == [
            pretend.call(target_roles=["bins-0", "bins-e"])
        ]
        assert test_repo._update_timestamp.calls == [
            pretend.call(3, skip=True)
        ]

    def test_publish_artifacts_payload_delegated_targets(
        self, test_repo, mocked_datetime
    ):
        @contextmanager
        def mocked_lock(lock, timeout):
            yield lock, timeout

        test_repo._db = pretend.stub(
            bind=pretend.stub(url=pretend.stub(drivername="postgresql"))
        )
        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
        )

        test_repo._update_snapshot = pretend.call_recorder(lambda *a, **kw: 3)
        test_repo._update_timestamp = pretend.call_recorder(
            lambda *a, **kw: None
        )

        payload = {"delegated_targets": ["bins-0", "bins-e"]}
        result = test_repo.publish_artifacts(payload)

        assert result == {
            "task": "publish_artifacts",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Publish Artifacts Processed",
            "error": None,
            "details": {
                "target_roles": ["bins-0", "bins-e"],
            },
        }
        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=500.0),
        ]
        assert test_repo._update_snapshot.calls == [
            pretend.call(target_roles=["bins-0", "bins-e"])
        ]
        assert test_repo._update_timestamp.calls == [
            pretend.call(3, skip=True)
        ]

    def test_publish_artifacts_payload_with_delegated_targets_empty(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        @contextmanager
        def mocked_lock(lock, timeout):
            yield lock, timeout

        test_repo._db = pretend.stub(
            bind=pretend.stub(url=pretend.stub(drivername="postgresql"))
        )
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
        test_repo._update_snapshot = pretend.call_recorder(lambda *a, **kw: 3)
        test_repo._update_timestamp = pretend.call_recorder(
            lambda *a, **kw: None
        )

        payload = {"delegated_targets": None}
        result = test_repo.publish_artifacts(payload)

        assert result == {
            "task": "publish_artifacts",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Publish Artifacts Processed",
            "error": None,
            "details": {
                "target_roles": ["bins-0", "bins-e"],
            },
        }
        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=500.0),
        ]
        assert fake_crud_read_roles_with_unpublished_files.calls == [
            pretend.call(test_repo._db)
        ]
        assert test_repo._update_snapshot.calls == [
            pretend.call(target_roles=["bins-0", "bins-e"])
        ]
        assert test_repo._update_timestamp.calls == [
            pretend.call(3, skip=True)
        ]

    def test_publish_artifacts_exception_LockNotOwnedError(self, test_repo):
        @contextmanager
        def mocked_lock(lock, timeout):
            raise repository.redis.exceptions.LockNotOwnedError("timeout")

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock)
        )

        with pytest.raises(repository.redis.exceptions.LockError) as e:
            test_repo.publish_artifacts()

        assert "RSTUF: Task exceed `LOCK_TIMEOUT` (500 seconds)" in str(e)
        assert test_repo._redis.lock.calls == [
            pretend.call("LOCK_TARGETS", timeout=500)
        ]

    def test_publish_artifacts_without_targets_to_publish(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        @contextmanager
        def mocked_lock(lock, timeout):
            yield lock, timeout

        test_repo._db = pretend.stub(
            bind=pretend.stub(url=pretend.stub(drivername="postgresql"))
        )
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

        result = test_repo.publish_artifacts()
        assert result == {
            "task": "publish_artifacts",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Publish Artifacts Processed",
            "error": None,
            "details": {
                "target_roles": None,
            },
        }
        assert test_repo._redis.lock.calls == [
            pretend.call("LOCK_TARGETS", timeout=500.0)
        ]
        assert (
            repository.targets_crud.read_roles_with_unpublished_files.calls
            == [pretend.call(test_repo._db)]
        )

    def test_add_artifacts(self, test_repo, monkeypatch, mocked_datetime):
        test_repo._db = pretend.stub(
            bind=pretend.stub(url=pretend.stub(drivername="postgresql"))
        )
        test_repo._get_role_for_artifact_path = pretend.call_recorder(
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
        test_repo._send_publish_artifacts_task = pretend.call_recorder(
            lambda *a: "fake_subtask"
        )
        test_repo._update_task = pretend.call_recorder(lambda *a: True)

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
            ],
            "task_id": "fake_task_id_xyz",
        }

        fake_update_state = pretend.stub()
        result = test_repo.add_artifacts(
            payload, update_state=fake_update_state
        )

        assert result == {
            "task": "add_artifacts",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Artifact(s) Added",
            "error": None,
            "details": {
                "added_artifacts": ["file1.tar.gz"],
                "invalid_paths": [],
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
        assert test_repo._get_role_for_artifact_path.calls == [
            pretend.call("file1.tar.gz")
        ]
        assert test_repo._send_publish_artifacts_task.calls == [
            pretend.call("fake_task_id_xyz", ["bins-e"])
        ]
        assert test_repo._update_task.calls == [
            pretend.call(
                {"bins-e": [fake_db_target]}, fake_update_state, "fake_subtask"
            )
        ]

    def test_add_artifacts_exists(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        test_repo._db = pretend.stub(
            bind=pretend.stub(url=pretend.stub(drivername="postgresql"))
        )
        test_repo._get_role_for_artifact_path = pretend.call_recorder(
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
        test_repo._send_publish_artifacts_task = pretend.call_recorder(
            lambda *a: "fake_subtask"
        )
        test_repo._update_task = pretend.call_recorder(lambda *a: True)

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
            ],
            "task_id": "fake_task_id_xyz",
        }

        fake_update_state = pretend.stub()
        result = test_repo.add_artifacts(
            payload, update_state=fake_update_state
        )

        assert result == {
            "task": "add_artifacts",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Artifact(s) Added",
            "error": None,
            "details": {
                "added_artifacts": ["file1.tar.gz"],
                "invalid_paths": [],
                "target_roles": ["bins-e"],
            },
        }
        assert test_repo._get_role_for_artifact_path.calls == [
            pretend.call("file1.tar.gz")
        ]
        assert test_repo._send_publish_artifacts_task.calls == [
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
                payload["artifacts"][0].get("path"),
                payload["artifacts"][0].get("info"),
            )
        ]

    def test_add_artifacts_without_targets(self, test_repo, mocked_datetime):
        payload = {}

        result = test_repo.add_artifacts(payload, update_state=pretend.stub())
        assert result == {
            "task": "add_artifacts",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Adding artifact(s) Failed",
            "error": "No 'artifacts' in the payload",
            "details": None,
        }

    def test_add_artifacts_skip_publishing(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        test_repo._db = pretend.stub(
            bind=pretend.stub(url=pretend.stub(drivername="postgresql"))
        )
        test_repo._get_role_for_artifact_path = pretend.call_recorder(
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
            ],
            "publish_artifacts": False,
            "task_id": "fake_task_id_xyz",
        }

        fake_update_state = pretend.stub()
        result = test_repo.add_artifacts(
            payload, update_state=fake_update_state
        )

        assert result == {
            "task": "add_artifacts",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Artifact(s) Added",
            "error": None,
            "details": {
                "added_artifacts": ["file1.tar.gz"],
                "invalid_paths": [],
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
        assert test_repo._get_role_for_artifact_path.calls == [
            pretend.call("file1.tar.gz")
        ]
        assert test_repo._update_task.calls == [
            pretend.call({"bins-e": [fake_db_target]}, fake_update_state, None)
        ]

    def test_add_artifacts_invalid_path(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        test_repo._db = pretend.stub(
            bind=pretend.stub(url=pretend.stub(drivername="postgresql"))
        )
        test_repo._get_role_for_artifact_path = pretend.call_recorder(
            lambda *a: None
        )

        def fake_artifact(key):
            if key == "path":
                return "fake_target1.tar.gz"
            if key == "info":
                return {"k": "v"}

        fake_db_target = pretend.stub(get=pretend.call_recorder(fake_artifact))

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
        test_repo._send_publish_artifacts_task = pretend.call_recorder(
            lambda *a: "fake_subtask"
        )
        test_repo._update_task = pretend.call_recorder(lambda *a: True)

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
            ],
            "task_id": "fake_task_id_xyz",
        }

        fake_update_state = pretend.stub()
        result = test_repo.add_artifacts(
            payload, update_state=fake_update_state
        )

        assert result == {
            "task": "add_artifacts",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Artifact(s) Added",
            "error": None,
            "details": {
                "added_artifacts": [],
                "invalid_paths": ["file1.tar.gz"],
                "target_roles": [],
            },
        }
        assert repository.targets_crud.read_file_by_path.calls == []
        assert repository.targets_crud.create_file.calls == []
        assert repository.targets_crud.read_role_by_rolename.calls == []
        assert test_repo._get_role_for_artifact_path.calls == [
            pretend.call("file1.tar.gz")
        ]
        assert test_repo._send_publish_artifacts_task.calls == []
        assert test_repo._update_task.calls == [
            pretend.call({}, fake_update_state, None)
        ]

    def test_remove_artifacts(self, test_repo, monkeypatch, mocked_datetime):
        test_repo._get_role_for_artifact_path = pretend.call_recorder(
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
            "artifacts": [
                "file1.tar.gz",
                "file2.tar.gz",
                "release-v0.1.0.yaml",
            ],
            "task_id": "fake_task_id_xyz",
        }
        test_repo._send_publish_artifacts_task = pretend.call_recorder(
            lambda *a: "fake_subtask"
        )
        test_repo._update_task = pretend.call_recorder(lambda *a: None)

        fake_update_state = pretend.stub()
        result = test_repo.remove_artifacts(
            payload, update_state=fake_update_state
        )

        assert result == {
            "task": "remove_artifacts",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Artifact(s) removed",
            "error": None,
            "details": {
                "deleted_artifacts": [
                    "file1.tar.gz",
                    "file2.tar.gz",
                    "release-v0.1.0.yaml",
                ],
                "not_found_artifacts": [],
            },
        }
        assert test_repo._get_role_for_artifact_path.calls == [
            pretend.call("file1.tar.gz"),
            pretend.call("file2.tar.gz"),
            pretend.call("release-v0.1.0.yaml"),
        ]
        assert repository.targets_crud.read_file_by_path.calls == [
            pretend.call(test_repo._db, "file1.tar.gz"),
            pretend.call(test_repo._db, "file2.tar.gz"),
            pretend.call(test_repo._db, "release-v0.1.0.yaml"),
        ]
        assert test_repo._send_publish_artifacts_task.calls == [
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

    def test_remove_artifacts_deleted_and_not_found_targets(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        get_role_for_target_path_generator = iter(("first_role", None))
        test_repo._get_role_for_artifact_path = pretend.call_recorder(
            lambda *a: next(get_role_for_target_path_generator)
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
            "artifacts": ["file1.tar.gz", "non-existent"],
            "task_id": "fake_task_id_xyz",
        }
        test_repo._send_publish_artifacts_task = pretend.call_recorder(
            lambda *a: "fake_subtask"
        )
        test_repo._update_task = pretend.call_recorder(lambda *a: None)

        fake_update_state = pretend.stub()
        result = test_repo.remove_artifacts(
            payload, update_state=fake_update_state
        )

        assert result == {
            "task": "remove_artifacts",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Artifact(s) removed",
            "error": None,
            "details": {
                "deleted_artifacts": ["file1.tar.gz"],
                "not_found_artifacts": ["non-existent"],
            },
        }
        assert test_repo._get_role_for_artifact_path.calls == [
            pretend.call("file1.tar.gz"),
            pretend.call("non-existent"),
        ]
        assert repository.targets_crud.read_file_by_path.calls == [
            pretend.call(test_repo._db, "file1.tar.gz"),
        ]
        assert test_repo._send_publish_artifacts_task.calls == [
            pretend.call("fake_task_id_xyz", ["first_role"])
        ]
        assert repository.targets_crud.update_file_action_to_remove.calls == [
            pretend.call(test_repo._db, fake_db_target),
        ]
        assert test_repo._update_task.calls == [
            pretend.call(
                {"first_role": [fake_db_target_removed]},
                fake_update_state,
                "fake_subtask",
            )
        ]

    def test_remove_artifacts_skip_publishing(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        test_repo._get_role_for_artifact_path = pretend.call_recorder(
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
            "artifacts": [
                "file1.tar.gz",
                "file2.tar.gz",
                "release-v0.1.0.yaml",
            ],
            "publish_artifacts": False,
            "task_id": "fake_task_id_xyz",
        }
        test_repo._update_task = pretend.call_recorder(lambda *a: None)

        fake_update_state = pretend.stub()
        result = test_repo.remove_artifacts(
            payload, update_state=fake_update_state
        )

        assert result == {
            "task": "remove_artifacts",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Artifact(s) removed",
            "error": None,
            "details": {
                "deleted_artifacts": [
                    "file1.tar.gz",
                    "file2.tar.gz",
                    "release-v0.1.0.yaml",
                ],
                "not_found_artifacts": [],
            },
        }
        assert test_repo._get_role_for_artifact_path.calls == [
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

    def test_remove_artifacts_all_none(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        test_repo._get_role_for_artifact_path = pretend.call_recorder(
            lambda *a: "bin-e"
        )
        test_repo._db = pretend.stub(
            refresh=pretend.call_recorder(lambda *a: None),
            bind=pretend.stub(
                url=pretend.stub(
                    drivername="postgresql",
                )
            ),
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "read_file_by_path",
            pretend.call_recorder(lambda *a: None),
        )

        payload = {
            "artifacts": [
                "file2.tar.gz",
                "file3.tar.gz",
                "release-v0.1.0.yaml",
            ]
        }

        result = test_repo.remove_artifacts(
            payload, update_state=pretend.stub()
        )

        assert result == {
            "task": "remove_artifacts",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Artifact(s) removed",
            "error": None,
            "details": {
                "deleted_artifacts": [],
                "not_found_artifacts": [
                    "file2.tar.gz",
                    "file3.tar.gz",
                    "release-v0.1.0.yaml",
                ],
            },
        }
        assert test_repo._get_role_for_artifact_path.calls == [
            pretend.call("file2.tar.gz"),
            pretend.call("file3.tar.gz"),
            pretend.call("release-v0.1.0.yaml"),
        ]
        assert repository.targets_crud.read_file_by_path.calls == [
            pretend.call(test_repo._db, "file2.tar.gz"),
            pretend.call(test_repo._db, "file3.tar.gz"),
            pretend.call(test_repo._db, "release-v0.1.0.yaml"),
        ]

    def test_remove_artifacts_action_remove_published_true(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        test_repo._get_role_for_artifact_path = pretend.call_recorder(
            lambda *a: "bin-e"
        )
        test_repo._db = pretend.stub(
            refresh=pretend.call_recorder(lambda *a: None),
            bind=pretend.stub(
                url=pretend.stub(
                    drivername="postgresql",
                )
            ),
        )
        fake_db_target = pretend.stub(
            bind=pretend.stub(url=pretend.stub(drivename="postgresql")),
            action=targets_schema.TargetAction.REMOVE,
            published=True,
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "read_file_by_path",
            pretend.call_recorder(lambda *a: fake_db_target),
        )
        payload = {
            "artifacts": [
                "file2.tar.gz",
                "file3.tar.gz",
                "release-v0.1.0.yaml",
            ]
        }

        result = test_repo.remove_artifacts(
            payload, update_state=pretend.stub()
        )

        assert result == {
            "task": "remove_artifacts",
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Artifact(s) removed",
            "error": None,
            "details": {
                "deleted_artifacts": [],
                "not_found_artifacts": [
                    "file2.tar.gz",
                    "file3.tar.gz",
                    "release-v0.1.0.yaml",
                ],
            },
        }
        assert test_repo._get_role_for_artifact_path.calls == [
            pretend.call("file2.tar.gz"),
            pretend.call("file3.tar.gz"),
            pretend.call("release-v0.1.0.yaml"),
        ]
        assert repository.targets_crud.read_file_by_path.calls == [
            pretend.call(test_repo._db, "file2.tar.gz"),
            pretend.call(test_repo._db, "file3.tar.gz"),
            pretend.call(test_repo._db, "release-v0.1.0.yaml"),
        ]

    def test_remove_artifacts_without_artifacts(
        self, test_repo, mocked_datetime
    ):
        payload = {"paths": []}

        result = test_repo.remove_artifacts(
            payload, update_state=pretend.stub()
        )

        assert result == {
            "task": "remove_artifacts",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Removing artifact(s) Failed",
            "error": "No 'artifacts' in the payload",
            "details": None,
        }

    def test_remove_artifacts_empty_artifacts(
        self, test_repo, mocked_datetime
    ):
        payload = {"artifacts": []}

        result = test_repo.remove_artifacts(
            payload, update_state=pretend.stub()
        )

        assert result == {
            "task": "remove_artifacts",
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Removing artifact(s) Failed",
            "error": "At list one artifact is required",
            "details": None,
        }

    def test__run_online_roles_bump_StorageError(self, test_repo, monkeypatch):
        def fake_get_fresh(setting: str):
            if setting == "TARGETS_ONLINE_KEY":
                return None
            elif setting == "DELEGATED_ROLES_NAMES":
                return ["bin-a"]

        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda a: fake_get_fresh(a))
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        test_repo._storage_backend.get = pretend.raiser(
            StorageError("Overwrite it")
        )

        with pytest.raises(StorageError):
            test_repo._run_online_roles_bump()

        assert fake_settings.get_fresh.calls == [
            pretend.call("TARGETS_ONLINE_KEY"),
        ]

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
            lambda *a, **kw: "fake_snapshot"
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
        assert test_repo._update_snapshot.calls == [
            pretend.call(only_snapshot=True)
        ]
        assert test_repo._update_timestamp.calls == [
            pretend.call("fake_snapshot")
        ]

    def test_bump_snapshot_unexpired(self, test_repo):
        fake_exp = datetime.datetime(2080, 6, 16, 9, 5, 1, tzinfo=timezone.utc)
        fake_snapshot = pretend.stub(
            signed=pretend.stub(
                meta={},
                expires=fake_exp,
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
        fake_exp = datetime.datetime(2080, 6, 16, 9, 5, 1, tzinfo=timezone.utc)
        caplog.set_level(repository.logging.DEBUG)
        fake_snapshot = pretend.stub(
            signed=pretend.stub(
                expires=fake_exp,
                version=87,
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_snapshot
        )
        test_repo._update_snapshot = pretend.call_recorder(
            lambda *a, **kw: "fake_snapshot"
        )
        test_repo._update_timestamp = pretend.call_recorder(
            lambda *a: pretend.stub(
                signed=pretend.stub(
                    snapshot_meta=pretend.stub(version=79),
                    version=87,
                    expires=fake_exp,
                )
            )
        )

        test_repo.bump_snapshot(force=True)
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Snapshot.type)
        ]
        assert test_repo._update_snapshot.calls == [
            pretend.call(only_snapshot=True)
        ]
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
            pretend.call(repository.LOCK_TARGETS, timeout=500)
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

    def test_bump_online_roles_when_inital_bootstrap(
        self, monkeypatch, test_repo
    ):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: "pre-")
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

    def test_bump_online_roles_when_bootstrap_signing_process(
        self, monkeypatch, test_repo
    ):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: "signing-")
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

        assert "RSTUF: Task exceed `LOCK_TIMEOUT` (500 seconds)" in str(e)
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]
        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=500)
        ]

    def test__verify_new_root_signing(self, test_repo):
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["k1"])},
                version=2,
                type=repository.Root.type,
            ),
            verify_delegate=pretend.call_recorder(lambda *a: None),
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["k1"])},
                version=1,
            ),
            verify_delegate=pretend.call_recorder(lambda *a: None),
        )

        result = test_repo._verify_new_root_signing(
            fake_old_root_md, fake_new_root_md
        )
        assert result is None
        assert fake_new_root_md.verify_delegate.calls == [
            pretend.call(repository.Root.type, fake_new_root_md)
        ]
        assert fake_old_root_md.verify_delegate.calls == [
            pretend.call(repository.Root.type, fake_new_root_md)
        ]

    def test__verify_new_root_signing_fail_current_verify_delegate(
        self, test_repo
    ):
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["k1"])},
                version=2,
                type=repository.Root.type,
            ),
            verify_delegate=pretend.raiser(
                TypeError("Call is valid only on delegator metadata")
            ),
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["k1"])},
                version=1,
            ),
            verify_delegate=pretend.call_recorder(lambda *a: None),
        )

        with pytest.raises(TypeError) as err:
            test_repo._verify_new_root_signing(
                fake_old_root_md, fake_new_root_md
            )
        assert "Call is valid only on delegator metadata" in str(err)

    def test__verify_new_root_signing_bad_version(self, test_repo):
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["k1"])},
                version=4,
                type=repository.Root.type,
            ),
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["k1"])},
                version=1,
            ),
        )

        with pytest.raises(repository.BadVersionNumberError) as err:
            test_repo._verify_new_root_signing(
                fake_old_root_md, fake_new_root_md
            )
        assert "Expected root version 2 instead got version 4" in str(err)

    def test__verify_new_root_signing_bad_type(self, test_repo):
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["k1"])},
                version=2,
                type=repository.Snapshot.type,
            ),
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"root": pretend.stub(keyids=["k1"])},
                version=1,
            ),
        )

        with pytest.raises(repository.RepositoryError) as err:
            test_repo._verify_new_root_signing(
                fake_old_root_md, fake_new_root_md
            )
        assert "Expected 'root', got 'snapshot'" in str(err)

    def test__run_force_online_metadata_update_targets_and_bins(
        self, test_repo
    ):
        fake_targets = Metadata(Targets())
        test_repo._storage_backend = pretend.stub(
            get=pretend.call_recorder(lambda a: fake_targets)
        )
        test_repo._bump_and_persist = pretend.call_recorder(lambda *a: None)
        test_repo._update_snapshot = pretend.call_recorder(
            lambda **kw: "version"
        )
        test_repo._update_timestamp = pretend.call_recorder(lambda a: None)
        payload = [Targets.type, "bins"]

        result = test_repo._run_force_online_metadata_update(payload)
        assert result == [Snapshot.type, Timestamp.type, Targets.type, "bins"]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Targets.type)
        ]
        assert test_repo._bump_and_persist.calls == [
            pretend.call(fake_targets, Targets.type)
        ]
        assert test_repo._update_snapshot.calls == [
            pretend.call(bump_all=True)
        ]
        assert test_repo._update_timestamp.calls == [pretend.call("version")]

    def test__run_force_online_metadata_update_targets_and_custom_role(
        self, test_repo
    ):
        fake_targets = Metadata(Targets())
        test_repo._storage_backend = pretend.stub(
            get=pretend.call_recorder(lambda a: fake_targets)
        )
        test_repo._bump_and_persist = pretend.call_recorder(lambda *a: None)
        test_repo._update_snapshot = pretend.call_recorder(
            lambda **kw: "version"
        )
        test_repo._update_timestamp = pretend.call_recorder(lambda a: None)
        payload = [Targets.type, "foo"]

        result = test_repo._run_force_online_metadata_update(payload)
        assert result == [Snapshot.type, Timestamp.type, Targets.type, "foo"]
        assert test_repo._bump_and_persist.calls == [
            pretend.call(fake_targets, Targets.type)
        ]
        assert test_repo._update_snapshot.calls == [
            pretend.call(target_roles=["foo"])
        ]
        assert test_repo._update_timestamp.calls == [pretend.call("version")]

    def test__run_force_online_metadata_update_targets_and_custom_roles(
        self, test_repo
    ):
        fake_targets = Metadata(Targets())
        test_repo._storage_backend = pretend.stub(
            get=pretend.call_recorder(lambda a: fake_targets)
        )
        test_repo._bump_and_persist = pretend.call_recorder(lambda *а: None)
        test_repo._update_snapshot = pretend.call_recorder(
            lambda **kw: "version"
        )
        test_repo._update_timestamp = pretend.call_recorder(lambda a: None)
        payload = [Targets.type, "foo", "bar"]

        result = test_repo._run_force_online_metadata_update(payload)
        assert result == [
            Snapshot.type,
            Timestamp.type,
            Targets.type,
            "foo",
            "bar",
        ]
        assert test_repo._bump_and_persist.calls == [
            pretend.call(fake_targets, Targets.type)
        ]
        assert test_repo._update_snapshot.calls == [
            pretend.call(target_roles=["foo", "bar"])
        ]
        assert test_repo._update_timestamp.calls == [pretend.call("version")]

    def test__run_force_online_metadata_update_bins(
        self, test_repo, monkeypatch
    ):
        test_repo._update_snapshot = pretend.call_recorder(
            lambda **kw: "version"
        )
        test_repo._update_timestamp = pretend.call_recorder(lambda a: None)

        result = test_repo._run_force_online_metadata_update(["bins"])
        assert result == [Snapshot.type, Timestamp.type, "bins"]
        assert test_repo._update_snapshot.calls == [
            pretend.call(bump_all=True)
        ]
        assert test_repo._update_timestamp.calls == [pretend.call("version")]

    def test__run_force_online_metadata_update_targets(self, test_repo):
        fake_targets = Metadata(Targets())
        test_repo._storage_backend = pretend.stub(
            get=pretend.call_recorder(lambda a: fake_targets)
        )
        test_repo._bump_and_persist = pretend.call_recorder(lambda *а: None)
        test_repo._update_snapshot = pretend.call_recorder(
            lambda **kw: "version"
        )
        test_repo._update_timestamp = pretend.call_recorder(lambda a: None)

        result = test_repo._run_force_online_metadata_update([Targets.type])
        assert result == [Snapshot.type, Timestamp.type, Targets.type]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Targets.type)
        ]
        assert test_repo._bump_and_persist.calls == [
            pretend.call(fake_targets, Targets.type)
        ]
        assert test_repo._update_snapshot.calls == [
            pretend.call(target_roles=[])
        ]
        assert test_repo._update_timestamp.calls == [pretend.call("version")]

    def test__run_force_online_metadata_update_snapshot(self, test_repo):
        test_repo.bump_snapshot = pretend.call_recorder(lambda **kw: None)

        result = test_repo._run_force_online_metadata_update([Snapshot.type])
        assert result == [Snapshot.type, Timestamp.type]
        assert test_repo.bump_snapshot.calls == [pretend.call(force=True)]

    def test__run_force_online_metadata_update_timestamp(self, test_repo):
        fake_snapshot = Metadata(Snapshot())
        test_repo._storage_backend = pretend.stub(
            get=pretend.call_recorder(lambda a: fake_snapshot)
        )
        test_repo._update_timestamp = pretend.call_recorder(lambda a: None)

        result = test_repo._run_force_online_metadata_update([Timestamp.type])
        assert result == [Timestamp.type]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Snapshot.type)
        ]
        assert test_repo._update_timestamp.calls == [
            pretend.call(fake_snapshot.signed.version)
        ]

    def test__force_online_metadata_update(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda a: "123")
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )

        @contextmanager
        def mocked_lock(lock, timeout):
            yield lock, timeout

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
        )
        roles = ["snapshot", "targets"]
        test_repo._run_force_online_metadata_update = pretend.call_recorder(
            lambda a: roles
        )
        payload = {"roles": roles}
        result = test_repo.force_online_metadata_update(payload)
        assert result == {
            "task": repository.TaskName.FORCE_ONLINE_METADATA_UPDATE,
            "status": True,
            "message": "Force new online metadata update succeeded",
            "error": None,
            "details": {
                "updated_roles": roles,
            },
            "last_update": mocked_datetime.now(),
        }
        assert fake_settings.get_fresh.calls == [pretend.call("BOOTSTRAP")]
        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=test_repo._timeout)
        ]
        assert test_repo._run_force_online_metadata_update.calls == [
            pretend.call(payload["roles"])
        ]

    @pytest.mark.parametrize("bootstrap_value", [None, "pre-", "signing-"])
    def test__force_online_metadata_update_bootstrap_not_finished(
        self, test_repo, monkeypatch, mocked_datetime, bootstrap_value
    ):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda a: bootstrap_value)
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        result = test_repo.force_online_metadata_update({"roles": "targets"})
        assert result == {
            "task": repository.TaskName.FORCE_ONLINE_METADATA_UPDATE,
            "status": False,
            "message": "Force new online metadata update failed",
            "error": "New metadata updates requre completed bootstrap",
            "details": None,
            "last_update": mocked_datetime.now(),
        }
        assert fake_settings.get_fresh.calls == [pretend.call("BOOTSTRAP")]

    def test__force_online_metadata_update_timeout(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda a: "123")
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )

        @contextmanager
        def mocked_lock(lock, timeout):
            raise repository.redis.exceptions.LockNotOwnedError("timeout")

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
        )
        payload = {"roles": ["snapshot", "targets"]}
        result = test_repo.force_online_metadata_update(payload)
        assert result == {
            "task": repository.TaskName.FORCE_ONLINE_METADATA_UPDATE,
            "status": False,
            "message": "Force new online metadata update failed",
            "error": (
                "The task to update online roles exceeded the "
                f"timeout of {test_repo._timeout} seconds."
            ),
            "details": None,
            "last_update": mocked_datetime.now(),
        }
        assert fake_settings.get_fresh.calls == [pretend.call("BOOTSTRAP")]
        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=test_repo._timeout)
        ]

    def test__root_metadata_update(self, test_repo, mocked_datetime):
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["k1"])},
                version=2,
            )
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["k1"])},
                version=1,
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_old_root_md
        )
        test_repo._verify_new_root_signing = pretend.call_recorder(
            lambda *a: None
        )
        test_repo._persist = pretend.call_recorder(lambda *a: None)

        result = test_repo._root_metadata_update(fake_new_root_md)

        assert result == {
            "task": repository.TaskName.METADATA_UPDATE,
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
        assert test_repo._verify_new_root_signing.calls == [
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
                roles={"timestamp": pretend.stub(keyids=["k1"])},
                version=2,
            )
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["k1"])},
                version=1,
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_old_root_md
        )
        test_repo._verify_new_root_signing = pretend.raiser(
            repository.UnsignedMetadataError()
        )

        fake_new_root_md.to_dict = pretend.call_recorder(lambda: "fake dict")
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: "fake"
        )

        result = test_repo._root_metadata_update(fake_new_root_md)

        assert result == {
            "task": repository.TaskName.METADATA_UPDATE,
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
                roles={"timestamp": pretend.stub(keyids=["k1"])},
                version=2,
            )
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["k1"])},
                version=1,
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_old_root_md
        )
        test_repo._verify_new_root_signing = pretend.raiser(
            repository.BadVersionNumberError("Version v3 instead v2")
        )

        result = test_repo._root_metadata_update(fake_new_root_md)

        assert result == {
            "task": repository.TaskName.METADATA_UPDATE,
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
        self, test_repo, mocked_datetime, monkeypatch
    ):
        fake_key_dict = {"keyval": "foo", "keyid": "old_key_id"}
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda a: copy(fake_key_dict))
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        old_key = pretend.stub(keyid="old_key_id")
        fake_key_obj = pretend.stub(
            from_dict=pretend.call_recorder(lambda *a: old_key)
        )
        monkeypatch.setattr(f"{REPOSITORY_PATH}.Key", fake_key_obj)
        new_key_dict = {"keyval": "bar"}
        new_key = pretend.stub(
            to_dict=pretend.call_recorder(lambda: new_key_dict),
            keyid="new_key_id",
        )
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["new_key_id"])},
                keys={"new_key_id": new_key},
                version=2,
            )
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["old_key_id"])},
                version=1,
            )
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_old_root_md
        )
        test_repo._verify_new_root_signing = pretend.call_recorder(
            lambda *a: None
        )

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
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )

        result = test_repo._root_metadata_update(fake_new_root_md)

        assert result == {
            "task": repository.TaskName.METADATA_UPDATE,
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
        assert test_repo._verify_new_root_signing.calls == [
            pretend.call(fake_old_root_md, fake_new_root_md)
        ]
        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=500.0)
        ]
        assert test_repo._persist.calls == [
            pretend.call(fake_new_root_md, repository.Root.type)
        ]
        assert fake_settings.get_fresh.calls == [pretend.call("ONLINE_KEY")]
        assert fake_key_obj.from_dict.calls == [
            pretend.call(fake_key_dict.pop("keyid"), fake_key_dict)
        ]
        assert new_key.to_dict.calls == [pretend.call()]
        assert test_repo._run_online_roles_bump.calls == [
            pretend.call(force=True)
        ]
        assert test_repo.write_repository_settings.calls == [
            pretend.call("ONLINE_KEY", new_key_dict)
        ]

    def test__root_metadata_update_online_key_lock_timeout(
        self, monkeypatch, test_repo
    ):
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["k1"])},
                version=2,
            )
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["k2"])},
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
        test_repo._verify_new_root_signing = pretend.call_recorder(
            lambda *a: None
        )

        @contextmanager
        def mocked_lock(lock, timeout):
            raise repository.redis.exceptions.LockNotOwnedError("timeout")

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
        )
        with pytest.raises(repository.redis.exceptions.LockError) as e:
            test_repo._root_metadata_update(fake_new_root_md)

        assert "RSTUF: Task exceed `LOCK_TIMEOUT` (500 seconds)" in str(e)
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Root.type)
        ]
        assert test_repo._verify_new_root_signing.calls == [
            pretend.call(fake_old_root_md, fake_new_root_md)
        ]

    def test_root_metadata_update_finalize_run_onlines_bump_fails(
        self, test_repo, monkeypatch
    ) -> None:
        fake_key_dict = {"keyval": "foo", "keyid": "old_key_id"}
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda a: copy(fake_key_dict))
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )
        old_key_dict = {"keyval": "old_bar"}
        old_key = pretend.stub(
            to_dict=pretend.call_recorder(lambda: old_key_dict),
            keyid="old_key_id",
        )
        fake_key_obj = pretend.stub(
            from_dict=pretend.call_recorder(lambda *a: old_key)
        )
        monkeypatch.setattr(f"{REPOSITORY_PATH}.Key", fake_key_obj)
        new_key_dict = {"keyval": "old_bar"}
        new_key = pretend.stub(
            to_dict=pretend.call_recorder(lambda: new_key_dict),
            keyid="new_key_id",
        )
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["new_key_id"])},
                keys={"new_key_id": new_key},
                version=2,
            )
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["old_key_id"])},
                version=1,
            )
        )

        @contextmanager
        def mocked_lock(lock, timeout):
            yield lock, timeout

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
        )
        test_repo._run_online_roles_bump = pretend.raiser(ValueError("Bad"))
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )

        with pytest.raises(ValueError):
            test_repo._root_metadata_update_finalize(
                fake_old_root_md, fake_new_root_md
            )

        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=500.0)
        ]
        assert fake_settings.get_fresh.calls == [pretend.call("ONLINE_KEY")]
        assert fake_key_obj.from_dict.calls == [
            pretend.call(fake_key_dict.pop("keyid"), fake_key_dict)
        ]
        assert new_key.to_dict.calls == [pretend.call()]
        # Assert that we have recovered to the previous online key.
        # These calls assert that the online key is set to current online key.
        assert old_key.to_dict.calls == [pretend.call()]
        assert test_repo.write_repository_settings.calls == [
            pretend.call("ONLINE_KEY", new_key_dict),
            pretend.call("ONLINE_KEY", old_key_dict),
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
            "task": repository.TaskName.METADATA_UPDATE,
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
            "task": repository.TaskName.METADATA_UPDATE,
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
            "task": repository.TaskName.METADATA_UPDATE,
            "status": False,
            "last_update": mocked_datetime.now(),
            "message": "Metadata Update Failed",
            "error": "Metadata Update requires a completed bootstrap",
            "details": None,
        }
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]

    def test_metadata_delegation_add(self, test_repo, mocked_datetime):
        # test repository.MetadataRepository.metadata_delegation
        payload = {
            "action": "add",
            "delegations": {
                "keys": {},
                "roles": [
                    {
                        "keyids": [],
                        "name": "delegation-1",
                        "paths": ["*"],
                        "terminating": True,
                        "threshold": 2,
                        "x-rstuf-expire-policy": 365,
                    }
                ],
            },
        }

        mocked_delegations = repository.Delegations.from_dict(
            deepcopy(payload["delegations"])
        )
        test_repo.Delegations = pretend.stub(
            from_dict=pretend.call_recorder(lambda *a: mocked_delegations)
        )
        test_repo._storage_load_snapshot = pretend.call_recorder(
            lambda: Metadata(Snapshot())
        )
        mocked_targets = Metadata(Targets())
        test_repo._storage_load_targets = pretend.call_recorder(
            lambda: mocked_targets
        )
        mocked_delegatedrole = repository.DelegatedRole.from_dict(
            copy(payload["delegations"]["roles"][0])
        )
        mocked_delegatedrole.signed = pretend.stub(version=1)
        test_repo._add_metadata_delegation = pretend.call_recorder(
            lambda *a, **kw: ({"delegation-1": mocked_delegatedrole}, [])
        )
        test_repo._validate_threshold = pretend.call_recorder(lambda *a: True)
        test_repo._persist = pretend.call_recorder(lambda *a: None)
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )

        result = test_repo.metadata_delegation(payload, None)

        assert test_repo._storage_load_snapshot.calls == [pretend.call()]
        assert test_repo._storage_load_targets.calls == [pretend.call()]
        assert test_repo._add_metadata_delegation.calls == [
            pretend.call(
                mocked_delegations, mocked_targets, persist_targets=True
            )
        ]
        assert test_repo._validate_threshold.calls == [
            pretend.call(mocked_delegatedrole, mocked_targets, "delegation-1")
        ]
        assert test_repo._persist.calls == [
            pretend.call(mocked_delegatedrole, "delegation-1")
        ]
        assert test_repo.write_repository_settings.calls == []
        assert result == {
            "task": repository.TaskName.METADATA_DELEGATION,
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Metadata Delegation Processed",
            "error": None,
            "details": {
                "delegated_roles": ["delegation-1"],
                "failed_roles": [],
            },
        }

    def test_metadata_delegation_add_no_treshold(
        self, test_repo, mocked_datetime
    ):
        # test repository.MetadataRepository.metadata_delegation
        payload = {
            "action": "add",
            "delegations": {
                "keys": {},
                "roles": [
                    {
                        "keyids": [],
                        "name": "delegation-1",
                        "paths": ["*"],
                        "terminating": True,
                        "threshold": 2,
                        "x-rstuf-expire-policy": 365,
                    }
                ],
            },
        }

        mocked_delegations = repository.Delegations.from_dict(
            deepcopy(payload["delegations"])
        )
        test_repo.Delegations = pretend.stub(
            from_dict=pretend.call_recorder(lambda *a: mocked_delegations)
        )
        test_repo._storage_load_snapshot = pretend.call_recorder(
            lambda: Metadata(Snapshot())
        )
        mocked_targets = Metadata(Targets())
        test_repo._storage_load_targets = pretend.call_recorder(
            lambda: mocked_targets
        )
        mocked_delegatedrole = repository.DelegatedRole.from_dict(
            copy(payload["delegations"]["roles"][0])
        )
        mocked_delegatedrole.signed = pretend.stub(version=1)
        test_repo._add_metadata_delegation = pretend.call_recorder(
            lambda *a, **kw: ({"delegation-1": mocked_delegatedrole}, [])
        )
        test_repo._validate_threshold = pretend.call_recorder(lambda *a: False)
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a: None
        )
        test_repo._persist = pretend.call_recorder(lambda *a: None)

        result = test_repo.metadata_delegation(payload, None)

        assert test_repo._storage_load_snapshot.calls == [pretend.call()]
        assert test_repo._storage_load_targets.calls == [pretend.call()]

        assert test_repo._add_metadata_delegation.calls == [
            pretend.call(
                mocked_delegations, mocked_targets, persist_targets=True
            )
        ]
        assert test_repo._validate_threshold.calls == [
            pretend.call(mocked_delegatedrole, mocked_targets, "delegation-1")
        ]
        assert test_repo._persist.calls == []
        assert test_repo.write_repository_settings.calls == [
            pretend.call(
                "DELEGATION-1_SIGNING",
                mocked_delegatedrole.to_dict(),
            )
        ]
        assert result == {
            "task": repository.TaskName.METADATA_DELEGATION,
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Metadata Delegation Processed",
            "error": None,
            "details": {
                "delegated_roles": ["delegation-1"],
                "failed_roles": [],
            },
        }

    def test_metadata_delegation_delete(self, test_repo, mocked_datetime):
        payload = {
            "action": "delete",
            "delegations": {
                "keys": {},
                "roles": [
                    {
                        "keyids": [],
                        "name": "delegation-1",
                        "paths": ["*"],
                        "terminating": True,
                        "threshold": 2,
                        "x-rstuf-expire-policy": 365,
                    }
                ],
            },
        }

        @contextmanager
        def mocked_lock(lock, timeout):
            yield lock, timeout

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock)
        )
        test_repo._delete_metadata_delegation = pretend.call_recorder(
            lambda delegations: ({"delegation-1": "deleted"}, [])
        )

        result = test_repo.metadata_delegation(payload)

        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=test_repo._timeout)
        ]
        assert test_repo._delete_metadata_delegation.calls == [
            pretend.call(payload["delegations"])
        ]
        assert result == {
            "task": repository.TaskName.METADATA_DELEGATION,
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Metadata Delegation Processed",
            "error": None,
            "details": {
                "delegated_roles": ["delegation-1"],
                "failed_roles": [],
            },
        }

    def test_metadata_delegation_delete_lock_timeout(self, caplog, test_repo):
        payload = {
            "action": "delete",
            "delegations": {
                "keys": {},
                "roles": [
                    {
                        "keyids": [],
                        "name": "delegation-1",
                        "paths": ["*"],
                        "terminating": True,
                        "threshold": 2,
                        "x-rstuf-expire-policy": 365,
                    }
                ],
            },
        }

        @contextmanager
        def mocked_lock(lock, timeout):
            raise repository.redis.exceptions.LockNotOwnedError("timeout")

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock)
        )
        with caplog.at_level("ERROR"):
            with pytest.raises(repository.redis.exceptions.LockError) as e:
                test_repo.metadata_delegation(payload)

        assert (
            f"The task to bump all online roles exceeded the timeout of "
            f"{test_repo._timeout} seconds." in caplog.text
        )
        assert "RSTUF: Task exceed `LOCK_TIMEOUT` (500 seconds)" in str(e)
        assert test_repo._redis.lock.calls == [
            pretend.call("LOCK_TARGETS", timeout=500)
        ]

    def test_metadata_delegation_update(self, test_repo, mocked_datetime):
        payload = {
            "action": "update",
            "delegations": {
                "keys": {},
                "roles": [
                    {
                        "keyids": [],
                        "name": "delegation-1",
                        "paths": ["*"],
                        "terminating": True,
                        "threshold": 2,
                        "x-rstuf-expire-policy": 365,
                    }
                ],
            },
        }
        mocked_delegations = repository.Delegations.from_dict(
            deepcopy(payload["delegations"])
        )
        test_repo.Delegations = pretend.stub(
            from_dict=pretend.call_recorder(lambda *a: mocked_delegations)
        )
        test_repo._update_metadata_delegation = pretend.call_recorder(
            lambda delegations: ({"delegation-1": None}, [])
        )
        result = test_repo.metadata_delegation(payload)

        assert test_repo._update_metadata_delegation.calls == [
            pretend.call(mocked_delegations)
        ]
        assert result == {
            "task": repository.TaskName.METADATA_DELEGATION,
            "status": True,
            "last_update": mocked_datetime.now(),
            "message": "Metadata Delegation Processed",
            "error": None,
            "details": {
                "delegated_roles": ["delegation-1"],
                "failed_roles": [],
            },
        }

    def test_metadata_delegation_invalid_action(self, test_repo):
        payload = {
            "action": "invalid",
            "delegations": {},
        }
        with pytest.raises(ValueError) as excinfo:
            test_repo.metadata_delegation(payload)
        assert "metadata delegation supports 'add', 'update', 'remove'" in str(
            excinfo.value
        )

    def test__validate_signature(self, test_repo):
        fake_root_md = pretend.stub(
            signatures=[{"keyid": "k1", "sig": "s1"}],
            signed=pretend.stub(
                type="root",
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
            signed=pretend.stub(
                type="root",
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
            signed=pretend.stub(
                type="root",
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
            signed=pretend.stub(
                type="root",
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

    def test_sign_metadata_update_no_pending_signatures(
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
            "error": "No signatures pending for foo",
            "details": None,
        }

    def test_sign_metadata_update_invalid_signature(
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
        assert fake_settings.get_fresh.calls == [
            pretend.call("ROOT_SIGNING"),
            pretend.call("BOOTSTRAP"),
        ]
        assert repository.Signature.from_dict.calls == [
            pretend.call(payload["signature"])
        ]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(Root.type)
        ]
        assert repository.Metadata.from_dict.calls == [
            pretend.call({"metadata": "fake"})
        ]

    def test_sign_metadata_update_invalid_threshold_trusted_and_new(
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

    def test_sign_metadata_update_invalid_threshold_trusted(
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

    def test_sign_metadata_update_invalid_threshold_new(
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

    def test_sign_metadata_update_valid_threshold(
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
        test_repo._root_metadata_update_finalize = pretend.call_recorder(
            lambda *a: None
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
        assert test_repo._root_metadata_update_finalize.calls == [
            pretend.call(fake_trusted_root, fake_new_root)
        ]

    def test_sign_metadata_non_root_role_invalid_signature(
        self, test_repo, monkeypatch, mocked_datetime
    ):
        def fake_get_fresh(key):
            if key == "TARGETS_SIGNING":
                return {
                    "signed": {
                        "version": 1,
                        "_type": "targets",
                        "spec_version": "1.0",
                        "expires": "2023-06-15T00:00:00Z",
                        "targets": {},
                    },
                    "signatures": {},
                }
            if key == "BOOTSTRAP":
                return "<task-id>"

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
        fake_targets_md = repository.Metadata(repository.Targets(version=1))
        fake_root = repository.Metadata(repository.Root(version=1))
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda r: fake_targets_md if r == "targets" else fake_root
        )
        test_repo._validate_signature = pretend.call_recorder(lambda *a: False)

        payload = {
            "role": "targets",
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
            pretend.call("TARGETS_SIGNING"),
            pretend.call("BOOTSTRAP"),
        ]

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

    def test_get_delegation_keyids_succinct_roles(
        self, test_repo, monkeypatch
    ):
        monkeypatch.setattr(test_repo, "_uses_succinct_roles", True)
        fake_key_dict = {
            "keyid": "fake-online-keyid",
            "keytype": "ed25519",
            "scheme": "ed25519",
            "keyval": {"public": "abcd1234"},
        }

        def fake_get_fresh(key: str):
            if key == "ONLINE_KEY":
                return fake_key_dict
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

        keyids = test_repo.get_delegation_keyids("bins-0")
        assert keyids == ["fake-online-keyid"]

    def test_get_delegation_keyids_custom_delegations(
        self, test_repo, monkeypatch
    ):
        monkeypatch.setattr(test_repo, "_uses_succinct_roles", False)
        fake_role = pretend.stub(keyids=["key1", "key2"])
        fake_delegations = pretend.stub(
            roles={"custom-role": fake_role}, succinct_roles=None
        )
        fake_targets_signed = pretend.stub(delegations=fake_delegations)
        fake_targets = pretend.stub(signed=fake_targets_signed)
        test_repo._storage_backend = pretend.stub(
            get=pretend.call_recorder(lambda role_type: fake_targets)
        )
        keyids = test_repo.get_delegation_keyids("custom-role")

        assert keyids == ["key1", "key2"]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Targets.type)
        ]

    @pytest.mark.parametrize(
        "delegation_keyids, from_storage, expected_calls",
        [
            # Case 1: Single online key
            (
                ["online_keyid"],
                True,
                {
                    "bump_and_persist": 1,
                    "persist": 1,
                    "bump_expiry": 0,
                    "bump_version": 0,
                    "sign": 0,
                    "write_settings": 0,
                },
            ),
            # Case 2: Multiple keys including online key
            (
                ["online_keyid", "offline_keyid"],
                True,
                {
                    "bump_and_persist": 0,
                    "persist": 0,
                    "bump_expiry": 1,
                    "bump_version": 1,
                    "sign": 1,
                    "write_settings": 1,
                },
            ),
            # Case 3: Multiple keys including online key, not from storage
            (
                ["online_keyid", "offline_keyid"],
                False,
                {
                    "bump_and_persist": 0,
                    "persist": 0,
                    "bump_expiry": 1,
                    "bump_version": 0,
                    "sign": 1,
                    "write_settings": 1,
                },
            ),
            # Case 4: Only offline keys
            (
                ["offline_keyid1", "offline_keyid2"],
                True,
                {
                    "bump_and_persist": 0,
                    "persist": 0,
                    "bump_expiry": 1,
                    "bump_version": 1,
                    "sign": 0,
                    "write_settings": 1,
                },
            ),
            # Case 5: Only offline keys, not from storage
            (
                ["offline_keyid1", "offline_keyid2"],
                False,
                {
                    "bump_and_persist": 0,
                    "persist": 0,
                    "bump_expiry": 1,
                    "bump_version": 0,
                    "sign": 0,
                    "write_settings": 1,
                },
            ),
        ],
    )
    def test_bump_persist_role(
        self,
        monkeypatch,
        test_repo,
        delegation_keyids,
        from_storage,
        expected_calls,
    ):
        rolename = "test-role"
        delegation = pretend.stub(
            signatures={},
            signed=pretend.stub(),
            to_dict=pretend.call_recorder(lambda: {"fake": "metadata"}),
        )
        test_repo._bump_and_persist = pretend.call_recorder(
            lambda *a, **kw: None
        )
        test_repo._persist = pretend.call_recorder(lambda *a, **kw: None)
        test_repo._bump_expiry = pretend.call_recorder(lambda *a, **kw: None)
        test_repo._bump_version = pretend.call_recorder(lambda *a, **kw: None)
        test_repo._sign = pretend.call_recorder(lambda *a, **kw: None)
        test_repo.write_repository_settings = pretend.call_recorder(
            lambda *a, **kw: None
        )

        test_repo.get_delegation_keyids = pretend.call_recorder(
            lambda role: delegation_keyids
        )

        fake_key_dict = {
            "keyid": "online_keyid",
            "keytype": "ed25519",
            "scheme": "ed25519",
            "keyval": {"public": "abcd1234"},
        }

        def fake_get_fresh(key: str):
            if key == "ONLINE_KEY":
                return fake_key_dict
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

        monkeypatch.setattr(test_repo, "_uses_succinct_roles", False)

        test_repo.bump_persist_role(delegation, rolename, from_storage)

        assert (
            len(test_repo._bump_and_persist.calls)
            == expected_calls["bump_and_persist"]
        )
        assert len(test_repo._persist.calls) == expected_calls["persist"]
        assert (
            len(test_repo._bump_expiry.calls) == expected_calls["bump_expiry"]
        )
        assert (
            len(test_repo._bump_version.calls)
            == expected_calls["bump_version"]
        )
        assert len(test_repo._sign.calls) == expected_calls["sign"]
        assert (
            len(test_repo.write_repository_settings.calls)
            == expected_calls["write_settings"]
        )

        if expected_calls["bump_and_persist"] > 0:
            assert test_repo._bump_and_persist.calls == [
                pretend.call(delegation, rolename, persist=False, expire=None)
            ]
        if expected_calls["persist"] > 0:
            assert test_repo._persist.calls == [
                pretend.call(delegation, rolename)
            ]
        if expected_calls["bump_expiry"] > 0:
            assert test_repo._bump_expiry.calls == [
                pretend.call(delegation, rolename)
            ]
        if expected_calls["write_settings"] > 0:
            assert test_repo.write_repository_settings.calls == [
                pretend.call(
                    f"{rolename.upper()}_SIGNING", {"fake": "metadata"}
                )
            ]
            assert delegation.to_dict.calls == [pretend.call()]

    def test_update_targets_delegated_role_main_targets(self, test_repo):
        mocked_targets = pretend.stub(
            signed=pretend.stub(
                version=4,
                expires=datetime.datetime(
                    2023, 6, 15, 9, 5, 1, tzinfo=timezone.utc
                ),
            )
        )
        test_repo._storage_backend = pretend.stub(
            get=pretend.call_recorder(lambda _role: mocked_targets)
        )
        test_repo._bump_and_persist = pretend.call_recorder(
            lambda *a, **kw: None
        )

        result = test_repo.update_targets_delegated_role("targets")

        assert test_repo._storage_backend.get.calls == [
            pretend.call("targets")
        ]
        assert test_repo._bump_and_persist.calls == [
            pretend.call(mocked_targets, "targets")
        ]
        expected_result = {
            "targets": {
                "version": 4,
                "expire": datetime.datetime(
                    2023, 6, 15, 9, 5, 1, tzinfo=timezone.utc
                ),
                "target_files": [],
            }
        }
        assert result == expected_result

    def test_update_targets_delegated_role_from_storage(self, test_repo):
        fake_target_file1 = pretend.stub(path="file1.txt")
        fake_target_file2 = pretend.stub(path="file2.txt")
        fake_db_role = pretend.stub(
            rolename="test-role",
            version=3,
            target_files=[fake_target_file1, fake_target_file2],
        )
        test_repo._db = pretend.stub()
        crud.read_role_joint_files = pretend.call_recorder(
            lambda db, role: fake_db_role
        )
        fake_delegation = pretend.stub(
            signed=pretend.stub(
                version=4,
                expires=datetime.datetime(
                    2023, 6, 15, 9, 5, 1, tzinfo=timezone.utc
                ),
            )
        )

        test_repo._storage_backend = pretend.stub(
            get=pretend.call_recorder(
                lambda _role, _version=None: fake_delegation
            )
        )
        test_repo._update_db_role_target_files = pretend.call_recorder(
            lambda _delegation, _db_role: fake_delegation
        )
        test_repo.bump_persist_role = pretend.call_recorder(
            lambda *_args: None
        )

        result = test_repo.update_targets_delegated_role("test-role")

        assert crud.read_role_joint_files.calls == [
            pretend.call(test_repo._db, "test-role")
        ]
        assert test_repo._storage_backend.get.calls == [
            pretend.call("test-role", 3)
        ]
        assert test_repo._update_db_role_target_files.calls == [
            pretend.call(fake_delegation, fake_db_role)
        ]
        assert test_repo.bump_persist_role.calls == [
            pretend.call(fake_delegation, "test-role", True)
        ]
        expected_result = {
            "test-role": {
                "version": 4,
                "expire": datetime.datetime(
                    2023, 6, 15, 9, 5, 1, tzinfo=timezone.utc
                ),
                "target_files": ["file1.txt", "file2.txt"],
            }
        }
        assert result == expected_result

    def test_update_targets_delegated_role_from_settings(
        self, test_repo, monkeypatch
    ):
        fake_target_file1 = pretend.stub(path="file1.txt")
        fake_target_file2 = pretend.stub(path="file2.txt")
        fake_db_role = pretend.stub(
            rolename="test-role",
            version=3,
            target_files=[fake_target_file1, fake_target_file2],
        )
        test_repo._db = pretend.stub()
        crud.read_role_joint_files = pretend.call_recorder(
            lambda db, role: fake_db_role
        )
        fake_delegation = pretend.stub(
            signed=pretend.stub(
                version=4,
                expires=datetime.datetime(
                    2023, 6, 15, 0, 0, 0, tzinfo=timezone.utc
                ),
            )
        )
        crud.read_role_joint_files = pretend.call_recorder(
            lambda db, role: fake_db_role
        )

        test_repo._storage_backend = pretend.stub(
            get=pretend.raiser(StorageError("Role not found"))
        )

        fake_delegation_dict = {
            "signed": {"version": 4, "expires": "2023-06-15T00:00:00Z"}
        }

        def fake_get_fresh(key: str):
            if key == "TEST-ROLE_SIGNING":
                return fake_delegation_dict
            return None

        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: fake_get_fresh(*a)),
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )

        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_delegation
        )

        test_repo._update_db_role_target_files = pretend.call_recorder(
            lambda _delegation, _db_role: fake_delegation
        )
        test_repo.bump_persist_role = pretend.call_recorder(
            lambda *_args: None
        )

        result = test_repo.update_targets_delegated_role("test-role")

        assert test_repo._settings.get_fresh.calls == [
            pretend.call("TEST-ROLE_SIGNING")
        ]
        assert repository.Metadata.from_dict.calls == [
            pretend.call(fake_delegation_dict)
        ]
        assert test_repo.bump_persist_role.calls == [
            pretend.call(fake_delegation, "test-role", False)
        ]
        expected_result = {
            "test-role": {
                "version": 4,
                "expire": datetime.datetime(
                    2023, 6, 15, 0, 0, 0, tzinfo=timezone.utc
                ),
                "target_files": ["file1.txt", "file2.txt"],
            }
        }
        assert result == expected_result

    def test_update_targets_delegated_role_error(self, test_repo, monkeypatch):
        fake_db_role = pretend.stub(
            rolename="test-role", version=3, target_files=[]
        )
        crud.read_role_joint_files = pretend.call_recorder(
            lambda db, role: fake_db_role
        )
        storage_error = StorageError("Role not found")
        test_repo._storage_backend = pretend.stub(
            get=pretend.raiser(storage_error)
        )
        fake_settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *_args: None),
        )
        monkeypatch.setattr(
            repository,
            "get_repository_settings",
            lambda *a, **kw: fake_settings,
        )

        with pytest.raises(StorageError) as exc_info:
            test_repo.update_targets_delegated_role("test-role")

        assert exc_info.value is storage_error
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("TEST-ROLE_SIGNING")
        ]
