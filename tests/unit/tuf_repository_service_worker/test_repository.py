# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import datetime
from contextlib import contextmanager

import pretend
import pytest
from celery.exceptions import ChordError
from celery.result import states

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

    def test_create_service(self, test_repo):
        assert isinstance(test_repo, repository.MetadataRepository) is True

    def test_refresh_settings_with_none_arg(self, test_repo):
        test_repo.refresh_settings()

        assert (
            isinstance(test_repo._worker_settings, repository.Dynaconf) is True
        )
        assert isinstance(test_repo._settings, repository.Dynaconf) is True

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
        assert isinstance(test_repo._settings, repository.Dynaconf) is True

    def test_refresh_settings_with_invalid_storage_backend(self, test_repo):
        fake_worker_settings = pretend.stub(
            STORAGE_BACKEND="INVALID_STORAGE_BACKEND"
        )

        with pytest.raises(ValueError):
            test_repo.refresh_settings(fake_worker_settings)

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
        test_repo._key_storage_backend = pretend.stub(
            get=pretend.call_recorder(lambda *a: "key_signer_1")
        )

        test_result = test_repo._sign(fake_md)

        assert test_result is None
        assert test_repo._key_storage_backend.get.calls == [pretend.call({})]
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
        )

        repository.JSONSerializer = pretend.call_recorder(lambda: None)

        test_repo._storage_backend = pretend.stub(
            put=pretend.call_recorder(lambda *a: None)
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

    def test_bump_expiry(self, monkeypatch, test_repo):
        test_repo._settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: 1460)
        )
        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.datetime", fake_datetime
        )
        fake_role = pretend.stub(
            signed=pretend.stub(expires=fake_time),
        )

        result = test_repo._bump_expiry(fake_role, "root")
        assert result is None
        assert fake_role.signed.expires == datetime.datetime(
            2023, 6, 15, 9, 5, 1
        )
        assert fake_datetime.now.calls == [pretend.call()]

    def test__bump_version(self, test_repo):
        role = pretend.stub(
            signed=pretend.stub(version=2),
        )
        result = test_repo._bump_version(role)

        assert result is None
        assert role.signed.version == 3

    def test__update_timestamp(self, monkeypatch, test_repo):
        snapshot_version = 3
        fake_metafile = pretend.call_recorder(
            lambda *a, **kw: snapshot_version
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.MetaFile", fake_metafile
        )

        mocked_timestamp = pretend.stub(signed=pretend.stub(snapshot_meta=2))
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: mocked_timestamp
        )
        test_repo._bump_version = pretend.call_recorder(lambda *a: None)
        test_repo._bump_expiry = pretend.call_recorder(lambda *a: None)
        test_repo._sign = pretend.call_recorder(lambda *a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)

        result = test_repo._update_timestamp(snapshot_version)

        assert result == mocked_timestamp
        assert mocked_timestamp.signed.snapshot_meta == snapshot_version
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Roles.TIMESTAMP.value)
        ]
        assert test_repo._bump_version.calls == [
            pretend.call(mocked_timestamp)
        ]
        assert test_repo._bump_expiry.calls == [
            pretend.call(mocked_timestamp, repository.Roles.TIMESTAMP.value)
        ]
        assert test_repo._sign.calls == [pretend.call(mocked_timestamp)]
        assert test_repo._persist.calls == [
            pretend.call(mocked_timestamp, repository.Roles.TIMESTAMP.value)
        ]

    def test__update_timestamp_with_db_targets(self, monkeypatch, test_repo):
        snapshot_version = 3
        fake_metafile = pretend.call_recorder(
            lambda *a, **kw: snapshot_version
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.MetaFile", fake_metafile
        )

        mocked_timestamp = pretend.stub(signed=pretend.stub(snapshot_meta=2))
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: mocked_timestamp
        )
        test_repo._bump_version = pretend.call_recorder(lambda *a: None)
        test_repo._bump_expiry = pretend.call_recorder(lambda *a: None)
        test_repo._sign = pretend.call_recorder(lambda *a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)

        mocked_crud_update_to_publish = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr(
            repository.targets_crud,
            "update_to_published",
            mocked_crud_update_to_publish,
        )
        faked_db_targets = pretend.stub(path="path/file1")

        result = test_repo._update_timestamp(
            snapshot_version, [faked_db_targets]
        )

        assert result == mocked_timestamp
        assert mocked_timestamp.signed.snapshot_meta == snapshot_version
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Roles.TIMESTAMP.value)
        ]
        assert test_repo._bump_version.calls == [
            pretend.call(mocked_timestamp)
        ]
        assert test_repo._bump_expiry.calls == [
            pretend.call(mocked_timestamp, repository.Roles.TIMESTAMP.value)
        ]
        assert test_repo._sign.calls == [pretend.call(mocked_timestamp)]
        assert test_repo._persist.calls == [
            pretend.call(mocked_timestamp, repository.Roles.TIMESTAMP.value)
        ]
        assert mocked_crud_update_to_publish.calls == [
            pretend.call(test_repo._db, [faked_db_targets])
        ]

    def test__update_snapshot(self, test_repo):
        snapshot_version = 3
        test_target_meta = [("bins", 3), ("f", 4)]
        mocked_snapshot = pretend.stub(
            signed=pretend.stub(
                meta={},
                version=snapshot_version,
            )
        )

        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: mocked_snapshot
        )
        test_repo._bump_version = pretend.call_recorder(lambda *a: None)
        test_repo._bump_expiry = pretend.call_recorder(lambda *a: None)
        test_repo._sign = pretend.call_recorder(lambda *a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)

        result = test_repo._update_snapshot(test_target_meta)

        assert result is snapshot_version
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Roles.SNAPSHOT.value)
        ]
        assert test_repo._bump_version.calls == [pretend.call(mocked_snapshot)]
        assert test_repo._bump_expiry.calls == [
            pretend.call(mocked_snapshot, repository.Roles.SNAPSHOT.value)
        ]
        assert test_repo._sign.calls == [pretend.call(mocked_snapshot)]
        assert test_repo._persist.calls == [
            pretend.call(mocked_snapshot, repository.Roles.SNAPSHOT.value)
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
            pretend.call("targets")
        ]

    def test__update_task(self, monkeypatch, test_repo):
        test_repo._db = pretend.stub(
            refresh=pretend.call_recorder(lambda *a: None)
        )

        fake_target = pretend.stub(published=True)
        fake_bin_targets = {
            "bin-e": [fake_target],
            "bin-f": [fake_target, fake_target],
        }
        fake_update_state = pretend.call_recorder(lambda *a, **kw: None)
        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        fake_subtask = pretend.stub(status=states.SUCCESS)
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.datetime", fake_datetime
        )
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
                    "published_roles": ["bin-e"],
                    "roles_to_publish": "['bin-e', 'bin-f']",
                    "status": "Publishing",
                    "last_update": fake_time,
                    "exc_type": None,
                    "exc_message": None,
                },
            ),
        ]

    def test__update_task_subtask_failure(self, test_repo, monkeypatch):
        test_repo._db = pretend.stub(
            refresh=pretend.call_recorder(lambda *a: None)
        )

        fake_target = pretend.stub(published=True)
        fake_bin_targets = {
            "bin-e": [fake_target],
            "bin-f": [fake_target, fake_target],
        }
        fake_update_state = pretend.call_recorder(lambda *a, **kw: None)
        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        fake_subtask = pretend.stub(
            status=states.FAILURE,
            task_id="publish_targets-fakeid",
            result=PermissionError("failed to write in the storage"),
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.datetime", fake_datetime
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
                    "published_roles": ["bin-e"],
                    "roles_to_publish": "['bin-e', 'bin-f']",
                    "status": "Publishing",
                    "last_update": fake_time,
                    "exc_type": "PermissionError",
                    "exc_message": ["failed to write in the storage"],
                },
            ),
        ]

    def test_bootstrap(self, monkeypatch, test_repo):
        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.datetime", fake_datetime
        )
        fake_root_md = pretend.stub(
            type="root",
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids=["online_key_id"])},
                keys={"online_key_id": "online_public_key"},
            ),
        )
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_root_md
        )
        repository.Targets.add_key = pretend.call_recorder(lambda *a: None)
        repository.Key.from_securesystemslib_key = pretend.call_recorder(
            lambda *a: "key"
        )
        fake_online_public_key = pretend.stub(key_dict={"k": "v"})
        test_repo._key_storage_backend.get = pretend.call_recorder(
            lambda *a: fake_online_public_key
        )
        test_repo._bump_expiry = pretend.call_recorder(lambda *a: None)
        test_repo._sign = pretend.call_recorder(lambda *a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)

        payload = {
            "settings": {"services": {"number_of_delegated_bins": 2}},
            "metadata": {
                "root": {"md_k1": "md_v1"},
            },
        }

        result = test_repo.bootstrap(payload)
        assert result == {
            "details": {"bootstrap": True},
            "last_update": fake_time,
            "status": "Task finished.",
        }
        assert fake_datetime.now.calls == [pretend.call()]
        assert repository.Metadata.from_dict.calls == [
            pretend.call(payload["metadata"]["root"])
        ]
        assert repository.Key.from_securesystemslib_key.calls == [
            pretend.call({"k": "v"}),
            pretend.call({"k": "v"}),
        ]
        assert test_repo._key_storage_backend.get.calls == [
            pretend.call("online_public_key"),
            pretend.call("online_public_key"),
        ]

        # Special checks as calls use metadata object instances

        # Assert that calls contain two args and 'role' argument is a
        # 'Metadata'.
        for call in test_repo._bump_expiry.calls:
            assert len(call.args) == 2
            assert isinstance(call.args[0], repository.Metadata)
        # Assert the test_repo._bump_expiry calls role_name argument
        _bump_expiry_role_names = [
            call.args[1] for call in test_repo._bump_expiry.calls
        ]
        assert _bump_expiry_role_names == [
            "bins",
            "bins",
            "targets",
            "snapshot",
            "timestamp",
        ]

        # Assert that calls use two args and 'role' argument is a 'Metadata'
        # type or a pretend.sub()
        for call in test_repo._persist.calls:
            assert len(call.args) == 2
            assert isinstance(
                call.args[0], (repository.Metadata, pretend.stub)
            )
        # Assert the test_repo._persist calls role_name argument
        _persist_persist_role_names = [
            call.args[1] for call in test_repo._persist.calls
        ]
        assert _persist_persist_role_names == [
            "root",
            "bins-0",
            "bins-1",
            "targets",
            "snapshot",
            "timestamp",
        ]

        # The role argument is an instance we cannot check the object itself
        # object itself
        for call in test_repo._sign.calls:
            assert len(call.args) == 1
            assert isinstance(call.args[0], repository.Metadata)
        # Assert the number of calls test_repos._sign excluding root which we
        # don't sign during the worker bootstrap process. This check guarantees
        # that all signed metadata is persisted.
        assert len(test_repo._sign.calls) == len(test_repo._persist.calls) - 1

    def test_bootstrap_missing_settings(self, test_repo):
        payload = {
            "metadata": {
                "root": {"md_k1": "md_v1"},
            },
        }

        with pytest.raises(KeyError) as err:
            test_repo.bootstrap(payload)

        assert "No 'settings' in the payload" in str(err)

    def test_bootstrap_missing_metadata(self, test_repo):
        payload = {
            "settings": {"k": "v"},
        }

        with pytest.raises(KeyError) as err:
            test_repo.bootstrap(payload)

        assert "No 'metadata' in the payload" in str(err)

    def test_publish_targets(self, test_repo, monkeypatch):
        @contextmanager
        def mocked_lock(lock, timeout):
            yield lock, timeout

        test_repo._db = pretend.stub()
        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
        )

        fake_crud_read_unpublished_rolenames = pretend.call_recorder(
            lambda *a: [(False, "bins-0"), (False, "bins-e")]
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "read_unpublished_rolenames",
            fake_crud_read_unpublished_rolenames,
        )
        fake_crud_read_unpublished_by_rolename = pretend.call_recorder(
            lambda **kw: [
                pretend.stub(path="path/file1"),
                pretend.stub(path="path/file2"),
            ]
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "read_unpublished_by_rolename",
            fake_crud_read_unpublished_by_rolename,
        )
        monkeypatch.setattr(
            repository.TargetFile, "from_dict", lambda *a: {"k": "v"}
        )
        fake_crud_read_all_add_by_rolename = pretend.call_recorder(
            lambda *a: [
                ("file1", {"info": {"k": "v"}}),
                ("file2", {"info": {"k": "v"}}),
            ],
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "read_all_add_by_rolename",
            fake_crud_read_all_add_by_rolename,
        )
        fake_md_target = pretend.stub(
            signed=pretend.stub(
                targets={"old_key": {"old_meta": {"old_meta"}}},
                version=42,
            ),
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda r: fake_md_target
        )
        test_repo._bump_version = pretend.call_recorder(lambda *a: None)
        test_repo._bump_expiry = pretend.call_recorder(lambda *a: None)
        test_repo._sign = pretend.call_recorder(lambda *a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)
        test_repo._update_snapshot = pretend.call_recorder(
            lambda *a: "fake_md_snapshot"
        )
        test_repo._update_timestamp = pretend.call_recorder(lambda *a: None)

        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.datetime", fake_datetime
        )

        test_result = test_repo.publish_targets()

        assert test_result == repository.asdict(
            repository.ResultDetails(
                states.SUCCESS,
                details={
                    "target_roles": ["bins-0", "bins-e"],
                },
                last_update=fake_time,
            )
        )
        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=60.0),
            pretend.call(repository.LOCK_TIMESTAMP, timeout=60.0),
        ]
        assert fake_crud_read_unpublished_rolenames.calls == [
            pretend.call(test_repo._db)
        ]
        assert fake_crud_read_unpublished_by_rolename.calls == [
            pretend.call(db=test_repo._db, rolename="bins-0"),
            pretend.call(db=test_repo._db, rolename="bins-e"),
        ]
        assert fake_crud_read_all_add_by_rolename.calls == [
            pretend.call(test_repo._db, "bins-0"),
            pretend.call(test_repo._db, "bins-e"),
        ]
        assert test_repo._storage_backend.get.calls == [
            pretend.call("bins-0"),
            pretend.call("bins-e"),
        ]
        assert test_repo._bump_expiry.calls == [
            pretend.call(fake_md_target, "bins"),
            pretend.call(fake_md_target, "bins"),
        ]
        assert test_repo._sign.calls == [
            pretend.call(fake_md_target),
            pretend.call(fake_md_target),
        ]
        assert test_repo._persist.calls == [
            pretend.call(fake_md_target, "bins-0"),
            pretend.call(fake_md_target, "bins-e"),
        ]
        assert test_repo._update_snapshot.calls == [
            pretend.call([("bins-0", 42), ("bins-e", 42)])
        ]
        assert test_repo._update_timestamp.calls == [
            pretend.call(
                "fake_md_snapshot",
                [
                    "path/file1",
                    "path/file2",
                    "path/file1",
                    "path/file2",
                ],
            )
        ]
        assert fake_datetime.now.calls == [pretend.call()]

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
        self, test_repo, monkeypatch
    ):
        @contextmanager
        def mocked_lock(lock, timeout):
            yield lock, timeout

        test_repo._db = pretend.stub()
        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
        )

        fake_crud_read_unpublished_rolenames = pretend.call_recorder(
            lambda *a: []
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "read_unpublished_rolenames",
            fake_crud_read_unpublished_rolenames,
        )

        test_result = test_repo.publish_targets()

        assert test_result is None
        assert test_repo._redis.lock.calls == [
            pretend.call("LOCK_TARGETS", timeout=60.0)
        ]
        assert fake_crud_read_unpublished_rolenames.calls == [
            pretend.call(test_repo._db)
        ]

    def test_add_targets(self, test_repo, monkeypatch):
        test_repo._db = pretend.stub()
        test_repo._get_path_succinct_role = pretend.call_recorder(
            lambda *a: "bin-e"
        )

        def fake_target(key):
            if key == "path":
                return "fake_target1.tar.gz"
            if key == "info":
                return {"k": "v"}

        fake_db_target = pretend.stub(get=pretend.call_recorder(fake_target))

        monkeypatch.setattr(
            repository.targets_crud,
            "read_by_path",
            pretend.call_recorder(lambda *a: None),
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "create",
            pretend.call_recorder(lambda *a: fake_db_target),
        )
        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.datetime", fake_datetime
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
            "details": {
                "target_roles": ["bin-e"],
                "targets": ["file1.tar.gz"],
            },
            "last_update": fake_time,
            "status": "Task finished.",
        }
        assert test_repo._get_path_succinct_role.calls == [
            pretend.call("file1.tar.gz")
        ]
        assert test_repo._send_publish_targets_task.calls == [
            pretend.call("fake_task_id_xyz")
        ]
        assert test_repo._update_task.calls == [
            pretend.call(
                {"bin-e": [fake_db_target]}, fake_update_state, "fake_subtask"
            )
        ]
        assert repository.targets_crud.read_by_path.calls == [
            pretend.call(test_repo._db, "file1.tar.gz")
        ]
        assert repository.targets_crud.create.calls == [
            pretend.call(
                test_repo._db,
                targets_schema.TargetsCreate(
                    path=payload["targets"][0].get("path"),
                    info=payload["targets"][0].get("info"),
                    published=False,
                    action=targets_schema.TargetAction.ADD,
                    rolename="bin-e",
                ),
            )
        ]
        assert fake_datetime.now.calls == [pretend.call()]

    def test_add_targets_exists(self, test_repo, monkeypatch):
        test_repo._db = pretend.stub()
        test_repo._get_path_succinct_role = pretend.call_recorder(
            lambda *a: "bin-e"
        )

        def fake_target(key):
            if key == "path":
                return "fake_target1.tar.gz"
            if key == "info":
                return {"k": "v"}

        fake_db_target = pretend.stub(get=pretend.call_recorder(fake_target))
        monkeypatch.setattr(
            repository.targets_crud,
            "read_by_path",
            pretend.call_recorder(lambda *a: fake_db_target),
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "update",
            pretend.call_recorder(lambda *a: fake_db_target),
        )

        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.datetime", fake_datetime
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
            "details": {
                "target_roles": ["bin-e"],
                "targets": ["file1.tar.gz"],
            },
            "last_update": fake_time,
            "status": "Task finished.",
        }
        assert test_repo._get_path_succinct_role.calls == [
            pretend.call("file1.tar.gz")
        ]
        assert test_repo._send_publish_targets_task.calls == [
            pretend.call("fake_task_id_xyz")
        ]
        assert test_repo._update_task.calls == [
            pretend.call(
                {"bin-e": [fake_db_target]}, fake_update_state, "fake_subtask"
            )
        ]
        assert repository.targets_crud.read_by_path.calls == [
            pretend.call(test_repo._db, "file1.tar.gz")
        ]
        assert repository.targets_crud.update.calls == [
            pretend.call(
                test_repo._db,
                fake_db_target,
                payload["targets"][0].get("path"),
                payload["targets"][0].get("info"),
            )
        ]
        assert fake_datetime.now.calls == [pretend.call()]

    def test_add_targets_without_targets(self, test_repo):
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

        with pytest.raises(ValueError) as err:
            test_repo.add_targets(payload, update_state=pretend.stub())

        assert "No targets in the payload" in str(err)

    def test_add_targets_skip_publishing(self, test_repo, monkeypatch):
        test_repo._db = pretend.stub()
        test_repo._get_path_succinct_role = pretend.call_recorder(
            lambda *a: "bin-e"
        )

        def fake_target(key):
            if key == "path":
                return "fake_target1.tar.gz"
            if key == "info":
                return {"k": "v"}

        fake_db_target = pretend.stub(get=pretend.call_recorder(fake_target))

        monkeypatch.setattr(
            repository.targets_crud,
            "read_by_path",
            pretend.call_recorder(lambda *a: None),
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "create",
            pretend.call_recorder(lambda *a: fake_db_target),
        )
        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.datetime", fake_datetime
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
            "publish_targets": False,
        }

        fake_update_state = pretend.stub()
        result = test_repo.add_targets(payload, update_state=fake_update_state)

        assert result == {
            "details": {
                "target_roles": ["bin-e"],
                "targets": ["file1.tar.gz"],
            },
            "last_update": fake_time,
            "status": "Task finished.",
        }
        assert test_repo._get_path_succinct_role.calls == [
            pretend.call("file1.tar.gz")
        ]
        assert repository.targets_crud.read_by_path.calls == [
            pretend.call(test_repo._db, "file1.tar.gz")
        ]
        assert repository.targets_crud.create.calls == [
            pretend.call(
                test_repo._db,
                targets_schema.TargetsCreate(
                    path=payload["targets"][0].get("path"),
                    info=payload["targets"][0].get("info"),
                    published=False,
                    action=targets_schema.TargetAction.ADD,
                    rolename="bin-e",
                ),
            )
        ]
        assert test_repo._update_task.calls == [
            pretend.call({"bin-e": [fake_db_target]}, fake_update_state, None)
        ]
        assert fake_datetime.now.calls == [pretend.call()]

    def test_remove_targets(self, test_repo, monkeypatch):
        test_repo._get_path_succinct_role = pretend.call_recorder(
            lambda *a: "bin-e"
        )
        fake_db_target = pretend.stub(action="REMOVE", published=False)
        monkeypatch.setattr(
            repository.targets_crud,
            "read_by_path",
            lambda *a: fake_db_target,
        )
        fake_db_target_removed = pretend.stub()
        monkeypatch.setattr(
            repository.targets_crud,
            "update_action_remove",
            lambda *a: fake_db_target_removed,
        )
        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.datetime", fake_datetime
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
            "status": "Task finished.",
            "last_update": fake_time,
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
        assert test_repo._send_publish_targets_task.calls == [
            pretend.call("fake_task_id_xyz")
        ]
        assert test_repo._update_task.calls == [
            pretend.call(
                {
                    "bin-e": [
                        fake_db_target_removed,
                        fake_db_target_removed,
                        fake_db_target_removed,
                    ]
                },
                fake_update_state,
                "fake_subtask",
            )
        ]
        assert fake_datetime.now.calls == [pretend.call()]

    def test_remove_targets_skip_publishing(self, test_repo, monkeypatch):
        test_repo._get_path_succinct_role = pretend.call_recorder(
            lambda *a: "bin-e"
        )
        fake_db_target = pretend.stub(action="REMOVE", published=False)
        monkeypatch.setattr(
            repository.targets_crud,
            "read_by_path",
            lambda *a: fake_db_target,
        )
        fake_db_target_removed = pretend.stub()
        monkeypatch.setattr(
            repository.targets_crud,
            "update_action_remove",
            lambda *a: fake_db_target_removed,
        )

        test_repo._update_task = pretend.call_recorder(lambda *a: None)

        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.datetime", fake_datetime
        )

        payload = {
            "targets": ["file1.tar.gz", "file2.tar.gz", "release-v0.1.0.yaml"],
            "task_id": "fake_task_id_xyz",
            "publish_targets": False,
        }

        fake_update_state = pretend.stub()
        result = test_repo.remove_targets(
            payload, update_state=fake_update_state
        )

        assert result == {
            "status": "Task finished.",
            "last_update": fake_time,
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
        assert test_repo._update_task.calls == [
            pretend.call(
                {
                    "bin-e": [
                        fake_db_target_removed,
                        fake_db_target_removed,
                        fake_db_target_removed,
                    ]
                },
                fake_update_state,
                None,
            )
        ]
        assert fake_datetime.now.calls == [pretend.call()]

    def test_remove_targets_all_none(self, test_repo, monkeypatch):
        test_repo._get_path_succinct_role = pretend.call_recorder(
            lambda *a: "bin-e"
        )

        monkeypatch.setattr(
            repository.targets_crud,
            "read_by_path",
            lambda *a: None,
        )
        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.datetime", fake_datetime
        )
        payload = {
            "targets": ["file2.tar.gz", "file3.tar.gz", "release-v0.1.0.yaml"]
        }

        result = test_repo.remove_targets(payload, update_state=pretend.stub())

        assert result == {
            "status": "Task finished.",
            "last_update": fake_time,
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

        assert fake_datetime.now.calls == [pretend.call()]

    def test_remove_targets_action_remove_published_true(
        self, test_repo, monkeypatch
    ):
        test_repo._get_path_succinct_role = pretend.call_recorder(
            lambda *a: "bin-e"
        )

        fake_db_target = pretend.stub(
            action=targets_schema.TargetAction.REMOVE, published=True
        )
        monkeypatch.setattr(
            repository.targets_crud,
            "read_by_path",
            lambda *a: fake_db_target,
        )
        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.datetime", fake_datetime
        )
        payload = {
            "targets": ["file2.tar.gz", "file3.tar.gz", "release-v0.1.0.yaml"]
        }

        result = test_repo.remove_targets(payload, update_state=pretend.stub())

        assert result == {
            "status": "Task finished.",
            "last_update": fake_time,
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

        assert fake_datetime.now.calls == [pretend.call()]

    def test_remove_targets_without_targets(self, test_repo):
        payload = {"paths": []}

        with pytest.raises(ValueError) as err:
            test_repo.remove_targets(payload, update_state=pretend.stub())

        assert "No targets in the payload" in str(err)

    def test_remove_targets_empty_targets(self, test_repo):
        payload = {"targets": []}

        with pytest.raises(IndexError) as err:
            test_repo.remove_targets(payload, update_state=pretend.stub())

        assert "At list one target is required" in str(err)

    def test_bump_target_roles(self, test_repo):
        fake_targets = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(
                    succinct_roles=pretend.stub(
                        get_roles=pretend.call_recorder(lambda *a: ["bin-a"])
                    )
                ),
                expires=datetime.datetime(2019, 6, 16, 8, 5, 1),
                version=1,
            )
        )

        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_bins = pretend.stub(
            signed=pretend.stub(targets={}, version=6, expires=fake_time)
        )

        def mocked_get(role):
            if role == "targets":
                return fake_targets
            else:
                return fake_bins

        test_repo._storage_backend.get = pretend.call_recorder(
            lambda r: mocked_get(r)
        )
        test_repo._settings.get_fresh = pretend.call_recorder(lambda *a: True)
        test_repo._bump_version = pretend.call_recorder(lambda *a: None)
        test_repo._bump_expiry = pretend.call_recorder(lambda *a: None)
        test_repo._sign = pretend.call_recorder(lambda *a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)
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
        result = test_repo.bump_target_roles()
        assert result is True
        assert test_repo._storage_backend.get.calls == [
            pretend.call("targets"),
            pretend.call("bin-a"),
        ]
        assert test_repo._bump_version.calls == [
            pretend.call(fake_targets),
            pretend.call(fake_bins),
        ]
        assert test_repo._bump_expiry.calls == [
            pretend.call(fake_targets),
            pretend.call(fake_bins, "bins"),
        ]
        assert test_repo._sign.calls == [
            pretend.call(fake_targets),
            pretend.call(fake_bins),
        ]
        assert test_repo._persist.calls == [
            pretend.call(fake_targets, repository.Targets.type),
            pretend.call(fake_bins, "bin-a"),
        ]
        assert test_repo._update_snapshot.calls == [
            pretend.call([("targets", 1), ("bin-a", 6)])
        ]
        assert test_repo._update_timestamp.calls == [
            pretend.call("fake_snapshot")
        ]

    def test_bump_target_roles_target_no_online_keys(self, caplog, test_repo):
        caplog.set_level(repository.logging.WARNING)
        fake_targets = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(
                    succinct_roles=pretend.stub(
                        get_roles=pretend.call_recorder(lambda *a: ["bin-a"])
                    )
                ),
                expires=datetime.datetime(2019, 6, 16, 8, 5, 1),
                version=1,
            )
        )

        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_bins = pretend.stub(
            signed=pretend.stub(targets={}, version=6, expires=fake_time)
        )

        def mocked_get(role):
            if role == "targets":
                return fake_targets
            else:
                return fake_bins

        test_repo._storage_backend.get = pretend.call_recorder(
            lambda r: mocked_get(r)
        )
        test_repo._settings.get_fresh = pretend.call_recorder(lambda *a: False)
        test_repo._bump_version = pretend.call_recorder(lambda *a: None)
        test_repo._bump_expiry = pretend.call_recorder(lambda *a: None)
        test_repo._sign = pretend.call_recorder(lambda *a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)
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
        result = test_repo.bump_target_roles()
        assert (
            "targets don't use online key, skipping 'Targets' role"
            in caplog.record_tuples[0]
        )
        assert result is True
        assert test_repo._storage_backend.get.calls == [
            pretend.call("targets"),
            pretend.call("bin-a"),
        ]
        assert test_repo._bump_version.calls == [pretend.call(fake_bins)]
        assert test_repo._bump_expiry.calls == [
            pretend.call(fake_bins, "bins")
        ]
        assert test_repo._sign.calls == [pretend.call(fake_bins)]
        assert test_repo._persist.calls == [pretend.call(fake_bins, "bin-a")]
        assert test_repo._update_snapshot.calls == [
            pretend.call([("bin-a", 6)])
        ]
        assert test_repo._update_timestamp.calls == [
            pretend.call("fake_snapshot")
        ]

    def test_bump_target_roles_warning_missing_config(self, caplog, test_repo):
        caplog.set_level(repository.logging.CRITICAL)
        fake_targets = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(
                    succinct_roles=pretend.stub(
                        get_roles=pretend.call_recorder(lambda *a: ["bin-a"])
                    )
                ),
                expires=datetime.datetime(2019, 6, 16, 8, 5, 1),
                version=1,
            )
        )

        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_bins = pretend.stub(
            signed=pretend.stub(targets={}, version=6, expires=fake_time)
        )

        def mocked_get(role):
            if role == "targets":
                return fake_targets
            else:
                return fake_bins

        test_repo._storage_backend.get = pretend.call_recorder(
            lambda r: mocked_get(r)
        )
        test_repo._settings.get_fresh = pretend.call_recorder(lambda *a: None)
        test_repo._bump_version = pretend.call_recorder(lambda *a: None)
        test_repo._bump_expiry = pretend.call_recorder(lambda *a: None)
        test_repo._sign = pretend.call_recorder(lambda *a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)
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
        result = test_repo.bump_target_roles()
        assert (
            "No configuration found for TARGETS_ONLINE_KEY"
            in caplog.record_tuples[0]
        )
        assert result is True
        assert test_repo._storage_backend.get.calls == [
            pretend.call("targets"),
            pretend.call("bin-a"),
        ]
        assert test_repo._bump_version.calls == [pretend.call(fake_bins)]
        assert test_repo._bump_expiry.calls == [
            pretend.call(fake_bins, "bins")
        ]
        assert test_repo._sign.calls == [pretend.call(fake_bins)]
        assert test_repo._persist.calls == [pretend.call(fake_bins, "bin-a")]
        assert test_repo._update_snapshot.calls == [
            pretend.call([("bin-a", 6)])
        ]
        assert test_repo._update_timestamp.calls == [
            pretend.call("fake_snapshot")
        ]

    def test_bump_target_roles_no_changes(self, test_repo):
        fake_targets = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(
                    succinct_roles=pretend.stub(
                        get_roles=pretend.call_recorder(lambda *a: ["bin-a"])
                    )
                ),
                expires=datetime.datetime(2054, 6, 16, 8, 5, 1),
                version=1,
            )
        )

        fake_time = datetime.datetime(2054, 6, 16, 9, 5, 1)
        fake_bins = pretend.stub(
            signed=pretend.stub(targets={}, version=6, expires=fake_time)
        )

        def mocked_get(role):
            if role == "targets":
                return fake_targets
            else:
                return fake_bins

        test_repo._storage_backend.get = pretend.call_recorder(
            lambda r: mocked_get(r)
        )

        result = test_repo.bump_target_roles()
        assert result is True
        assert test_repo._storage_backend.get.calls == [
            pretend.call("targets"),
            pretend.call("bin-a"),
        ]

    def test_bump_target_roles_StorageError(self, test_repo):
        test_repo._storage_backend.get = pretend.raiser(
            repository.StorageError("Overwrite it")
        )

        result = test_repo.bump_target_roles()
        assert result is False

    def test_bump_snapshot(self, test_repo):
        fake_snapshot = pretend.stub(
            signed=pretend.stub(
                meta={},
                expires=datetime.datetime(2019, 6, 16, 9, 5, 1),
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

        result = test_repo.bump_snapshot()
        assert result is True
        assert test_repo._storage_backend.get.calls == [
            pretend.call("snapshot")
        ]
        assert test_repo._update_snapshot.calls == [pretend.call([])]
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

        result = test_repo.bump_snapshot()
        assert result is True
        assert test_repo._storage_backend.get.calls == [
            pretend.call("snapshot")
        ]

    def test_bump_snapshot_not_found(self, test_repo):
        test_repo._storage_backend.get = pretend.raiser(
            repository.StorageError
        )

        result = test_repo.bump_snapshot()
        assert result is False

    def test_bump_online_roles(self, test_repo):
        @contextmanager
        def mocked_lock(lock, timeout):
            yield lock, timeout

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock)
        )
        test_repo._settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: "fake_bootstrap_id")
        )
        test_repo.bump_target_roles = pretend.call_recorder(lambda **kw: None)

        result = test_repo.bump_online_roles()
        assert result is True
        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=60)
        ]
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]
        assert test_repo.bump_target_roles.calls == [pretend.call(force=False)]

    def test_bump_online_roles_when_no_bootstrap(self, test_repo):
        @contextmanager
        def mocked_lock(lock, timeout):
            yield lock, timeout

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock)
        )
        test_repo._settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: None)
        )

        result = test_repo.bump_online_roles()
        assert result is False
        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=60)
        ]
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]

    def test_bump_online_roles_exception_LockNotOwnedError(self, test_repo):
        @contextmanager
        def mocked_lock(lock, timeout):
            raise repository.redis.exceptions.LockNotOwnedError("timeout")

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock)
        )
        with pytest.raises(repository.redis.exceptions.LockError) as e:
            test_repo.bump_online_roles()

        assert "RSTUF: Task exceed `LOCK_TIMEOUT` (60 seconds)" in str(e)
        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=60)
        ]

    def test_metadata_rotation_only_root(self, monkeypatch, test_repo):
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
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_new_root_md
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_old_root_md
        )
        test_repo._persist = pretend.call_recorder(lambda *a: None)
        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.datetime", fake_datetime
        )
        payload = {"metadata": {"root": "root_metadata"}}
        result = test_repo.metadata_rotation(payload)

        assert result == {
            "status": "Task finished.",
            "details": {
                "message": "metadata rotation finished",
            },
            "last_update": fake_time,
        }
        assert repository.Metadata.from_dict.calls == [
            pretend.call("root_metadata")
        ]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Root.type)
        ]
        assert test_repo._persist.calls == [
            pretend.call(fake_new_root_md, repository.Root.type)
        ]
        assert repository.datetime.now.calls == [pretend.call()]

    def test_metadata_rotation_online_key(self, monkeypatch, test_repo):
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
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_new_root_md
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_old_root_md
        )

        @contextmanager
        def mocked_lock(lock, timeout):
            yield lock, timeout

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
        )
        test_repo._persist = pretend.call_recorder(lambda *a: None)
        test_repo.bump_target_roles = pretend.call_recorder(lambda **kw: None)
        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.datetime", fake_datetime
        )
        payload = {"metadata": {"root": "root_metadata"}}
        result = test_repo.metadata_rotation(payload)

        assert result == {
            "status": "Task finished.",
            "details": {
                "message": "metadata rotation finished",
            },
            "last_update": fake_time,
        }
        assert repository.Metadata.from_dict.calls == [
            pretend.call("root_metadata")
        ]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Root.type)
        ]
        assert test_repo._redis.lock.calls == [
            pretend.call(repository.LOCK_TARGETS, timeout=60.0)
        ]
        assert test_repo._persist.calls == [
            pretend.call(fake_new_root_md, repository.Root.type)
        ]
        assert test_repo.bump_target_roles.calls == [pretend.call(force=True)]
        assert repository.datetime.now.calls == [pretend.call()]

    def test_metadata_rotation_online_key_lock_timeout(self, test_repo):
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
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_new_root_md
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_old_root_md
        )

        @contextmanager
        def mocked_lock(lock, timeout):
            raise repository.redis.exceptions.LockNotOwnedError("timeout")

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
        )
        payload = {"metadata": {"root": "root_metadata"}}
        with pytest.raises(repository.redis.exceptions.LockError) as e:
            test_repo.metadata_rotation(payload)

        assert "RSTUF: Task exceed `LOCK_TIMEOUT` (60 seconds)" in str(e)
        assert repository.Metadata.from_dict.calls == [
            pretend.call("root_metadata")
        ]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Root.type)
        ]

    def test_metadata_rotation_no_metadata(self, test_repo):
        payload = {}
        with pytest.raises(KeyError) as e:
            test_repo.metadata_rotation(payload)

        assert "No 'metadata' in the payload" in str(e)

    def test_metadata_rotation_unexpected_version_higher(self, test_repo):
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k1": "v1"})},
                version=3,
            )
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k2": "v2"})},
                version=1,
            )
        )
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_new_root_md
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_old_root_md
        )

        payload = {"metadata": {"root": "root_metadata"}}
        with pytest.raises(repository.BadVersionNumberError) as e:
            test_repo.metadata_rotation(payload)

        assert (
            f"New root version not expected {fake_new_root_md.signed.version}"
            in str(e)
        )
        assert repository.Metadata.from_dict.calls == [
            pretend.call("root_metadata")
        ]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Root.type)
        ]

    def test_metadata_rotation_unexpected_version_lower(self, test_repo):
        fake_new_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k1": "v1"})},
                version=2,
            )
        )
        fake_old_root_md = pretend.stub(
            signed=pretend.stub(
                roles={"timestamp": pretend.stub(keyids={"k2": "v2"})},
                version=5,
            )
        )
        repository.Metadata.from_dict = pretend.call_recorder(
            lambda *a: fake_new_root_md
        )
        test_repo._storage_backend.get = pretend.call_recorder(
            lambda *a: fake_old_root_md
        )

        payload = {"metadata": {"root": "root_metadata"}}
        with pytest.raises(repository.BadVersionNumberError) as e:
            test_repo.metadata_rotation(payload)

        assert (
            f"New root version not expected {fake_new_root_md.signed.version}"
            in str(e)
        )
        assert repository.Metadata.from_dict.calls == [
            pretend.call("root_metadata")
        ]
        assert test_repo._storage_backend.get.calls == [
            pretend.call(repository.Root.type)
        ]
