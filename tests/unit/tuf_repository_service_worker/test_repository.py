# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT

import datetime
from contextlib import contextmanager

import pretend
import pytest

from repository_service_tuf_worker import Dynaconf, repository
from repository_service_tuf_worker.models import targets_schema


class TestMetadataRepository:
    def test_basic_init(self):
        test_repo = repository.MetadataRepository()
        assert isinstance(test_repo, repository.MetadataRepository) is True

    def test_create_service(self):
        test_repo = repository.MetadataRepository.create_service()
        assert isinstance(test_repo, repository.MetadataRepository) is True

    def test_refresh_settings_with_none_arg(self):
        test_repo = repository.MetadataRepository.create_service()
        test_repo.refresh_settings()

        assert (
            isinstance(test_repo._worker_settings, repository.Dynaconf) is True
        )
        assert isinstance(test_repo._settings, repository.Dynaconf) is True

    def test_refresh_settings_with_worker_settings_arg(self):
        FAKE_SETTINGS_FILE_PATH = "/data/mysettings.ini"
        fake_worker_settings = Dynaconf(
            settings_files=[FAKE_SETTINGS_FILE_PATH],
            envvar_prefix="RSTUF",
        )

        test_repo = repository.MetadataRepository.create_service()
        test_repo.refresh_settings(fake_worker_settings)

        assert (
            test_repo._worker_settings.to_dict()
            == fake_worker_settings.to_dict()
        )
        assert isinstance(test_repo._settings, repository.Dynaconf) is True

    def test_refresh_settings_with_invalid_storage_backend(self):
        fake_worker_settings = pretend.stub(
            STORAGE_BACKEND="INVALID_STORAGE_BACKEND"
        )

        test_repo = repository.MetadataRepository.create_service()

        with pytest.raises(ValueError):
            test_repo.refresh_settings(fake_worker_settings)

    def test__sign(self):
        test_repo = repository.MetadataRepository.create_service()

        fake_role = pretend.stub(
            signatures=pretend.stub(clear=pretend.call_recorder(lambda: None)),
            sign=pretend.call_recorder(lambda *a, **kw: None),
        )
        test_repo._key_storage_backend = pretend.stub(
            get=pretend.call_recorder(
                lambda *a, **kw: ["key_signer_1", "key_signer_2"]
            )
        )

        test_result = test_repo._sign(fake_role, "root")

        assert test_result is None
        assert test_repo._key_storage_backend.get.calls == [pretend.call()]
        assert fake_role.signatures.clear.calls == [pretend.call()]
        assert fake_role.sign.calls == [
            pretend.call("key_signer_1", append=True),
            pretend.call("key_signer_2", append=True),
        ]

    def _test_helper_persist(self, role, version, expected_file_name):
        test_repo = repository.MetadataRepository.create_service()
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

    def test__persist(self):
        self._test_helper_persist("snapshot", 2, "2.snapshot.json")

    def test__persist_file_has_version(self):
        self._test_helper_persist("1.snapshot", 1, "1.snapshot.json")

    def test__persist_file_has_number_name(self):
        self._test_helper_persist("bin-3", 2, "2.bin-3.json")

    def test__persist_timestamp(self):
        self._test_helper_persist("timestamp", 2, "timestamp.json")

    def test_bump_expiry(self, monkeypatch):
        test_repo = repository.MetadataRepository.create_service()
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

    def test__bump_version(self):
        test_repo = repository.MetadataRepository.create_service()

        role = pretend.stub(
            signed=pretend.stub(version=2),
        )
        result = test_repo._bump_version(role)

        assert result is None
        assert role.signed.version == 3

    def test__update_timestamp(self, monkeypatch):
        test_repo = repository.MetadataRepository.create_service()

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
        assert test_repo._sign.calls == [
            pretend.call(mocked_timestamp, repository.Roles.TIMESTAMP.value)
        ]
        assert test_repo._persist.calls == [
            pretend.call(mocked_timestamp, repository.Roles.TIMESTAMP.value)
        ]

    def test__update_timestamp_with_db_targets(self, monkeypatch):
        test_repo = repository.MetadataRepository.create_service()

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
        faked_db_target = pretend.stub()

        result = test_repo._update_timestamp(
            snapshot_version, [faked_db_target]
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
        assert test_repo._sign.calls == [
            pretend.call(mocked_timestamp, repository.Roles.TIMESTAMP.value)
        ]
        assert test_repo._persist.calls == [
            pretend.call(mocked_timestamp, repository.Roles.TIMESTAMP.value)
        ]
        assert mocked_crud_update_to_publish.calls == [
            pretend.call(test_repo._db, faked_db_target)
        ]

    def test__update_snapshot(self):
        test_repo = repository.MetadataRepository.create_service()

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
        assert test_repo._sign.calls == [
            pretend.call(mocked_snapshot, repository.Roles.SNAPSHOT.value)
        ]
        assert test_repo._persist.calls == [
            pretend.call(mocked_snapshot, repository.Roles.SNAPSHOT.value)
        ]

    def test__get_path_succinct_role(self):
        test_repo = repository.MetadataRepository.create_service()

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

    def test__update_task(self, monkeypatch):
        test_repo = repository.MetadataRepository.create_service()

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
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.datetime", fake_datetime
        )
        result = test_repo._update_task(fake_bin_targets, fake_update_state)

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
                },
            )
        ]

    def test_bootstrap(self, monkeypatch):
        test_repo = repository.MetadataRepository.create_service()

        test_repo._persist = pretend.call_recorder(lambda *a: None)
        repository.Metadata = pretend.stub(
            from_dict=pretend.call_recorder(lambda *a: "fake_metadata")
        )
        repository.JSONSerializer = pretend.call_recorder(lambda: None)
        test_repo._storage_backend = pretend.stub()

        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.datetime", fake_datetime
        )

        payload = {
            "settings": {"k": "v"},
            "metadata": {
                "1.root": {"md_k1": "md_v1"},
                "1.snapshot": {"md_k2": "md_v2"},
            },
        }

        result = test_repo.bootstrap(payload)
        assert result == {
            "details": {"bootstrap": True},
            "last_update": fake_time,
            "status": "Task finished.",
        }
        assert repository.Metadata.from_dict.calls == [
            pretend.call({"md_k1": "md_v1"}),
            pretend.call({"md_k2": "md_v2"}),
        ]
        assert fake_datetime.now.calls == [pretend.call()]
        assert test_repo._persist.calls == [
            pretend.call("fake_metadata", "1.root"),
            pretend.call("fake_metadata", "1.snapshot"),
        ]

    def test_bootstrap_missing_settings(self):
        test_repo = repository.MetadataRepository.create_service()

        payload = {
            "metadata": {
                "1.root": {"md_k1": "md_v1"},
                "1.snapshot": {"md_k2": "md_v2"},
            },
        }

        with pytest.raises(ValueError) as err:
            test_repo.bootstrap(payload)

        assert "No settings in the payload" in str(err)

    def test_bootstrap_missing_metadata(self):
        test_repo = repository.MetadataRepository.create_service()

        payload = {
            "settings": {"k": "v"},
        }

        with pytest.raises(ValueError) as err:
            test_repo.bootstrap(payload)

        assert "No metadata in the payload" in str(err)

    def test_publish_targets(self, monkeypatch):
        test_repo = repository.MetadataRepository.create_service()

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
        fake_db_targets = pretend.stub()
        fake_crud_read_unpublished_by_rolename = pretend.call_recorder(
            lambda **kw: [fake_db_targets, fake_db_targets]
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

        test_result = test_repo.publish_targets()

        assert test_result is None
        assert test_repo._redis.lock.calls == [
            pretend.call("publish_targets", timeout=5.0)
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
            pretend.call(fake_md_target, "bins"),
            pretend.call(fake_md_target, "bins"),
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
                    fake_db_targets,
                    fake_db_targets,
                    fake_db_targets,
                    fake_db_targets,
                ],
            )
        ]

    def test_publish_targets_without_targets_to_publish(self, monkeypatch):
        test_repo = repository.MetadataRepository.create_service()

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
            pretend.call("publish_targets", timeout=5.0)
        ]
        assert fake_crud_read_unpublished_rolenames.calls == [
            pretend.call(test_repo._db)
        ]

    def test_add_targets(self, monkeypatch):
        test_repo = repository.MetadataRepository.create_service()
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
            lambda *a: None
        )
        test_repo._update_task = pretend.call_recorder(lambda *a: None)

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
            pretend.call({"bin-e": [fake_db_target]}, fake_update_state)
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

    def test_add_targets_exists(self, monkeypatch):
        test_repo = repository.MetadataRepository.create_service()
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
            lambda *a: None
        )
        test_repo._update_task = pretend.call_recorder(lambda *a: None)

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
            pretend.call({"bin-e": [fake_db_target]}, fake_update_state)
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

    def test_add_targets_without_targets(self):
        test_repo = repository.MetadataRepository.create_service()

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

    def test_remove_targets(self, monkeypatch):
        test_repo = repository.MetadataRepository.create_service()

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
            lambda *a: None
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
            )
        ]
        assert fake_datetime.now.calls == [pretend.call()]

    def test_remove_targets_all_none(self, monkeypatch):
        test_repo = repository.MetadataRepository.create_service()

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

    def test_remove_targets_action_remove_published_true(self, monkeypatch):
        test_repo = repository.MetadataRepository.create_service()

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

    def test_remove_targets_without_targets(self):
        test_repo = repository.MetadataRepository.create_service()

        payload = {"paths": []}

        with pytest.raises(ValueError) as err:
            test_repo.remove_targets(payload, update_state=pretend.stub())

        assert "No targets in the payload" in str(err)

    def test_remove_targets_empty_targets(self):
        test_repo = repository.MetadataRepository.create_service()

        payload = {"targets": []}

        with pytest.raises(IndexError) as err:
            test_repo.remove_targets(payload, update_state=pretend.stub())

        assert "At list one target is required" in str(err)

    def test_bump_bins_roles(self):
        test_repo = repository.MetadataRepository.create_service()

        fake_targets = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(
                    succinct_roles=pretend.stub(
                        get_roles=pretend.call_recorder(lambda *a: ["bin-a"])
                    )
                ),
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
        result = test_repo.bump_bins_roles()
        assert result is True
        assert test_repo._storage_backend.get.calls == [
            pretend.call("targets"),
            pretend.call("bin-a"),
        ]
        assert test_repo._bump_version.calls == [pretend.call(fake_bins)]
        assert test_repo._bump_expiry.calls == [
            pretend.call(fake_bins, "bins")
        ]
        assert test_repo._sign.calls == [pretend.call(fake_bins, "bins")]
        assert test_repo._persist.calls == [pretend.call(fake_bins, "bin-a")]
        assert test_repo._update_snapshot.calls == [
            pretend.call([("bin-a", 6)])
        ]
        assert test_repo._update_timestamp.calls == [
            pretend.call("fake_snapshot")
        ]

    def test_bump_bins_roles_no_changes(self):
        test_repo = repository.MetadataRepository.create_service()

        fake_targets = pretend.stub(
            signed=pretend.stub(
                delegations=pretend.stub(
                    succinct_roles=pretend.stub(
                        get_roles=pretend.call_recorder(lambda *a: ["bin-a"])
                    )
                ),
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

        result = test_repo.bump_bins_roles()
        assert result is True
        assert test_repo._storage_backend.get.calls == [
            pretend.call("targets"),
            pretend.call("bin-a"),
        ]

    def test_bump_bins_roles_StorageError(self):
        test_repo = repository.MetadataRepository.create_service()

        test_repo._storage_backend.get = pretend.raiser(
            repository.StorageError("Overwrite it")
        )

        result = test_repo.bump_bins_roles()
        assert result is False

    def test_bump_snapshot(self):
        test_repo = repository.MetadataRepository.create_service()

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

    def test_bump_snapshot_unexpired(self):
        test_repo = repository.MetadataRepository.create_service()

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

    def test_bump_snapshot_not_found(self):
        test_repo = repository.MetadataRepository.create_service()

        test_repo._storage_backend.get = pretend.raiser(
            repository.StorageError
        )

        result = test_repo.bump_snapshot()
        assert result is False

    def test_bump_online_roles(self):
        test_repo = repository.MetadataRepository.create_service()

        @contextmanager
        def mocked_lock(lock):
            yield lock

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock)
        )
        test_repo._settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: "fake_bootstrap_id")
        )
        test_repo.bump_snapshot = pretend.call_recorder(lambda: None)
        test_repo.bump_bins_roles = pretend.call_recorder(lambda: None)

        result = test_repo.bump_online_roles()
        assert result is True
        assert test_repo._redis.lock.calls == [
            pretend.call("TUF_SNAPSHOT_TIMESTAMP")
        ]
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]
        assert test_repo.bump_snapshot.calls == [pretend.call()]
        assert test_repo.bump_bins_roles.calls == [pretend.call()]

    def test_bump_online_roles_when_no_bootstrap(self):
        test_repo = repository.MetadataRepository.create_service()

        @contextmanager
        def mocked_lock(lock):
            yield lock

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock)
        )
        test_repo._settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: None)
        )

        result = test_repo.bump_online_roles()
        assert result is False
        assert test_repo._redis.lock.calls == [
            pretend.call("TUF_SNAPSHOT_TIMESTAMP")
        ]
        assert test_repo._settings.get_fresh.calls == [
            pretend.call("BOOTSTRAP")
        ]
