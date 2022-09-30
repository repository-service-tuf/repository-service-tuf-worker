import datetime
from contextlib import contextmanager

import pretend
import pytest

from tuf_repository_service_worker import repository


class TestMetadataRepository:
    def test_basic_init(self):

        test_repo = repository.MetadataRepository()
        assert isinstance(test_repo, repository.MetadataRepository) is True

    def test_create_service(self):
        test_repo = repository.MetadataRepository.create_service()
        assert isinstance(test_repo, repository.MetadataRepository) is True

    def test_refresh_settings(self):
        test_repo = repository.MetadataRepository.create_service()
        test_repo.refresh_settings()

        assert (
            test_repo._worker_settings.to_dict()
            == repository.worker_settings.to_dict()
        )
        assert isinstance(test_repo._settings, repository.Dynaconf) is True

    def test__load(self):
        test_repo = repository.MetadataRepository.create_service()
        repository.Metadata = pretend.stub(
            from_file=pretend.call_recorder(lambda *a, **kw: "root_metadata")
        )

        test_result = test_repo._load("root")
        assert test_result == "root_metadata"
        assert repository.Metadata.from_file.calls == [
            pretend.call("root", None, test_repo._storage_backend)
        ]

    def test__sign(self):
        test_repo = repository.MetadataRepository.create_service()

        fake_role = pretend.stub(
            signatures=pretend.stub(clear=pretend.call_recorder(lambda: None)),
            sign=pretend.call_recorder(lambda *a, **kw: None),
        )
        test_repo._key_storage_backend = pretend.stub(
            get=pretend.call_recorder(lambda *a, **kw: ["key1", "key2"])
        )
        repository.SSlibSigner = pretend.call_recorder(lambda *a: "key_signer")

        test_result = test_repo._sign(fake_role, "root")

        assert test_result is None
        assert test_repo._key_storage_backend.get.calls == [
            pretend.call("root")
        ]
        assert fake_role.signatures.clear.calls == [pretend.call()]
        assert fake_role.sign.calls == [
            pretend.call("key_signer", append=True),
            pretend.call("key_signer", append=True),
        ]
        assert repository.SSlibSigner.calls == [
            pretend.call("key1"),
            pretend.call("key2"),
        ]

    def test__persist(self):
        test_repo = repository.MetadataRepository.create_service()

        fake_role = pretend.stub(
            signed=pretend.stub(version=2),
            to_file=pretend.call_recorder(lambda *a, **kw: None),
        )

        repository.JSONSerializer = pretend.call_recorder(lambda: None)
        test_repo._storage_backend = pretend.stub()

        test_result = test_repo._persist(fake_role, "snapshot")
        assert test_result is None
        assert fake_role.to_file.calls == [
            pretend.call(
                "2.snapshot.json",
                repository.JSONSerializer(),
                test_repo._storage_backend,
            )
        ]

    def test__persist_timestamp(self):
        test_repo = repository.MetadataRepository.create_service()

        fake_role = pretend.stub(
            signed=pretend.stub(version=2),
            to_file=pretend.call_recorder(lambda *a, **kw: None),
        )

        repository.JSONSerializer = pretend.call_recorder(lambda: None)
        test_repo._storage_backend = pretend.stub()

        test_result = test_repo._persist(fake_role, "timestamp")
        assert test_result is None
        assert fake_role.to_file.calls == [
            pretend.call(
                "timestamp.json",
                repository.JSONSerializer(),
                test_repo._storage_backend,
            )
        ]

    def test_bump_exipry(self, monkeypatch):
        test_repo = repository.MetadataRepository.create_service()
        test_repo._settings = pretend.stub(
            get_fresh=pretend.call_recorder(lambda *a: 1460)
        )
        fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1)
        fake_datetime = pretend.stub(
            now=pretend.call_recorder(lambda: fake_time)
        )
        monkeypatch.setattr(
            "tuf_repository_service_worker.repository.datetime", fake_datetime
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
            "tuf_repository_service_worker.repository.MetaFile", fake_metafile
        )

        mocked_timestamp = pretend.stub(signed=pretend.stub(snapshot_meta=2))
        test_repo._load = pretend.call_recorder(lambda *a: mocked_timestamp)
        test_repo._bump_version = pretend.call_recorder(lambda *a: None)
        test_repo._bump_expiry = pretend.call_recorder(lambda *a: None)
        test_repo._sign = pretend.call_recorder(lambda *a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)

        result = test_repo._update_timestamp(snapshot_version)

        assert result == mocked_timestamp
        assert mocked_timestamp.signed.snapshot_meta == snapshot_version
        assert test_repo._load.calls == [
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

        test_repo._load = pretend.call_recorder(lambda *a: mocked_snapshot)
        test_repo._bump_version = pretend.call_recorder(lambda *a: None)
        test_repo._bump_expiry = pretend.call_recorder(lambda *a: None)
        test_repo._sign = pretend.call_recorder(lambda *a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)

        result = test_repo._update_snapshot(test_target_meta)

        assert result is snapshot_version
        assert test_repo._load.calls == [
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

        fake_bin = pretend.stub(
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
        test_repo._load = pretend.call_recorder(lambda *a: fake_bin)
        result = test_repo._get_path_succinct_role("v0.0.1/test_path.tar.gz")

        assert result == "bin-e"
        assert (
            fake_bin.signed.delegations.succinct_roles.get_role_for_target.calls  # noqa
            == [pretend.call("v0.0.1/test_path.tar.gz")]
        )

    def test__add_to_unpublished_metas(self):
        test_repo = repository.MetadataRepository.create_service()

        @contextmanager
        def mocked_lock(lock):
            yield lock

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
            exists=pretend.call_recorder(lambda *a: True),
            get=pretend.call_recorder(lambda *a: b"bins-a, bins-b"),
            append=pretend.call_recorder(lambda *a: None),
        )

        result = test_repo._add_to_unpublished_metas(
            [("bin-e", 3), ("bin-2", 6)]
        )

        assert result is None

        assert test_repo._redis.exists.calls == [
            pretend.call("unpublished_metas")
        ]
        assert test_repo._redis.get.calls == [
            pretend.call("unpublished_metas")
        ]
        assert test_repo._redis.append.calls == [
            pretend.call("unpublished_metas", ", bin-e"),
            pretend.call("unpublished_metas", ", bin-2"),
        ]

    def test__add_to_unpublished_metas_empty(self):
        test_repo = repository.MetadataRepository.create_service()

        result = test_repo._add_to_unpublished_metas([])

        assert result is None

    def test__add_to_unpublished_metas_empty_unpublished_metas(self):
        test_repo = repository.MetadataRepository.create_service()

        @contextmanager
        def mocked_lock(lock):
            yield lock

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
            exists=pretend.call_recorder(lambda *a: False),
            set=pretend.call_recorder(lambda *a: None),
        )

        result = test_repo._add_to_unpublished_metas(
            [("bin-e", 3), ("bin-2", 6)]
        )

        assert result is None

        assert test_repo._redis.exists.calls == [
            pretend.call("unpublished_metas")
        ]
        assert test_repo._redis.set.calls == [
            pretend.call("unpublished_metas", "bin-e, bin-2")
        ]

    def test__publish_meta_state(self):
        test_repo = repository.MetadataRepository.create_service()

        fake_snapshot = pretend.stub(
            signed=pretend.stub(
                meta={
                    "bin-e.json": pretend.stub(version=1),
                    "bin-a.json": pretend.stub(version=5),
                }
            )
        )

        test_repo._load = pretend.call_recorder(lambda *a: fake_snapshot)

        fake_update_state = pretend.call_recorder(lambda *a, **kw: None)
        result = test_repo._publish_meta_state(
            [("bin-e", 1), ("bin-a", 5)], fake_update_state
        )
        assert result is None
        assert test_repo._load.calls == [
            pretend.call("snapshot"),
            pretend.call("snapshot"),
        ]
        assert fake_update_state.calls == [
            pretend.call(
                state="PUBLISHING",
                meta={"unpublished_roles": ["bin-a version 5"]},
            )
        ]

    def test_bootstrap(self):
        test_repo = repository.MetadataRepository.create_service()

        test_repo.store_online_keys = pretend.call_recorder(lambda *s: None)

        fake_metadata = pretend.stub(
            to_file=pretend.call_recorder(lambda *a: None)
        )
        repository.Metadata = pretend.stub(
            from_dict=pretend.call_recorder(lambda *a: fake_metadata)
        )
        repository.JSONSerializer = pretend.call_recorder(lambda: None)
        test_repo._storage_backend = pretend.stub()

        payload = {
            "settings": {"k": "v"},
            "metadata": {
                "1.root": {"md_k1": "md_v1"},
                "1.snapshot": {"md_k2": "md_v2"},
            },
        }

        result = test_repo.bootstrap(payload)
        assert result is True
        assert test_repo.store_online_keys.calls == [pretend.call({"k": "v"})]
        assert repository.Metadata.from_dict.calls == [
            pretend.call({"md_k1": "md_v1"}),
            pretend.call({"md_k2": "md_v2"}),
        ]
        assert repository.JSONSerializer.calls == [
            pretend.call(),
            pretend.call(),
        ]
        assert fake_metadata.to_file.calls == [
            pretend.call(
                "1.root.json",
                repository.JSONSerializer(),
                test_repo._storage_backend,
            ),
            pretend.call(
                "1.snapshot.json",
                repository.JSONSerializer(),
                test_repo._storage_backend,
            ),
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

        test_repo.store_online_keys = pretend.call_recorder(lambda *s: None)
        payload = {
            "settings": {"k": "v"},
        }

        with pytest.raises(ValueError) as err:
            test_repo.bootstrap(payload)

        assert "No metadata in the payload" in str(err)

    def test_add_targets(self):
        test_repo = repository.MetadataRepository.create_service()

        @contextmanager
        def mocked_lock(lock):
            yield lock

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
        )

        test_repo._get_path_succinct_role = pretend.call_recorder(
            lambda *a: "bin-e"
        )

        fake_bins = pretend.stub(signed=pretend.stub(targets={}, version=41))

        test_repo._load = pretend.call_recorder(lambda r: fake_bins)
        test_repo._bump_version = pretend.call_recorder(lambda *a: None)
        test_repo._bump_expiry = pretend.call_recorder(lambda *a: None)
        test_repo._sign = pretend.call_recorder(lambda *a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)
        test_repo._add_to_unpublished_metas = pretend.call_recorder(
            lambda *a: None
        )
        test_repo._publish_meta_state = pretend.call_recorder(lambda *a: None)

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
            ]
        }
        fake_ue = pretend.stub()
        result = test_repo.add_targets(payload, update_state=fake_ue)

        assert result == {
            "details": {
                "target_roles": ["bin-e"],
                "targets": ["file1.tar.gz"],
            },
            "message": "Task finished.",
        }
        assert test_repo._get_path_succinct_role.calls == [
            pretend.call("file1.tar.gz")
        ]
        assert test_repo._load.calls == [
            pretend.call("bin-e"),
        ]
        assert test_repo._bump_version.calls == [pretend.call(fake_bins)]
        assert test_repo._redis.lock.calls == [
            pretend.call("TUF_BINS_HASHED"),
        ]
        assert test_repo._bump_expiry.calls == [
            pretend.call(fake_bins, "bins")
        ]
        assert test_repo._sign.calls == [pretend.call(fake_bins, "bins")]
        assert test_repo._persist.calls == [pretend.call(fake_bins, "bin-e")]
        assert test_repo._add_to_unpublished_metas.calls == [
            pretend.call([("bin-e", 41)])
        ]
        assert test_repo._publish_meta_state.calls == [
            pretend.call([("bin-e", 41)], fake_ue)
        ]

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

    def test_remove_targets(self):
        test_repo = repository.MetadataRepository.create_service()

        @contextmanager
        def mocked_lock(lock):
            yield lock

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
        )

        test_repo._get_path_succinct_role = pretend.call_recorder(
            lambda *a: "bin-e"
        )

        fake_bins = pretend.stub(
            signed=pretend.stub(
                targets={"file1.tar.gz": "TargetFileObject"}, version=4
            )
        )

        test_repo._load = pretend.call_recorder(lambda r: fake_bins)
        test_repo._bump_version = pretend.call_recorder(lambda *a: None)
        test_repo._bump_expiry = pretend.call_recorder(lambda *a: None)
        test_repo._sign = pretend.call_recorder(lambda *a: None)
        test_repo._persist = pretend.call_recorder(lambda *a: None)
        test_repo._add_to_unpublished_metas = pretend.call_recorder(
            lambda *a: None
        )
        test_repo._publish_meta_state = pretend.call_recorder(lambda *a: None)
        payload = {
            "targets": ["file1.tar.gz", "file2.tar.gz", "release-v0.1.0.yaml"]
        }
        fake_ue = pretend.stub()
        result = test_repo.remove_targets(payload, update_state=fake_ue)

        assert result == {
            "message": "Task finished.",
            "details": {
                "deleted_targets": ["file1.tar.gz"],
                "not_found_targets": ["file2.tar.gz", "release-v0.1.0.yaml"],
            },
        }
        assert test_repo._get_path_succinct_role.calls == [
            pretend.call("file1.tar.gz"),
            pretend.call("file2.tar.gz"),
            pretend.call("release-v0.1.0.yaml"),
        ]
        assert test_repo._load.calls == [
            pretend.call("bin-e"),
        ]
        assert test_repo._bump_version.calls == [pretend.call(fake_bins)]
        assert test_repo._redis.lock.calls == [
            pretend.call("TUF_BINS_HASHED"),
        ]
        assert test_repo._bump_expiry.calls == [
            pretend.call(fake_bins, "bins")
        ]
        assert test_repo._sign.calls == [pretend.call(fake_bins, "bins")]
        assert test_repo._persist.calls == [pretend.call(fake_bins, "bin-e")]
        assert test_repo._add_to_unpublished_metas.calls == [
            pretend.call([("bin-e", 4)])
        ]
        assert test_repo._publish_meta_state.calls == [
            pretend.call([("bin-e", 4)], fake_ue)
        ]

    def test_remove_targets_all_not_found(self):
        test_repo = repository.MetadataRepository.create_service()

        @contextmanager
        def mocked_lock(lock):
            yield lock

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
        )

        test_repo._get_path_succinct_role = pretend.call_recorder(
            lambda *a: "bin-e"
        )

        fake_bins = pretend.stub(
            signed=pretend.stub(
                targets={"file1.tar.gz": "TargetFileObject"}, version=4
            )
        )

        test_repo._load = pretend.call_recorder(lambda r: fake_bins)

        payload = {
            "targets": ["file2.tar.gz", "file3.tar.gz", "release-v0.1.0.yaml"]
        }

        result = test_repo.remove_targets(payload, update_state=pretend.stub())

        assert result == {
            "message": "Task finished.",
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
        assert test_repo._load.calls == [
            pretend.call("bin-e"),
        ]
        assert test_repo._redis.lock.calls == [
            pretend.call("TUF_BINS_HASHED"),
        ]

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

    def test_publish_targets_meta(self):
        test_repo = repository.MetadataRepository.create_service()

        @contextmanager
        def mocked_lock(lock):
            yield lock

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
            get=pretend.call_recorder(lambda *a: b"bins-a, bins-b"),
            delete=pretend.call_recorder(lambda *a: None),
        )

        fake_snapshot = pretend.stub(signed=pretend.stub(meta={}))
        fake_bins = pretend.stub(signed=pretend.stub(targets={}, version=4))

        def mocked_load(role):
            if role == "snapshot":
                return fake_snapshot
            else:
                return fake_bins

        test_repo._load = pretend.call_recorder(lambda r: mocked_load(r))
        test_repo._update_snapshot = pretend.call_recorder(
            lambda *a: "fake_snapshot"
        )
        test_repo._update_timestamp = pretend.call_recorder(lambda *a: None)

        result = test_repo.publish_targets_meta()

        assert result is None
        assert test_repo._redis.lock.calls == [
            pretend.call("TUF_SNAPSHOT_TIMESTAMP")
        ]
        assert test_repo._redis.get.calls == [
            pretend.call("unpublished_metas")
        ]
        assert test_repo._redis.delete.calls == [
            pretend.call("unpublished_metas")
        ]
        assert test_repo._load.calls == [
            pretend.call("snapshot"),
            pretend.call("bins-a"),
            pretend.call("bins-b"),
        ]
        assert test_repo._update_snapshot.calls == [
            pretend.call([("bins-a", 4), ("bins-b", 4)])
        ]
        assert test_repo._update_timestamp.calls == [
            pretend.call("fake_snapshot")
        ]

    def test_publish_targets_meta_same_version(self):
        test_repo = repository.MetadataRepository.create_service()

        @contextmanager
        def mocked_lock(lock):
            yield lock

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
            get=pretend.call_recorder(lambda *a: b"bins-a, bins-b"),
        )

        fake_snapshot = pretend.stub(
            signed=pretend.stub(meta={"bins-a.json": 4, "bins-b.json": 4})
        )
        fake_bins = pretend.stub(signed=pretend.stub(targets={}, version=4))

        def mocked_load(role):
            if role == "snapshot":
                return fake_snapshot
            else:
                return fake_bins

        test_repo._load = pretend.call_recorder(lambda r: mocked_load(r))
        result = test_repo.publish_targets_meta()

        assert result is None
        assert test_repo._redis.lock.calls == [
            pretend.call("TUF_SNAPSHOT_TIMESTAMP")
        ]
        assert test_repo._redis.get.calls == [
            pretend.call("unpublished_metas")
        ]
        assert test_repo._load.calls == [
            pretend.call("snapshot"),
            pretend.call("bins-a"),
            pretend.call("bins-b"),
        ]

    def test_publish_targets_meta_empty_unpublished(self):
        test_repo = repository.MetadataRepository.create_service()

        @contextmanager
        def mocked_lock(lock):
            yield lock

        test_repo._redis = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
            get=pretend.call_recorder(lambda *a: None),
        )

        result = test_repo.publish_targets_meta()

        assert result is None
        assert test_repo._redis.lock.calls == [
            pretend.call("TUF_SNAPSHOT_TIMESTAMP")
        ]
        assert test_repo._redis.get.calls == [
            pretend.call("unpublished_metas")
        ]

    def test_bump_bins_roles(self):
        test_repo = repository.MetadataRepository.create_service()

        fake_bin = pretend.stub(
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

        def mocked_load(role):
            if role == "bin":
                return fake_bin
            else:
                return fake_bins

        test_repo._load = pretend.call_recorder(lambda r: mocked_load(r))
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
        assert test_repo._load.calls == [
            pretend.call("bin"),
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

        fake_bin = pretend.stub(
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

        def mocked_load(role):
            if role == "bin":
                return fake_bin
            else:
                return fake_bins

        test_repo._load = pretend.call_recorder(lambda r: mocked_load(r))

        result = test_repo.bump_bins_roles()
        assert result is True
        assert test_repo._load.calls == [
            pretend.call("bin"),
            pretend.call("bin-a"),
        ]

    def test_bump_bins_roles_StorageError(self):
        test_repo = repository.MetadataRepository.create_service()

        test_repo._load = pretend.raiser(
            repository.StorageError("Overwite it")
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
        test_repo._load = pretend.call_recorder(lambda *a: fake_snapshot)
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
        assert test_repo._update_snapshot.calls == [pretend.call([])]
        assert test_repo._update_timestamp.calls == [
            pretend.call("fake_snapshot")
        ]

    def test_bump_snapshot_unxpired(self):
        test_repo = repository.MetadataRepository.create_service()

        fake_snapshot = pretend.stub(
            signed=pretend.stub(
                meta={},
                expires=datetime.datetime(2080, 6, 16, 9, 5, 1),
                version=87,
            )
        )
        test_repo._load = pretend.call_recorder(lambda *a: fake_snapshot)

        result = test_repo.bump_snapshot()
        assert result is True

    def test_bump_snapshot_not_found(self):
        test_repo = repository.MetadataRepository.create_service()

        test_repo._load = pretend.raiser(repository.StorageError)

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

    def test_store_online_keys(self):
        test_repo = repository.MetadataRepository.create_service()

        test_repo._key_storage_backend = pretend.stub(
            put=pretend.call_recorder(lambda *a: None)
        )
        roles_config = {
            "roles": {
                "root": {"keys": {"k1": "v1"}},
                "snapshot": {"keys": {"k1": "v1"}},
                "timestamp": {"keys": {"k1": "v1"}},
            }
        }
        result = test_repo.store_online_keys(roles_config)
        assert result is True

    def test_store_online_keys_empty(self):
        test_repo = repository.MetadataRepository.create_service()

        test_repo._key_storage_backend = pretend.stub(
            put=pretend.call_recorder(lambda *a: None)
        )
        roles_config = {}
        result = test_repo.store_online_keys(roles_config)
        assert result is False
