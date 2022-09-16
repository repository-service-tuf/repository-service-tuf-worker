from contextlib import contextmanager

import pretend
import pytest

from app import worker_settings
from repo_worker import kaprien


class TestKaprien:
    def test_store_online_keys(self):
        fake_keys = {"key1": {"k", "v"}}
        test_roles_config = {
            "roles": {
                "root": {
                    "expiration": 365,
                    "threshold": 1,
                    "offline_keys": True,
                    "keys": fake_keys,
                }
            }
        }

        test_worker_config = pretend.stub(
            KEYVAULT=pretend.stub(put=pretend.call_recorder(lambda *a: True))
        )

        result = kaprien.store_online_keys(
            test_roles_config, test_worker_config
        )
        assert result is True

    def test_store_online_keys_no_roles(self):
        test_roles_config = {}
        test_worker_config = pretend.stub()

        result = kaprien.store_online_keys(
            test_roles_config, test_worker_config
        )
        assert result is False

    def test_main_add_initial_metadata_no_settings(self):
        fake_config = pretend.stub(
            repository=pretend.stub(
                add_initial_metadata=pretend.call_recorder(lambda *a: None)
            ),
            settings=worker_settings,
        )
        kaprien.runner = pretend.stub(
            update=pretend.call_recorder(lambda *a: None),
            get=fake_config,
        )

        test_payload = {"metadata": {"k": "v"}}

        with pytest.raises(ValueError) as err:
            kaprien.main(
                "add_initial_metadata",
                test_payload,
                worker_settings,
            )
        assert "No settings in the payload" in str(err)

    def test_main_add_initial_metadata(self):
        fake_config = pretend.stub(
            repository=pretend.stub(
                add_initial_metadata=pretend.call_recorder(lambda *a: None)
            ),
            settings=worker_settings,
        )
        kaprien.runner = pretend.stub(
            update=pretend.call_recorder(lambda *a: None),
            get=fake_config,
        )

        @contextmanager
        def mocked_lock(lock):
            yield lock

        mocked_redis_session = pretend.stub(
            lock=pretend.call_recorder(mocked_lock)
        )
        kaprien.redis = pretend.stub(
            StrictRedis=pretend.stub(
                from_url=pretend.call_recorder(lambda *a: mocked_redis_session)
            )
        )
        kaprien.store_online_keys = pretend.call_recorder(lambda *a: None)

        test_payload = {"settings": {"k": "v"}, "metadata": {"k": "v"}}

        result = kaprien.main(
            "add_initial_metadata",
            test_payload,
            worker_settings,
        )
        assert result is True
        assert fake_config.repository.add_initial_metadata.calls == [
            pretend.call(test_payload.get("metadata"))
        ]
        assert kaprien.runner.update.calls == [pretend.call(worker_settings)]

    def test_main_add_targets(self):
        fake_config = pretend.stub(
            repository=pretend.stub(
                add_targets=pretend.call_recorder(lambda *a: [("bin_a", "2")])
            ),
            settings=worker_settings,
        )
        kaprien.runner = pretend.stub(
            update=pretend.call_recorder(lambda *a: None),
            get=fake_config,
        )

        @contextmanager
        def mocked_lock(lock):
            yield lock

        mocked_redis_session = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
            exists=pretend.call_recorder(lambda key_name: False),
            set=pretend.call_recorder(lambda *a: None),
        )
        kaprien.redis = pretend.stub(
            StrictRedis=pretend.stub(
                from_url=pretend.call_recorder(lambda *a: mocked_redis_session)
            )
        )
        test_payload = {"targets": {"k": "v"}}
        test_task_settings = kaprien.Dynaconf(
            settings_files=["test_worker_settings.ini"]
        )
        test_task_settings.BOOTSTRAP = "done"

        result = kaprien.main(
            "add_targets",
            test_payload,
            worker_settings,
        )
        assert result is True
        assert fake_config.repository.add_targets.calls == [
            pretend.call(test_payload.get("targets"))
        ]
        assert fake_config.repository.add_targets.calls == [
            pretend.call({"k": "v"})
        ]
        assert mocked_redis_session.lock.calls == [
            pretend.call("TUF_BINS_HASHED"),
            pretend.call("TUF_TARGETS_META"),
        ]
        assert mocked_redis_session.exists.calls == [
            pretend.call("umpublished_metas")
        ]
        assert mocked_redis_session.set.calls == [
            pretend.call("umpublished_metas", "bin_a")
        ]

    def test_main_add_targets_existing_umpublished_metas(self):
        fake_config = pretend.stub(
            repository=pretend.stub(
                add_targets=pretend.call_recorder(lambda *a: [("bin_a", "2")])
            ),
            settings=worker_settings,
        )
        kaprien.runner = pretend.stub(
            update=pretend.call_recorder(lambda *a: None),
            get=fake_config,
        )

        @contextmanager
        def mocked_lock(lock):
            yield lock

        mocked_redis_session = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
            exists=pretend.call_recorder(lambda key_name: True),
            get=pretend.call_recorder(lambda *a: b"bin_b"),
            append=pretend.call_recorder(lambda *a: None),
        )
        kaprien.redis = pretend.stub(
            StrictRedis=pretend.stub(
                from_url=pretend.call_recorder(lambda *a: mocked_redis_session)
            )
        )
        test_payload = {"targets": {"k": "v"}}
        test_task_settings = kaprien.Dynaconf(
            settings_files=["test_worker_settings.ini"]
        )
        test_task_settings.BOOTSTRAP = "done"

        result = kaprien.main(
            "add_targets",
            test_payload,
            worker_settings,
        )
        assert result is True
        assert fake_config.repository.add_targets.calls == [
            pretend.call(test_payload.get("targets"))
        ]
        assert fake_config.repository.add_targets.calls == [
            pretend.call({"k": "v"})
        ]
        assert mocked_redis_session.lock.calls == [
            pretend.call("TUF_BINS_HASHED"),
            pretend.call("TUF_TARGETS_META"),
        ]
        assert mocked_redis_session.exists.calls == [
            pretend.call("umpublished_metas")
        ]
        assert mocked_redis_session.get.calls == [
            pretend.call("umpublished_metas")
        ]
        assert mocked_redis_session.append.calls == [
            pretend.call("umpublished_metas", ", bin_a")
        ]

    def test_main_add_targets_existing_umpublished_metas_and_delegate_role(
        self,
    ):
        fake_config = pretend.stub(
            repository=pretend.stub(
                add_targets=pretend.call_recorder(lambda *a: [("bin_b", "2")])
            ),
            settings=worker_settings,
        )
        kaprien.runner = pretend.stub(
            update=pretend.call_recorder(lambda *a: None),
            get=fake_config,
        )

        @contextmanager
        def mocked_lock(lock):
            yield lock

        mocked_redis_session = pretend.stub(
            lock=pretend.call_recorder(mocked_lock),
            exists=pretend.call_recorder(lambda key_name: True),
            get=pretend.call_recorder(lambda *a: b"bin_b"),
            append=pretend.call_recorder(lambda *a: None),
        )
        kaprien.redis = pretend.stub(
            StrictRedis=pretend.stub(
                from_url=pretend.call_recorder(lambda *a: mocked_redis_session)
            )
        )
        test_payload = {"targets": {"k": "v"}}
        test_task_settings = kaprien.Dynaconf(
            settings_files=["test_worker_settings.ini"]
        )
        test_task_settings.BOOTSTRAP = "done"

        result = kaprien.main(
            "add_targets",
            test_payload,
            worker_settings,
        )
        assert result is True
        assert fake_config.repository.add_targets.calls == [
            pretend.call(test_payload.get("targets"))
        ]
        assert fake_config.repository.add_targets.calls == [
            pretend.call({"k": "v"})
        ]
        assert mocked_redis_session.lock.calls == [
            pretend.call("TUF_BINS_HASHED"),
            pretend.call("TUF_TARGETS_META"),
        ]
        assert mocked_redis_session.exists.calls == [
            pretend.call("umpublished_metas")
        ]
        assert mocked_redis_session.get.calls == [
            pretend.call("umpublished_metas")
        ]
        assert mocked_redis_session.append.calls == []

    def test_main_invalid_action(self):
        test_payload = {"targets": {"k": "v"}}
        test_worker_dynaconf = kaprien.Dynaconf()

        action = "invalid_action"
        with pytest.raises(AttributeError) as err:
            kaprien.main(
                "invalid_action",
                test_payload,
                test_worker_dynaconf,
            )
        assert f"Invalid action attribute '{action}'" in str(err)
