import pretend
import pytest

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
            settings=pretend.stub(
                KEYVAULT=pretend.stub(
                    put=pretend.call_recorder(lambda *a: True)
                )
            )
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

    def test_main_add_initial_metadata(self):
        fake_config = pretend.stub(
            repository=pretend.stub(
                add_initial_metadata=pretend.call_recorder(lambda *a: None)
            )
        )
        kaprien.get_config = pretend.call_recorder(lambda *a: fake_config)
        kaprien.store_online_keys = pretend.call_recorder(lambda *a: None)

        test_payload = {"settings": {"k": "v"}, "metadata": {"k": "v"}}
        test_worker_dynaconf = kaprien.Dynaconf()
        test_task_settings = kaprien.Dynaconf()

        result = kaprien.main(
            "add_initial_metadata",
            test_payload,
            test_worker_dynaconf,
            test_task_settings,
        )
        assert result is True
        assert fake_config.repository.add_initial_metadata.calls == [
            pretend.call(test_payload.get("metadata"))
        ]
        assert kaprien.get_config.calls == [
            pretend.call(test_worker_dynaconf, test_task_settings)
        ]
        assert kaprien.store_online_keys.calls == [
            pretend.call(test_payload.get("settings"), kaprien.get_config())
        ]

    def test_main_add_targets(self):
        fake_config = pretend.stub(
            repository=pretend.stub(
                add_targets=pretend.call_recorder(lambda *a: None)
            )
        )
        kaprien.get_config = pretend.call_recorder(lambda *a: fake_config)

        test_payload = {"targets": {"k": "v"}}
        test_worker_dynaconf = kaprien.Dynaconf()
        test_task_settings = kaprien.Dynaconf()

        result = kaprien.main(
            "add_targets",
            test_payload,
            test_worker_dynaconf,
            test_task_settings,
        )
        assert result is True
        assert fake_config.repository.add_targets.calls == [
            pretend.call(test_payload.get("targets"))
        ]
        assert kaprien.get_config.calls == [
            pretend.call(test_worker_dynaconf, test_task_settings)
        ]

    def test_main_invalid_action(self):
        kaprien.get_config = pretend.call_recorder(lambda *a: None)

        test_payload = {"targets": {"k": "v"}}
        test_worker_dynaconf = kaprien.Dynaconf()
        test_task_settings = kaprien.Dynaconf()

        action = "invalid_action"
        with pytest.raises(AttributeError) as err:
            kaprien.main(
                "invalid_action",
                test_payload,
                test_worker_dynaconf,
                test_task_settings,
            )
        assert f"Invalid action attribute '{action}'" in str(err)
        assert kaprien.get_config.calls == [
            pretend.call(test_worker_dynaconf, test_task_settings)
        ]
