import tempfile

import dynaconf
import pretend
import pytest

from repo_worker.tuf.repository import MetadataRepository


class TestApp:
    def test_app(self, monkeypatch):
        monkeypatch.setenv("KAPRIEN_WORKER_ID", "test")
        monkeypatch.setenv(
            "KAPRIEN_LOCAL_STORAGE_BACKEND_PATH", tempfile.gettempdir()
        )
        monkeypatch.setenv("KAPRIEN_RABBITMQ_SERVER", "fake-rabbitmq")
        monkeypatch.setenv(
            "KAPRIEN_LOCAL_KEYVAULT_PATH", tempfile.gettempdir()
        )
        import app

        assert app.Celery.__name__ == "Celery"

    def test___publish_backend(self, monkeypatch):
        import app

        mocked_redis_backend = pretend.stub(
            set=pretend.call_recorder(lambda *a: None)
        )
        monkeypatch.setattr("app.redis_backend", mocked_redis_backend)

        result = app._publish_backend(app.status.RUNNING, {"k": "v"})
        assert result is None

    def test__get_config(self, monkeypatch):
        monkeypatch.setenv("KAPRIEN_WORKER_ID", "test")
        monkeypatch.setenv(
            "KAPRIEN_LOCAL_STORAGE_BACKEND_PATH", tempfile.gettempdir()
        )
        monkeypatch.setenv("KAPRIEN_RABBITMQ_SERVER", "fake-rabbitmq")
        monkeypatch.setenv(
            "KAPRIEN_LOCAL_KEYVAULT_PATH", tempfile.gettempdir()
        )

        import app

        test_settings = dynaconf.Dynaconf()
        test_settings.STORAGE_BACKEND = "LocalStorage"
        test_settings.KEYVAULT_BACKEND = "LocalKeyVault"

        result = app._get_config(test_settings)
        assert type(result.repository) == MetadataRepository
        assert type(result.settings) == dynaconf.base.LazySettings

    def test__get_config_wrong_storage_backend(self, monkeypatch):
        monkeypatch.setenv("KAPRIEN_WORKER_ID", "test")

        import app

        test_settings = dynaconf.Dynaconf()
        test_settings.STORAGE_BACKEND = "InvalidStorage"
        test_settings.KEYVAULT_BACKEND = "LocalKeyVault"

        with pytest.raises(ValueError) as err:
            app._get_config(test_settings)

        assert "Invalid Storage Backend InvalidStorage" in str(err)

    def test__get_config_wrong_keyvault_backend(self, monkeypatch):
        monkeypatch.setenv("KAPRIEN_WORKER_ID", "test")
        monkeypatch.setenv("KAPRIEN_RABBITMQ_SERVER", "fake-rabbitmq")

        import app

        test_settings = dynaconf.Dynaconf()
        test_settings.STORAGE_BACKEND = "LocalStorage"
        test_settings.KEYVAULT_BACKEND = "InvalidKeyVault"

        with pytest.raises(ValueError) as err:
            app._get_config(test_settings)

        assert "Invalid Key Vault Backend InvalidKeyVault" in str(err)

    def test_kaprien_repo_worker(self, monkeypatch):
        monkeypatch.setenv("KAPRIEN_WORKER_ID", "test")
        monkeypatch.setenv(
            "KAPRIEN_LOCAL_STORAGE_BACKEND_PATH", tempfile.gettempdir()
        )
        monkeypatch.setenv("KAPRIEN_RABBITMQ_SERVER", "fake-rabbitmq")
        monkeypatch.setenv(
            "KAPRIEN_LOCAL_KEYVAULT_PATH", tempfile.gettempdir()
        )

        import app

        test_settings = dynaconf.Dynaconf()
        test_settings.STORAGE_BACKEND = "LocalStorage"
        test_settings.KEYVAULT_BACKEND = "LocalKeyVault"

        mocked_repo = pretend.stub(
            add_targets=pretend.call_recorder(lambda *a: None)
        )
        monkeypatch.setattr("app.MetadataRepository", lambda *a: mocked_repo)

        result = app.kaprien_repo_worker(
            "add_targets", test_settings, {"targets": {"key": "value"}}
        )

        assert result is None
        assert mocked_repo.add_targets.calls == [
            pretend.call({"key": "value"})
        ]

    def test_kaprien_repo_worker_invalid_action(self, monkeypatch):
        monkeypatch.setenv("KAPRIEN_WORKER_ID", "test")
        monkeypatch.setenv(
            "KAPRIEN_LOCAL_STORAGE_BACKEND_PATH", tempfile.gettempdir()
        )
        monkeypatch.setenv("KAPRIEN_RABBITMQ_SERVER", "fake-rabbitmq")
        monkeypatch.setenv(
            "KAPRIEN_LOCAL_KEYVAULT_PATH", tempfile.gettempdir()
        )

        import app

        test_settings = dynaconf.Dynaconf()
        test_settings.STORAGE_BACKEND = "LocalStorage"
        test_settings.KEYVAULT_BACKEND = "LocalKeyVault"

        mocked_repo = pretend.stub(
            add_targets=pretend.call_recorder(lambda *a: None)
        )
        monkeypatch.setattr("app.MetadataRepository", lambda *a: mocked_repo)

        with pytest.raises(AttributeError) as err:
            app.kaprien_repo_worker("invalid", test_settings, {"key": "value"})

        assert "module 'MetadataRepository' has no attribute 'invalid'" in str(
            err
        )
        assert mocked_repo.add_targets.calls == []

    def test_task_pre_run_notifier(self, monkeypatch):
        import app

        mocked__publish_backend = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr("app._publish_backend", mocked__publish_backend)

        app.task_pre_run_notifier(**{"task_id": "001"})

        assert mocked__publish_backend.calls == [
            pretend.call(app.status.PRE_RUN, "001")
        ]

    def test_task_unknown_notifier(self, monkeypatch):
        import app

        mocked__publish_backend = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr("app._publish_backend", mocked__publish_backend)

        app.task_unknown_notifier(**{"task_id": "001"})

        assert mocked__publish_backend.calls == [
            pretend.call(app.status.UNKNOWN, "001")
        ]

    def test_task_failure_notifier(self, monkeypatch):
        import app

        mocked__publish_backend = pretend.call_recorder(lambda *a: None)
        monkeypatch.setattr("app._publish_backend", mocked__publish_backend)

        app.task_failure_notifier(**{"task_id": "001"})

        assert mocked__publish_backend.calls == [
            pretend.call(app.status.FAILURE, "001")
        ]
