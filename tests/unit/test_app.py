import tempfile

import pretend


class TestApp:
    def test_app(self, monkeypatch):
        monkeypatch.setenv("KAPRIEN_WORKER_ID", "test")
        monkeypatch.setenv(
            "KAPRIEN_LOCAL_STORAGE_BACKEND_PATH", tempfile.gettempdir()
        )
        monkeypatch.setenv("KAPRIEN_BROKER_SERVER", "fake-rabbitmq")
        monkeypatch.setenv(
            "KAPRIEN_LOCAL_KEYVAULT_PATH", tempfile.gettempdir()
        )
        import app

        assert app.Celery.__name__ == "Celery"

    def test_kaprien_repo_worker(self):
        import app

        app.kaprien = pretend.stub(
            main=pretend.call_recorder(lambda *a, **kw: True)
        )

        task_settings = app.Dynaconf()
        result = app.kaprien_repo_worker(
            "test_action", task_settings, {"k": "v"}
        )
        assert result is True
        assert app.kaprien.main.calls == [
            pretend.call(
                action="test_action",
                payload={"k": "v"},
                worker_settings=app.worker_settings,
                task_settings=task_settings,
            )
        ]

    def test_task_pre_run_notifier(self):
        import app

        app._publish_signals = pretend.call_recorder(lambda *a: None)
        app.task_pre_run_notifier(**{"task_id": "001"})

        assert app._publish_signals.calls == [
            pretend.call(app.status.PRE_RUN, "001")
        ]

    def test_task_unknown_notifier(self):
        import app

        app._publish_signals = pretend.call_recorder(lambda *a: None)
        app.task_unknown_notifier(**{"task_id": "001"})

        assert app._publish_signals.calls == [
            pretend.call(app.status.UNKNOWN, "001")
        ]

    def test_task_received_notifier(self):
        import app

        app._publish_signals = pretend.call_recorder(lambda *a: None)
        app.task_received_notifier(**{"task_id": "001"})

        assert app._publish_signals.calls == [
            pretend.call(app.status.RECEIVED, "001")
        ]
