# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT

import tempfile

import pretend


class TestApp:
    def test_app(self, monkeypatch):
        monkeypatch.setenv("RSTUF_WORKER_ID", "test")
        monkeypatch.setenv(
            "RSTUF_LOCAL_STORAGE_BACKEND_PATH", tempfile.gettempdir()
        )
        monkeypatch.setenv("RSTUF_BROKER_SERVER", "fake-rabbitmq")
        monkeypatch.setenv("RSTUF_LOCAL_KEYVAULT_PATH", tempfile.gettempdir())
        import app

        assert app.Celery.__name__ == "Celery"

    def test_repository_service_tuf_worker(self):
        import app

        app.repository = pretend.stub(
            refresh_settings=pretend.call_recorder(lambda *a: None),
            test_action=pretend.call_recorder(lambda *a, **kw: True),
        )

        result = app.repository_service_tuf_worker(
            "test_action",
            payload={"k": "v"},
        )
        assert result is True
        assert app.repository.test_action.calls == [
            pretend.call(
                {"k": "v", "task_id": None},
                update_state=app.repository_service_tuf_worker.update_state,
            ),
        ]

    def test_repository_service_tuf_worker_no_payload(self):
        import app

        app.repository = pretend.stub(
            refresh_settings=pretend.call_recorder(lambda *a: None),
            test_action=pretend.call_recorder(lambda *a, **kw: True),
        )

        result = app.repository_service_tuf_worker(
            "test_action",
        )
        assert result is True
        assert app.repository.test_action.calls == [
            pretend.call(),
        ]

    def test__publish_signals(self):
        import app

        app.redis_backend = pretend.stub(
            set=pretend.call_recorder(lambda *a: None)
        )

        result = app._publish_signals(
            app.status.RECEIVED, "01234567890abcdef", "done"
        )

        assert result is None
        assert app.redis_backend.set.calls == [
            pretend.call(
                "celery-task-meta-01234567890abcdef",
                app.json.dumps(
                    {
                        "status": "RECEIVED",
                        "task_id": "01234567890abcdef",
                        "result": "done",
                    }
                ),
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
