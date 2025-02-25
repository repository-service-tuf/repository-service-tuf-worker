# SPDX-FileCopyrightText: 2023-2025 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import tempfile
from contextlib import contextmanager

import pretend
import pytest


class TestApp:
    def test_app(self, app, monkeypatch):
        monkeypatch.setenv("RSTUF_WORKER_ID", "test")
        monkeypatch.setenv(
            "RSTUF_LOCAL_STORAGE_BACKEND_PATH", tempfile.gettempdir()
        )
        monkeypatch.setenv("RSTUF_BROKER_SERVER", "fake-rabbitmq")

        assert app.Celery.__name__ == "Celery"

    def test_repository_service_tuf_worker(self, app):
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

    def test_repository_service_tuf_worker_no_payload(self, app):
        app.repository = pretend.stub(
            refresh_settings=pretend.call_recorder(lambda *a: None),
            test_action=pretend.call_recorder(lambda *a, **kw: True),
        )

        result = app.repository_service_tuf_worker("test_action")

        assert result is True
        assert app.repository.test_action.calls == [
            pretend.call(),
        ]

    def test__publish_signals(self, app):
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

    def test_task_pre_run_notifier(self, app):
        app._publish_signals = pretend.call_recorder(lambda *a: None)
        app.task_pre_run_notifier(**{"task_id": "001"})

        assert app._publish_signals.calls == [
            pretend.call(app.status.PRE_RUN, "001")
        ]

    def test_task_unknown_notifier(self, app):
        app._publish_signals = pretend.call_recorder(lambda *a: None)
        app.task_unknown_notifier(**{"task_id": "001"})

        assert app._publish_signals.calls == [
            pretend.call(app.status.UNKNOWN, "001")
        ]

    def test_task_received_notifier(self, app):
        app._publish_signals = pretend.call_recorder(lambda *a: None)
        app.task_received_notifier(**{"task_id": "001"})

        assert app._publish_signals.calls == [
            pretend.call(app.status.RECEIVED, "001")
        ]

    @pytest.mark.parametrize(
        "expired, bor_lock, booststrap_state, mock_delegated_rolenames,"
        "chunk_size_cfg, expected_log_msg",
        [
            # Case 1: Cannot acquire lock
            (
                True,
                False,
                None,
                [],
                None,
                [
                    "Skipping bump_online_roles, another task is already "
                    "running."
                ],
            ),
            # Case 2: No bootstrap finished
            (
                True,
                True,
                "signing",
                [],
                None,
                ["Skipping bump_online_roles, bootstrap not finished."],
            ),
            # Case 3: No delegated roles
            (
                True,
                True,
                "finished",
                [],
                None,
                ["Total roles to bump: 0"],
            ),
            # Case 4: With delegated roles, but only one role
            (
                True,
                True,
                "finished",
                ["a"],
                None,
                ["Total roles to bump: 1"],
            ),
            # Case 5: With delegated roles, but only one role and chunk size
            # is set to the same number of roles
            (
                True,
                True,
                "finished",
                ["a"],
                1,
                ["Total roles to bump: 1"],
            ),
            # Case 6: With delegated roles and chunk size is set higher than
            # the number of roles
            (
                True,
                True,
                "finished",
                ["a", "b", "c", "d"],
                10,
                ["Total roles to bump: 4", "Tasks: 2 | Chunk size: 2"],
            ),
            # Case 7: With delegated roles and chunk size is set lower than
            # the number of roles
            (
                True,
                True,
                "finished",
                ["a", "b", "c", "d", "e"],
                2,
                ["Total roles to bump: 5", "Tasks: 3 | Chunk size: 2"],
            ),
            # Case 8: With delegated roles as 1 and chunk size is set 1000
            (
                True,
                True,
                "finished",
                ["a"],
                1000,
                ["Total roles to bump: 1"],
            ),
        ],
    )
    def test_bump_online_roles(
        self,
        monkeypatch,
        app,
        caplog,
        expired,
        bor_lock,
        booststrap_state,
        mock_delegated_rolenames,
        chunk_size_cfg,
        expected_log_msg,
    ):
        caplog.set_level(app.logging.INFO)

        @contextmanager
        def mocked_lock(lock, timeout):
            yield lock, timeout

        start_time = 1740472169.0
        app.time = pretend.stub(
            time=pretend.call_recorder(lambda *a: start_time),
        )
        app.repository = pretend.stub(
            _timeout=60,
            _redis=pretend.stub(
                set=pretend.call_recorder(lambda *a, **kw: bor_lock),
                lock=pretend.call_recorder(mocked_lock),
            ),
            _settings=pretend.stub(
                get_fresh=pretend.call_recorder(
                    lambda *a: chunk_size_cfg or 500
                )
            ),
            bootstrap_state=booststrap_state,
            get_delegated_rolenames=pretend.call_recorder(
                lambda *a, **kw: mock_delegated_rolenames
            ),
            update_targets_delegated_role=pretend.call_recorder(
                lambda *a, **kw: {
                    r: {"v": 1, "x": 1} for r in mock_delegated_rolenames
                }
            ),
        )

        monkeypatch.setattr(
            app,
            "_update_snapshot_timestamp",
            pretend.call_recorder(lambda *a: None),
        )
        app._update_snapshot_timestamp.s = pretend.call_recorder(
            lambda *a: None
        )
        monkeypatch.setattr(
            app,
            "_end_bor_chain_callback",
            pretend.call_recorder(lambda *a: None),
        )
        app._end_bor_chain_callback.s = pretend.call_recorder(lambda *a: None)
        app.chain = pretend.call_recorder(
            lambda *a: pretend.call_recorder(lambda **kw: "fake_chain")
        )

        result = app.bump_online_roles(expired=expired)

        assert result == mock_delegated_rolenames
        assert expected_log_msg == [rec.message for rec in caplog.records]

        assert app.repository._redis.set.calls == [
            pretend.call(app.BOR_LOCK, "locked", ex=app.BOR_TTL, nx=True)
        ]

        if bor_lock is False or booststrap_state != "finished":
            assert app.repository.get_delegated_rolenames.calls == []
        else:
            assert app.repository.get_delegated_rolenames.calls == [
                pretend.call(expired=expired)
            ]

        if len(mock_delegated_rolenames) == 1:
            assert app.repository._settings.get_fresh.calls == [
                pretend.call("BUMP_ONLINE_ROLES_CHUNK_SIZE", 500)
            ]
            assert app.repository.update_targets_delegated_role.calls == [
                pretend.call(mock_delegated_rolenames[0])
            ]
            assert app._update_snapshot_timestamp.calls == [
                pretend.call(
                    [[{r: {"v": 1, "x": 1} for r in mock_delegated_rolenames}]]
                )
            ]
            assert app._end_bor_chain_callback.calls == [
                pretend.call(None, start_time)
            ]

        if len(mock_delegated_rolenames) > 1:
            assert app.repository._settings.get_fresh.calls == [
                pretend.call("BUMP_ONLINE_ROLES_CHUNK_SIZE", 500)
            ]
            assert app._update_snapshot_timestamp.s.calls == [
                pretend.call(
                    app._update_online_role.chunks(
                        zip(mock_delegated_rolenames),
                        int(expected_log_msg[-1].split(":")[-1].strip()),
                    ).group()
                )
            ]
            assert app._end_bor_chain_callback.s.calls == [
                pretend.call(start_time)
            ]
            assert app.chain.calls == [
                pretend.call(
                    app._update_online_role.chunks(
                        zip(mock_delegated_rolenames),
                        int(expected_log_msg[-1].split(":")[-1].strip()),
                    ).group(),
                    None,
                    None,
                )
            ]

    def test_bump_online_roles_lock_exception(self, app, caplog):
        caplog.set_level(app.logging.ERROR)

        app.time = pretend.stub(
            time=pretend.call_recorder(lambda: 1740472169.0)
        )
        app.repository = pretend.stub(
            _timeout=60,
            _redis=pretend.stub(
                set=pretend.call_recorder(lambda *a, **kw: True),
                lock=pretend.raiser(
                    app.redis.exceptions.LockNotOwnedError("error lock")
                ),
            ),
            bootstrap_state="finished",
        )

        with pytest.raises(app.redis.exceptions.LockError):
            app.bump_online_roles(expired=True)

        assert [
            "The task to bump all online roles exceeded the timeout of 60 "
            "seconds."
        ] == [rec.message for rec in caplog.records]

    def test__update_online_role(self, app):
        app.repository = pretend.stub(
            update_targets_delegated_role=pretend.call_recorder(
                lambda *a, **kw: None
            )
        )

        result = app._update_online_role("a")

        assert result is None
        assert app.repository.update_targets_delegated_role.calls == [
            pretend.call("a")
        ]

    def test__end_bor_chain_callback(self, app, caplog):
        caplog.set_level(app.logging.INFO)
        app.repository._redis = pretend.stub(
            delete=pretend.call_recorder(lambda *a, **kw: None)
        )

        app.time = pretend.stub(
            time=pretend.call_recorder(lambda: 1740472171.0)
        )

        result = app._end_bor_chain_callback({"some": "result"}, 1740472169.0)

        assert [
            "Total execution time for bump_online_roles: 2.00 seconds",
            "Bump online roles lock removed",
        ] == [rec.message for rec in caplog.records]
        assert result == {
            "result": {"some": "result"},
            "execution_time_seconds": 2.00,
        }
        assert app.repository._redis.delete.calls == [
            pretend.call(app.BOR_LOCK)
        ]

    @pytest.mark.parametrize(
        "args, expected_result, expected_logs",
        [
            (
                [
                    [
                        {
                            "a": {
                                "version": 1,
                                "expire": "fake data",
                                "target_files": [],
                            }
                        }
                    ]
                ],
                None,
                [
                    "Time parsing _update_snapshot_timestamp: 2.0 seconds",
                    "Time updating _update_snapshot_timestamp: 5.0 seconds",
                    "Updated snapshot/timestamp with 1 role(s)",
                ],
            ),
            (
                [
                    [
                        {
                            "a": {
                                "version": 1,
                                "expire": "fake data",
                                "target_files": [],
                            }
                        },
                        {
                            "b": {
                                "version": 5,
                                "expire": "fake data",
                                "target_files": [],
                            }
                        },
                        {
                            "targets": {
                                "version": 3,
                                "expire": "fake data",
                                "target_files": [],
                            }
                        },
                    ]
                ],
                None,
                [
                    "Time parsing _update_snapshot_timestamp: 2.0 seconds",
                    "Time updating _update_snapshot_timestamp: 5.0 seconds",
                    "Updated snapshot/timestamp with 3 role(s)",
                ],
            ),
        ],
    )
    def test__update_snapshot_timestamp(
        self, app, caplog, args, expected_result, expected_logs
    ):
        caplog.set_level(app.logging.INFO)

        mocked_time = iter((1740472169.0, 1740472171.0, 1740472174.0))
        app.time = pretend.stub(
            time=pretend.call_recorder(lambda: next(mocked_time))
        )
        app.repository = pretend.stub(
            _update_timestamp=pretend.call_recorder(lambda *a: None),
            update_snapshot=pretend.call_recorder(
                lambda *a: pretend.stub(signed=pretend.stub(version=5))
            ),
        )

        result = app._update_snapshot_timestamp(args)
        assert result is expected_result
        assert expected_logs == [rec.message for rec in caplog.records]
        assert app.repository._update_timestamp.calls == [pretend.call(5)]
