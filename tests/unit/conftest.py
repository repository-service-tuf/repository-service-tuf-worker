# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
import datetime
import os
from datetime import timezone
from types import ModuleType

import pretend
import pytest

# tox sets these; bare `pytest` from a dev shell often does not — set before
# importing the worker (MetadataRepository.__init__ calls refresh_settings).
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_TEST_DATA = os.path.join(_REPO_ROOT, "data-test")
os.environ.setdefault("DATA_DIR", _TEST_DATA)
os.environ.setdefault("RSTUF_WORKER_ID", "test")
os.environ.setdefault("RSTUF_BROKER_SERVER", "fakeserver")
os.environ.setdefault("RSTUF_REDIS_SERVER", "redis://fake-redis")
os.environ.setdefault("RSTUF_DB_SERVER", "postgresql://fake-sql")
os.environ.setdefault("RSTUF_STORAGE_BACKEND", "LocalStorage")
os.environ.setdefault("RSTUF_LOCAL_STORAGE_BACKEND_PATH", os.path.join(_TEST_DATA, "s"))

from repository_service_tuf_worker.repository import MetadataRepository


@pytest.fixture()
def test_repo(monkeypatch: pytest.MonkeyPatch) -> MetadataRepository:
    return MetadataRepository.create_service()


@pytest.fixture()
def app(test_repo: MetadataRepository) -> ModuleType:
    # On each app test it's required that a new "repository" instance is used.
    import app

    app.repository = test_repo
    return app


@pytest.fixture()
def mocked_datetime(monkeypatch):
    fake_time = datetime.datetime(2019, 6, 16, 9, 5, 1, tzinfo=timezone.utc)
    fake_datetime = pretend.stub(
        now=pretend.call_recorder(lambda *а: fake_time)
    )
    monkeypatch.setattr(
        "repository_service_tuf_worker.repository.datetime", fake_datetime
    )

    return fake_datetime
