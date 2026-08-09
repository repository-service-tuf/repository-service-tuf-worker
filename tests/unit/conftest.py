# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
import datetime
from datetime import timezone
from types import ModuleType

import pretend
import pytest

from repository_service_tuf_worker import repository
from repository_service_tuf_worker.repository import MetadataRepository


@pytest.fixture()
def test_repo(monkeypatch: pytest.MonkeyPatch) -> MetadataRepository:
    fake_engine = pretend.stub()
    fake_sql = pretend.stub(get_bind=lambda: fake_engine)
    monkeypatch.setattr(
        repository, "rstuf_db", pretend.call_recorder(lambda *a: fake_sql)
    )
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
