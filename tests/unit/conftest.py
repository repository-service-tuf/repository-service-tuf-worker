# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
import datetime
from datetime import timezone
from types import ModuleType

import pretend
import pytest

from repository_service_tuf_worker.repository import MetadataRepository


@pytest.fixture()
def test_repo(monkeypatch: pytest.MonkeyPatch) -> MetadataRepository:
    from repository_service_tuf_worker.services.keyvault import local

    fake_import_privatekey_from_file = pretend.call_recorder(lambda *a: None)
    monkeypatch.setattr(
        local,
        "import_privatekey_from_file",
        fake_import_privatekey_from_file,
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
