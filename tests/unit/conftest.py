# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from types import ModuleType

import pretend
import pytest

from repository_service_tuf_worker.repository import MetadataRepository


@pytest.fixture()
def test_repo(monkeypatch: pytest.MonkeyPatch) -> MetadataRepository:
    fake_configure = pretend.call_recorder(lambda *a: None)
    monkeypatch.setattr(
        "repository_service_tuf_worker.services.keyvault.local.LocalKeyVault.configure",  # noqa
        fake_configure,
    )
    return MetadataRepository.create_service()


@pytest.fixture()
def app(test_repo: MetadataRepository) -> ModuleType:
    # On each app test it's required that a new "repository" instance is used.
    import app

    app.repository = test_repo
    return app
