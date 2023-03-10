# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

from repository_service_tuf_worker import (
    Dynaconf,
    get_repository_settings,
    get_worker_settings,
)


class TestSettingsSetup:
    def test_get_worker_settings(self):
        worker_settings = get_worker_settings()
        assert isinstance(worker_settings, Dynaconf)

    def test_get_repository_settings(self):
        repository_settings = get_repository_settings()
        assert isinstance(repository_settings, Dynaconf)
