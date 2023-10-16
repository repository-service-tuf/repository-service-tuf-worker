# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
import pretend

import repository_service_tuf_worker


class TestSettingsSetup:
    def test_get_worker_settings(self):
        worker_settings = repository_service_tuf_worker.get_worker_settings()
        assert isinstance(
            worker_settings, repository_service_tuf_worker.Dynaconf
        )

    def test_get_repository_settings(self):
        repository_settings = (
            repository_service_tuf_worker.get_repository_settings()
        )
        assert isinstance(
            repository_settings, repository_service_tuf_worker.Dynaconf
        )


class TestParseIfSecret:
    def test_parse_if_secret(self):
        result = repository_service_tuf_worker.parse_if_secret("variable")
        assert result == "variable"

    def test_parse_if_secret_as_secret(self, monkeypatch):
        fake_file_obj = pretend.stub(
            __enter__=pretend.call_recorder(
                lambda *a: pretend.stub(read=lambda: "mysecret")
            ),
            read=pretend.call_recorder(lambda *a: "mysecret"),
            close=pretend.call_recorder(lambda *a: None),
            __exit__=pretend.call_recorder(lambda *a: None),
        )
        monkeypatch.setitem(
            repository_service_tuf_worker.__builtins__,
            "open",
            lambda *a: fake_file_obj,
        )

        result = repository_service_tuf_worker.parse_if_secret(
            "/run/secrets/VARIABLE"
        )
        assert result == "mysecret"

    def test_parse_raw_key(self, monkeypatch):
        fake_parse_if_secert = pretend.call_recorder(
            lambda *a: "key,password,rsa"
        )
        monkeypatch.setattr(
            "repository_service_tuf_worker.parse_if_secret",
            fake_parse_if_secert,
        )

        result = repository_service_tuf_worker.parse_raw_key("key,pass2,rsa")
        assert result == ["key", "password", "rsa"]
        assert fake_parse_if_secert.calls == [pretend.call("key,pass2,rsa")]
