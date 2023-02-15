# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT

import pretend
import pytest

from repository_service_tuf_worker.services.keyvault import local


class TestLocalStorageService:
    def test_basic_init(self):
        service = local.LocalKeyVault(
            "/path", "custom_online.key", "password", "rsassa-pss-sha256"
        )
        assert service._path == "/path"
        assert service._online_key_name == "custom_online.key"
        assert service._online_key_password == "password"
        assert service._online_key_type == "rsassa-pss-sha256"

    def test_basic_init_minimum_settings(self):
        service = local.LocalKeyVault("/path")
        assert service._path == "/path"
        assert service._online_key_name == "online.key"
        assert service._online_key_password is None
        assert service._online_key_type == "ed25519"

    def test_configure(self):
        test_settings = pretend.stub(LOCAL_KEYVAULT_PATH="/path")
        local.os = pretend.stub(
            makedirs=pretend.call_recorder(lambda *a, **kw: None),
            path=pretend.stub(
                join=pretend.call_recorder(lambda *a: "/path/.secrets.yaml")
            ),
        )

        service = local.LocalKeyVault(
            "/path", "online.key", "password", "ed25519"
        )
        service.configure(test_settings)
        assert service._path == "/path"
        assert local.os.path.join.calls == [
            pretend.call(service._path, ".secrets.yaml")
        ]
        assert local.os.makedirs.calls == [
            pretend.call("/path", exist_ok=True)
        ]

    def test_settings(self):
        service = local.LocalKeyVault(
            "/path", "online.key", "password", "ed25519"
        )
        service_settings = service.settings()

        assert service_settings == [
            local.ServiceSettings(
                name="LOCAL_KEYVAULT_PATH",
                argument="path",
                required=True,
            ),
            local.ServiceSettings(
                name="LOCAL_KEYVAULT_ONLINE_KEY_NAME",
                argument="online_key_name",
                required=False,
            ),
            local.ServiceSettings(
                name="LOCAL_KEYVAULT_ONLINE_KEY_PASSWORD",
                argument="online_key_pass",
                required=False,
            ),
            local.ServiceSettings(
                name="LOCAL_KEYVAULT_ONLINE_KEY_TYPE",
                argument="online_key_type",
                required=False,
            ),
        ]

    def test_get(self):
        service = local.LocalKeyVault(
            "/path", "online.key", "password", "ed25519"
        )
        service.keyvault = pretend.stub(
            store={
                "timestamp": [
                    {"key": "key_values", "password": "key_password"}
                ]
            }
        )
        local.decrypt_key = pretend.call_recorder(
            lambda *a: "fake_keys_sslib_format"
        )

        result = service.get("timestamp")
        assert result == ["fake_keys_sslib_format"]
        assert local.decrypt_key.calls == [
            pretend.call("key_values", "key_password")
        ]

    def test_get_BoxKeyError_or_KeyError(self):
        service = local.LocalKeyVault(
            "/path", "online.key", "password", "ed25519"
        )
        service.keyvault = pretend.stub(
            store={
                "timestamp": [
                    {"key": "key_values", "password": "key_password"}
                ]
            }
        )
        local.decrypt_key = pretend.raiser(
            local.BoxKeyError("don't show this message")
        )
        with pytest.raises(local.KeyVaultError) as err:
            service.get("timestamp")

        assert "timestamp key(s) not found" in str(err)
