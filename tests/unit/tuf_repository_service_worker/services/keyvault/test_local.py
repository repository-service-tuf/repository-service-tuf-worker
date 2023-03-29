# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import pretend
import pytest
from securesystemslib.signer import Key, SSlibSigner

from repository_service_tuf_worker.services.keyvault import local


class TestLocalStorageService:
    def test_basic_init(self):
        service = local.LocalKeyVault(
            "password", "custom_online.key", "rsassa-pss-sha256"
        )
        assert service._path == "custom_online.key"
        assert service._password == "password"
        assert service._type == "rsassa-pss-sha256"

    def test_basic_init_minimum_settings(self):
        service = local.LocalKeyVault("password")
        assert service._path == "online.key"
        assert service._password == "password"
        assert service._type == "ed25519"

    def test_configure(self):
        test_settings = pretend.stub(
            LOCAL_KEYVAULT_PATH="/path/online.key",
            LOCAL_KEYVAULT_TYPE="ed25519",
            LOCAL_KEYVAULT_PASSWORD="strongPass",
        )
        local.import_privatekey_from_file = pretend.call_recorder(
            lambda *a: {}
        )

        local.LocalKeyVault.configure(test_settings)
        assert local.import_privatekey_from_file.calls == [
            pretend.call("/path/online.key", "ed25519", "strongPass")
        ]

    def test_configure_ValueError(self):
        test_settings = pretend.stub(
            LOCAL_KEYVAULT_PATH="/path/online.key",
            LOCAL_KEYVAULT_TYPE="ed25519",
            LOCAL_KEYVAULT_PASSWORD="strongPass",
        )
        local.import_privatekey_from_file = pretend.raiser(ValueError("error"))

        with pytest.raises(local.KeyVaultError) as err:
            local.LocalKeyVault.configure(test_settings)

        assert "Cannot read private key file" in str(err)

    def test_settings(self):
        service = local.LocalKeyVault("password", "online.key", "ed25519")
        service_settings = service.settings()

        assert service_settings == [
            local.ServiceSettings(
                name="LOCAL_KEYVAULT_PATH",
                argument="key_path",
                required=False,
                default="online.key",
            ),
            local.ServiceSettings(
                name="LOCAL_KEYVAULT_PASSWORD",
                argument="key_pass",
                required=True,
            ),
            local.ServiceSettings(
                name="LOCAL_KEYVAULT_TYPE",
                argument="key_type",
                required=False,
                default="ed25519",
            ),
        ]

    def test_get(self):
        service = local.LocalKeyVault("key_password", "online.key", "ed25519")
        key_dict = {
            "keytype": "ed25519",
            "scheme": "ed25519",
            "keyval": {
                "public": "abc",
            },
        }
        key = Key.from_dict("keyid", key_dict)
        signer = SSlibSigner(key_dict)
        local.SSlibSigner = pretend.stub(
            from_priv_key_uri=pretend.call_recorder(lambda *a: signer)
        )
        result = service.get(key)
        assert result == signer
        private_key_uri = "file:online.key?encrypted=true"
        assert local.SSlibSigner.from_priv_key_uri.calls == [
            pretend.call(private_key_uri, key, service._secrets_handler)
        ]

    def test_get_securesystemslib_error(self):
        service = local.LocalKeyVault("key_password", "online.key", "ed25519")
        key_dict = {
            "keytype": "ed25519",
            "scheme": "ed25519",
            "keyval": {
                "public": "abc",
            },
        }
        key = Key.from_dict("keyid", key_dict)
        local.SSlibSigner = pretend.stub(
            from_priv_key_uri=pretend.raiser(ValueError("problem"))
        )
        with pytest.raises(local.KeyVaultError) as err:
            service.get(key)

        assert "Cannot load the online key" in str(err)
