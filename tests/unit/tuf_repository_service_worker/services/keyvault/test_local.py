# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT

import pretend
import pytest
from securesystemslib.signer import Key, SSlibSigner

from repository_service_tuf_worker.services.keyvault import local


class TestLocalStorageService:
    def test_basic_init(self):
        service = local.LocalKeyVault(
            "custom_online.key", "password", "rsassa-pss-sha256"
        )
        assert service._key_path == "custom_online.key"
        assert service._key_password == "password"
        assert service._key_type == "rsassa-pss-sha256"

    def test_basic_init_minimum_settings(self):
        service = local.LocalKeyVault()
        assert service._key_path == "online.key"
        assert service._key_password is None
        assert service._key_type == "ed25519"

    def test_configure(self):
        test_settings = pretend.stub(
            LOCAL_KEYVAULT_KEY_PATH="/path/online.key",
            LOCAL_KEYVAULT_KEY_TYPE="ed25519",
            LOCAL_KEYVAULT_KEY_PASSWORD="strongPass",
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
            LOCAL_KEYVAULT_KEY_PATH="/path/online.key",
            LOCAL_KEYVAULT_KEY_TYPE="ed25519",
            LOCAL_KEYVAULT_KEY_PASSWORD="strongPass",
        )
        local.import_privatekey_from_file = pretend.raiser(ValueError("error"))

        with pytest.raises(local.KeyVaultError) as err:
            local.LocalKeyVault.configure(test_settings)

        assert "Cannot read private key file" in str(err)

    def test_settings(self):
        service = local.LocalKeyVault("online.key", "password", "ed25519")
        service_settings = service.settings()

        assert service_settings == [
            local.ServiceSettings(
                name="LOCAL_KEYVAULT_KEY_PATH",
                argument="key_path",
                required=False,
                default="online.key",
            ),
            local.ServiceSettings(
                name="LOCAL_KEYVAULT_KEY_PASSWORD",
                argument="key_pass",
                required=False,
                default=None,
            ),
            local.ServiceSettings(
                name="LOCAL_KEYVAULT_KEY_TYPE",
                argument="key_type",
                required=False,
                default="ed25519",
            ),
        ]

    def test_get(self):
        service = local.LocalKeyVault("online.key", "key_password", "ed25519")
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
        service = local.LocalKeyVault("online.key", "key_password", "ed25519")
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
