# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT

import pretend
import pytest
from securesystemslib.signer import SSlibSigner

from repository_service_tuf_worker.services.keyvault import local


class TestLocalStorageService:
    def test_basic_init(self):
        service = local.LocalKeyVault(
            "/path", "custom_online.key", "password", "rsassa-pss-sha256"
        )
        assert service._path == "/path"
        assert service._key_name == "custom_online.key"
        assert service._key_password == "password"
        assert service._key_type == "rsassa-pss-sha256"

    def test_basic_init_minimum_settings(self):
        service = local.LocalKeyVault("/path")
        assert service._path == "/path"
        assert service._key_name == "online.key"
        assert service._key_password is None
        assert service._key_type == "ed25519"

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
                name="LOCAL_KEYVAULT_KEY_NAME",
                argument="key_name",
                required=False,
            ),
            local.ServiceSettings(
                name="LOCAL_KEYVAULT_KEY_PASSWORD",
                argument="key_pass",
                required=False,
            ),
            local.ServiceSettings(
                name="LOCAL_KEYVAULT_KEY_TYPE",
                argument="key_type",
                required=False,
            ),
        ]

    def test_get(self):
        service = local.LocalKeyVault(
            "/path", "online.key", "key_password", "ed25519"
        )
        local.import_privatekey_from_file = pretend.call_recorder(
            lambda *a: {}
        )
        result = service.get()
        assert isinstance(result, SSlibSigner)

        assert local.import_privatekey_from_file.calls == [
            pretend.call("online.key", "ed25519", "key_password")
        ]

    def test_get_securesystemslib_error(self):
        service = local.LocalKeyVault(
            "/path", "online.key", "key_password", "ed25519"
        )
        local.import_privatekey_from_file = pretend.raiser(
            local.CryptoError("don't show this message")
        )
        with pytest.raises(local.KeyVaultError) as err:
            service.get()

        assert "Cannot load the online key" in str(err)
