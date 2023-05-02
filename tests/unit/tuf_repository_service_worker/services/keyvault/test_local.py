# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
from unittest.mock import MagicMock

import pretend
import pytest

from repository_service_tuf_worker.services.keyvault import local


class TestLocalStorageService:
    def test_basic_init(self):
        service = local.LocalKeyVault(
            "/test/key_vault", "custom_online.key,rsassa-pss-sha256"
        )

        assert service._path == "/test/key_vault"
        assert service._keys == "custom_online.key,rsassa-pss-sha256"

    def test_basic_init_with_secrets(self):
        service = local.LocalKeyVault(
            "/test/key_vault",
            "/run/secrets/ONLINE_KEY_1:/run/secrets/ONLINE_KEY_2",
        )

        assert service._path == "/test/key_vault"
        assert (
            service._keys
            == "/run/secrets/ONLINE_KEY_1:/run/secrets/ONLINE_KEY_2"
        )

    def test__raw_key_parser(self):
        service = local.LocalKeyVault(
            "/test/key_vault", "key1.key,pass1:key2.key,pass2,rsa"
        )
        parsed_keys = service._raw_key_parser(service._keys)

        assert parsed_keys == [
            local.LocalKey(
                filename="key1.key", password="pass1", type="ed25519"
            ),
            local.LocalKey(filename="key2.key", password="pass2", type="rsa"),
        ]

    def test__raw_key_parser_with_secrets(self, monkeypatch):
        service = local.LocalKeyVault("/test/key_vault", "/run/secrets/KEY1")

        fake_data = pretend.stub(
            read=pretend.call_recorder(lambda: "key1.key,pass1\n")
        )
        fake_file_obj = pretend.stub(
            __enter__=pretend.call_recorder(lambda: fake_data),
            __exit__=pretend.call_recorder(lambda *a: None),
            close=pretend.call_recorder(lambda: None),
        )
        monkeypatch.setitem(
            local.__builtins__, "open", lambda *a: fake_file_obj
        )

        parsed_keys = service._raw_key_parser(service._keys)

        assert parsed_keys == [
            local.LocalKey(
                filename="key1.key", password="pass1", type="ed25519"
            )
        ]

    def test__raw_key_parser_with_one_invalid_configuration(self, caplog):
        service = local.LocalKeyVault(
            "/test/key_vault", "key1.key:key2.key,pass2,rsa"
        )
        caplog.set_level(local.logging.ERROR)
        parsed_keys = service._raw_key_parser(service._keys)

        assert parsed_keys == [
            local.LocalKey(filename="key2.key", password="pass2", type="rsa")
        ]
        assert "Key 0 is invalid" in caplog.record_tuples[0]

    def test__raw_key_parser_with_invalid_configuration(self):
        service = local.LocalKeyVault("/test/key_vault", "key1.key:pass2")

        with pytest.raises(local.KeyVaultError) as err:
            service._raw_key_parser(service._keys)

        assert (
            "No valid keys in configuration 'RSTUF_LOCAL_KEYVAULT_KEYS'"
            in str(err)
        )

    def test_configure(self):
        test_settings = pretend.stub(
            LOCAL_KEYVAULT_PATH="/path/key_vault/",
            LOCAL_KEYVAULT_KEYS="key1.key,pass1:key2.key,pass2,rsa",
        )
        local.import_privatekey_from_file = pretend.call_recorder(
            lambda *a: {}
        )

        local.LocalKeyVault.configure(test_settings)
        assert local.import_privatekey_from_file.calls == [
            pretend.call("/path/key_vault/key1.key", "ed25519", "pass1"),
            pretend.call("/path/key_vault/key2.key", "rsa", "pass2"),
        ]

    def test_configure_no_valid_keys(self):
        test_settings = pretend.stub(
            LOCAL_KEYVAULT_PATH="/path/key_vault/",
            LOCAL_KEYVAULT_KEYS="key1.key:key2.key",
        )

        local.LocalKeyVault._raw_key_parser = pretend.call_recorder(
            lambda *a: []
        )
        with pytest.raises(local.KeyVaultError) as err:
            local.LocalKeyVault.configure(test_settings)

        assert "No valid keys found in the LocalKeyVault" in str(err)
        assert local.LocalKeyVault._raw_key_parser.calls == [
            pretend.call(test_settings.LOCAL_KEYVAULT_KEYS)
        ]

    def test_configure_sslib_fail_one_key(self, caplog):
        test_settings = pretend.stub(
            LOCAL_KEYVAULT_PATH="/path/key_vault/",
            LOCAL_KEYVAULT_KEYS="key1,pass1:key2,pass2,rsa",
        )
        caplog.set_level(local.logging.WARNING)
        local.LocalKeyVault._raw_key_parser = pretend.call_recorder(
            lambda *a: [
                local.LocalKey(filename="key1", password="pass1"),
                local.LocalKey(filename="key2", password="pass2", type="rsa"),
            ]
        )
        mocked_import_pk_from_file = MagicMock()
        mocked_import_pk_from_file.side_effect = [
            local.FormatError("Invalid format"),
            None,
        ]
        local.import_privatekey_from_file = mocked_import_pk_from_file

        local.LocalKeyVault.configure(test_settings)

        assert caplog.record_tuples == [
            ("root", 40, "Invalid format"),
            ("root", 30, "Failed to load key1 LocalKeyVault key"),
        ]
        assert local.LocalKeyVault._raw_key_parser.calls == [
            pretend.call(test_settings.LOCAL_KEYVAULT_KEYS)
        ]

    def test_configure_sslib_fail_all_keys(self, caplog):
        test_settings = pretend.stub(
            LOCAL_KEYVAULT_PATH="/path/key_vault/",
            LOCAL_KEYVAULT_KEYS="key1,pass1:key2,rsa,pass2",
        )
        caplog.set_level(local.logging.WARNING)
        local.LocalKeyVault._raw_key_parser = pretend.call_recorder(
            lambda *a: [
                local.LocalKey(filename="key1", password="pass1"),
                local.LocalKey(filename="key2", password="pass2", type="rsa"),
            ]
        )
        local.import_privatekey_from_file = pretend.raiser(
            local.FormatError("Invalid format")
        )

        with pytest.raises(local.KeyVaultError) as err:
            local.LocalKeyVault.configure(test_settings)

        assert "No valid keys found in the LocalKeyVault" in str(err)

        assert caplog.record_tuples == [
            ("root", 40, "Invalid format"),
            ("root", 30, "Failed to load key1 LocalKeyVault key"),
            ("root", 40, "Invalid format"),
            ("root", 30, "Failed to load key2 LocalKeyVault key"),
            ("root", 40, "No valid keys found in the LocalKeyVault"),
        ]
        assert local.LocalKeyVault._raw_key_parser.calls == [
            pretend.call(test_settings.LOCAL_KEYVAULT_KEYS)
        ]

    def test_settings(self):
        service = local.LocalKeyVault(
            "/test/key_vault", "key1.key,pass1:key2.key,rsa,pass2"
        )
        service_settings = service.settings()

        assert service_settings == [
            local.ServiceSettings(
                name="LOCAL_KEYVAULT_PATH",
                argument="path",
                required=True,
            ),
            local.ServiceSettings(
                name="LOCAL_KEYVAULT_KEYS",
                argument="keys",
                required=True,
            ),
        ]

    def test_get(self):
        service = local.LocalKeyVault(
            "/test/key_vault", "key1.key,pass1:key2.key,pass2,rsa"
        )
        fake_key = pretend.stub(
            keyid="keyid", to_dict=pretend.call_recorder(lambda: {"k": "v"})
        )
        local.SSlibKey.from_dict = pretend.call_recorder(
            lambda *a: "fake_public_key"
        )
        local.SSlibSigner.from_priv_key_uri = pretend.call_recorder(
            lambda *a: "fake_signer"
        )
        service._secrets_handler = pretend.call_recorder(lambda pwd: pwd)
        result = service.get(fake_key)

        assert result == "fake_signer"
        assert local.SSlibSigner.from_priv_key_uri.calls == [
            pretend.call(
                "file:/test/key_vault/key1?encrypted=true",
                "fake_public_key",
                "pass1",
            )
        ]
        assert local.SSlibKey.from_dict.calls == [
            pretend.call("keyid", {"k": "v"})
        ]
        assert service._secrets_handler.calls == [pretend.call("pass1")]

    def test_get_fail_first_key(self, caplog):
        caplog.set_level(local.logging.ERROR)
        service = local.LocalKeyVault(
            "/test/key_vault", "key1.key,pass1:key2.key,pass2,rsa"
        )
        fake_key = pretend.stub(
            keyid="keyid", to_dict=pretend.call_recorder(lambda: {"k": "v"})
        )
        mocked_sslibkey_from_dict = MagicMock()
        mocked_sslibkey_from_dict.side_effect = [
            ValueError("Failed load online key"),
            "fake_public_key",
        ]
        local.SSlibKey.from_dict = mocked_sslibkey_from_dict
        local.SSlibSigner.from_priv_key_uri = pretend.call_recorder(
            lambda *a: "fake_signer"
        )
        service._secrets_handler = pretend.call_recorder(lambda pwd: pwd)

        result = service.get(fake_key)

        assert result == "fake_signer"
        assert local.SSlibSigner.from_priv_key_uri.calls == [
            pretend.call(
                "file:/test/key_vault/key2?encrypted=true",
                "fake_public_key",
                "pass2",
            )
        ]
        assert service._secrets_handler.calls == [pretend.call("pass2")]
        assert caplog.record_tuples == [
            ("root", 40, "Cannot load the online key key1")
        ]

    def test_get_fail_all_configured_keys(self, caplog):
        caplog.set_level(local.logging.ERROR)
        service = local.LocalKeyVault(
            "/test/key_vault", "key1.key,pass1:key2.key,pass2,rsa"
        )
        fake_key = pretend.stub(
            keyid="keyid", to_dict=pretend.call_recorder(lambda: {"k": "v"})
        )
        mocked_sslibkey_from_dict = MagicMock()
        mocked_sslibkey_from_dict.side_effect = [
            FileNotFoundError("Cannot find file"),
            None,
        ]
        local.SSlibKey.from_dict = mocked_sslibkey_from_dict
        local.SSlibSigner.from_priv_key_uri = pretend.raiser(
            local.CryptoError("Wrong password")
        )
        with pytest.raises(local.KeyVaultError) as err:
            service.get(fake_key)

        assert "Cannot load a valid online key" in str(err)
        assert caplog.record_tuples == [
            ("root", 40, "Cannot read private key file key1"),
            ("root", 40, "Key key2 didn't match"),
            ("root", 50, "Cannot load a valid online key."),
        ]
