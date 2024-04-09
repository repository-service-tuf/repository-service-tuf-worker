# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
from unittest.mock import MagicMock

import pretend
import pytest

from repository_service_tuf_worker.services.keyvault import local

MOCK_PATH = "repository_service_tuf_worker.services.keyvault.local"


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

    def test___base64_key(self, monkeypatch):
        service = local.LocalKeyVault(
            "/test/key_vault", "base64|fakebase64keybody,pass1"
        )
        fake_haslib = pretend.stub(
            blake2b=pretend.call_recorder(
                lambda *a, **kw: pretend.stub(hexdigest=lambda *a: "fake_hash")
            )
        )
        monkeypatch.setattr(f"{MOCK_PATH}.hashlib", fake_haslib)
        fake_os = pretend.stub(
            path=pretend.stub(
                join=pretend.call_recorder(lambda *a: "key_path"),
                isfile=pretend.call_recorder(lambda a: True),
            )
        )
        monkeypatch.setattr(f"{MOCK_PATH}.os", fake_os)

        result = service._base64_key(
            "/test/key_vault", "base64|fakebase64keybody"
        )

        assert result == "fake_hash"
        assert fake_haslib.blake2b.calls == [
            pretend.call(
                "base64|fakebase64keybody".encode("utf-8"), digest_size=16
            )
        ]
        assert fake_os.path.isfile.calls == [pretend.call("key_path")]

    def test___base64_key_file_doesnt_exist(self, monkeypatch):
        service = local.LocalKeyVault(
            "/test/key_vault", "base64|fakebase64keybody,pass1:key2.key,pass2"
        )
        fake_haslib = pretend.stub(
            blake2b=pretend.call_recorder(
                lambda *a, **kw: pretend.stub(hexdigest=lambda *a: "fake_hash")
            )
        )
        monkeypatch.setattr(f"{MOCK_PATH}.hashlib", fake_haslib)
        fake_os = pretend.stub(
            path=pretend.stub(
                join=pretend.call_recorder(lambda *a: "key_path"),
                isfile=pretend.call_recorder(lambda a: False),
            )
        )
        monkeypatch.setattr(f"{MOCK_PATH}.os", fake_os)
        fake_data = pretend.stub(write=pretend.call_recorder(lambda *a: None))
        fake_file_obj = pretend.stub(
            __enter__=pretend.call_recorder(lambda: fake_data),
            __exit__=pretend.call_recorder(lambda *a: None),
            close=pretend.call_recorder(lambda: None),
        )
        monkeypatch.setitem(
            local.__builtins__, "open", lambda *a: fake_file_obj
        )
        fake_base64_decode_obj = pretend.stub(
            decode=pretend.call_recorder(lambda: "k")
        )
        fake_base64 = pretend.stub(
            b64decode=pretend.call_recorder(lambda *a: fake_base64_decode_obj)
        )
        monkeypatch.setattr(f"{MOCK_PATH}.base64", fake_base64)
        result = service._base64_key("/test/key_vault", "fakebase64keybody")

        assert result == "fake_hash"
        assert fake_haslib.blake2b.calls == [
            pretend.call("fakebase64keybody".encode("utf-8"), digest_size=16)
        ]
        assert fake_os.path.isfile.calls == [pretend.call("key_path")]
        assert fake_data.write.calls == [pretend.call("k")]
        assert fake_base64.b64decode.calls == [
            pretend.call("fakebase64keybody")
        ]
        assert fake_base64_decode_obj.decode.calls == [pretend.call()]

    def test__raw_key_parser(self):
        service = local.LocalKeyVault(
            "/test/key_vault", "key1.key,pass1:key2.key,pass2,rsa"
        )
        parsed_keys = service._raw_key_parser(service._path, service._keys)

        assert parsed_keys == [
            local.LocalKey(file="key1.key", password="pass1", type="ed25519"),
            local.LocalKey(file="key2.key", password="pass2", type="rsa"),
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

        parsed_keys = service._raw_key_parser(service._path, service._keys)

        assert parsed_keys == [
            local.LocalKey(file="key1.key", password="pass1", type="ed25519")
        ]

    def test__raw_key_parser_with_key_base64(self, monkeypatch):
        fake__base64_key = pretend.call_recorder(lambda *a: "fake-hash")
        monkeypatch.setattr(
            f"{MOCK_PATH}.LocalKeyVault._base64_key", fake__base64_key
        )
        parsed_keys = local.LocalKeyVault._raw_key_parser(
            "/test/key_vault",
            "base64|LnRvnYvCg==,pass1:base64|LnRAsdmiAS==,pass2,rsa",
        )

        assert parsed_keys == [
            local.LocalKey(file="fake-hash", password="pass1", type="ed25519"),
            local.LocalKey(file="fake-hash", password="pass2", type="rsa"),
        ]
        assert fake__base64_key.calls == [
            pretend.call("/test/key_vault", "LnRvnYvCg=="),
            pretend.call("/test/key_vault", "LnRAsdmiAS=="),
        ]

    def test__raw_key_parser_with_one_invalid_configuration(self, caplog):
        service = local.LocalKeyVault(
            "/test/key_vault", "key1.key:key2.key,pass2,rsa"
        )
        caplog.set_level(local.logging.ERROR)
        parsed_keys = service._raw_key_parser(service._path, service._keys)

        assert parsed_keys == [
            local.LocalKey(file="key2.key", password="pass2", type="rsa")
        ]
        assert "Key is invalid" in caplog.record_tuples[0]

    def test__raw_key_parser_with_invalid_configuration(self):
        service = local.LocalKeyVault("/test/key_vault", "key1.key:pass2")

        with pytest.raises(local.KeyVaultError) as err:
            service._raw_key_parser(service._path, service._keys)

        assert (
            "No valid keys in configuration 'RSTUF_LOCAL_KEYVAULT_KEYS'"
            in str(err)
        )

    def test_configure(self, monkeypatch):
        test_settings = pretend.stub(
            LOCAL_KEYVAULT_PATH="/path/key_vault/",
            LOCAL_KEYVAULT_KEYS="key1.key,pass1:key2.key,pass2,rsa",
        )
        local_keys = [
            local.LocalKey(file="key1.key", password="pass1"),
            local.LocalKey(file="key2.key", password="pass2", type="rsa"),
        ]
        fake_import_privatekey_from_file = pretend.call_recorder(lambda *a: {})
        monkeypatch.setattr(
            f"{MOCK_PATH}.import_privatekey_from_file",
            fake_import_privatekey_from_file,
        )

        service = local.LocalKeyVault.configure(test_settings)
        assert fake_import_privatekey_from_file.calls == [
            pretend.call("/path/key_vault/key1.key", "ed25519", "pass1"),
            pretend.call("/path/key_vault/key2.key", "rsa", "pass2"),
        ]
        assert isinstance(service, local.LocalKeyVault)
        assert service._path == test_settings.LOCAL_KEYVAULT_PATH
        assert service._keys == local_keys

    def test_configure_file_base64(self, monkeypatch):
        test_settings = pretend.stub(
            LOCAL_KEYVAULT_PATH="/path/key_vault/",
            LOCAL_KEYVAULT_KEYS="base64|LnRvnYvCg==,pass1:key2.key,pass2,rsa",
        )
        local_keys = [
            local.LocalKey(file="fake_hash", password="pass1"),
            local.LocalKey(file="key2.key", password="pass2", type="rsa"),
        ]
        fake__raw_key_parser = pretend.call_recorder(lambda *a: local_keys)
        monkeypatch.setattr(
            f"{MOCK_PATH}.LocalKeyVault._raw_key_parser", fake__raw_key_parser
        )
        fake_import_privatekey_from_file = pretend.call_recorder(lambda *a: {})
        monkeypatch.setattr(
            f"{MOCK_PATH}.import_privatekey_from_file",
            fake_import_privatekey_from_file,
        )

        service = local.LocalKeyVault.configure(test_settings)
        assert isinstance(service, local.LocalKeyVault)
        assert service._path == test_settings.LOCAL_KEYVAULT_PATH
        assert service._keys == local_keys
        assert fake_import_privatekey_from_file.calls == [
            pretend.call("/path/key_vault/fake_hash", "ed25519", "pass1"),
            pretend.call("/path/key_vault/key2.key", "rsa", "pass2"),
        ]
        assert fake__raw_key_parser.calls == [
            pretend.call(
                test_settings.LOCAL_KEYVAULT_PATH,
                test_settings.LOCAL_KEYVAULT_KEYS,
            )
        ]

    def test_configure_no_valid_keys(self, monkeypatch):
        test_settings = pretend.stub(
            LOCAL_KEYVAULT_PATH="/path/key_vault/",
            LOCAL_KEYVAULT_KEYS="key1.key:key2.key",
        )
        fake__raw_key_parser = pretend.call_recorder(lambda *a: [])
        monkeypatch.setattr(
            f"{MOCK_PATH}.LocalKeyVault._raw_key_parser", fake__raw_key_parser
        )
        with pytest.raises(local.KeyVaultError) as err:
            local.LocalKeyVault.configure(test_settings)

        assert "No valid keys found in the LocalKeyVault" in str(err)
        assert fake__raw_key_parser.calls == [
            pretend.call(
                test_settings.LOCAL_KEYVAULT_PATH,
                test_settings.LOCAL_KEYVAULT_KEYS,
            )
        ]

    def test_configure_sslib_fail_one_key(self, caplog, monkeypatch):
        test_settings = pretend.stub(
            LOCAL_KEYVAULT_PATH="/path/key_vault/",
            LOCAL_KEYVAULT_KEYS="key1,pass1:key2,pass2,rsa",
        )
        caplog.set_level(local.logging.WARNING)
        local_keys = [
            local.LocalKey(file="key1", password="pass1"),
            local.LocalKey(file="key2", password="pass2", type="rsa"),
        ]
        fake__raw_key_parser = pretend.call_recorder(lambda *a: local_keys)
        monkeypatch.setattr(
            f"{MOCK_PATH}.LocalKeyVault._raw_key_parser", fake__raw_key_parser
        )
        mocked_import_pk_from_file = MagicMock()
        mocked_import_pk_from_file.side_effect = [
            local.FormatError("Invalid format"),
            None,
        ]
        monkeypatch.setattr(
            f"{MOCK_PATH}.import_privatekey_from_file",
            mocked_import_pk_from_file,
        )

        service = local.LocalKeyVault.configure(test_settings)
        assert isinstance(service, local.LocalKeyVault)
        assert service._path == test_settings.LOCAL_KEYVAULT_PATH
        assert service._keys == local_keys
        assert caplog.record_tuples == [
            ("root", 40, "Invalid format"),
            ("root", 30, "Failed to load LocalKeyVault key"),
        ]
        assert fake__raw_key_parser.calls == [
            pretend.call(
                test_settings.LOCAL_KEYVAULT_PATH,
                test_settings.LOCAL_KEYVAULT_KEYS,
            )
        ]

    def test_configure_sslib_fail_all_keys(self, caplog, monkeypatch):
        test_settings = pretend.stub(
            LOCAL_KEYVAULT_PATH="/path/key_vault/",
            LOCAL_KEYVAULT_KEYS="key1,pass1:key2,rsa,pass2",
        )
        caplog.set_level(local.logging.WARNING)
        local_keys = [
            local.LocalKey(file="key1", password="pass1"),
            local.LocalKey(file="key2", password="pass2", type="rsa"),
        ]
        fake__raw_key_parser = pretend.call_recorder(lambda *a: local_keys)
        monkeypatch.setattr(
            f"{MOCK_PATH}.LocalKeyVault._raw_key_parser", fake__raw_key_parser
        )

        fake_import_privatekey_from_file = pretend.raiser(
            local.FormatError("Invalid format")
        )
        monkeypatch.setattr(
            f"{MOCK_PATH}.import_privatekey_from_file",
            fake_import_privatekey_from_file,
        )
        with pytest.raises(local.KeyVaultError) as err:
            local.LocalKeyVault.configure(test_settings)

        assert "No valid keys found in the LocalKeyVault" in str(err)

        assert caplog.record_tuples == [
            ("root", 40, "Invalid format"),
            ("root", 30, "Failed to load LocalKeyVault key"),
            ("root", 40, "Invalid format"),
            ("root", 30, "Failed to load LocalKeyVault key"),
            ("root", 40, "No valid keys found in the LocalKeyVault"),
        ]
        assert fake__raw_key_parser.calls == [
            pretend.call(
                test_settings.LOCAL_KEYVAULT_PATH,
                test_settings.LOCAL_KEYVAULT_KEYS,
            )
        ]

    def test_settings(self):
        service = local.LocalKeyVault(
            "/test/key_vault", "key1.key,pass1:key2.key,rsa,pass2"
        )
        service_settings = service.settings()

        assert service_settings == [
            local.ServiceSettings(
                names=["LOCAL_KEYVAULT_PATH"],
                required=True,
            ),
            local.ServiceSettings(
                names=["LOCAL_KEYVAULT_KEYS"],
                required=True,
            ),
        ]

    def test_get(self, monkeypatch):
        local_keys = [
            local.LocalKey(file="key1.key", password="pass1"),
            local.LocalKey(file="key2.key", password="pass2"),
        ]
        service = local.LocalKeyVault("/test/key_vault", local_keys)
        fake_key = pretend.stub(
            keyid="keyid", to_dict=pretend.call_recorder(lambda: {"k": "v"})
        )
        fake_sslibkey = pretend.stub(
            from_dict=pretend.call_recorder(lambda *a: "fake_public_key")
        )
        monkeypatch.setattr(f"{MOCK_PATH}.SSlibKey", fake_sslibkey)
        fake_sslib_signer = pretend.stub(
            from_priv_key_uri=pretend.call_recorder(lambda *a: "fake_signer")
        )
        monkeypatch.setattr(f"{MOCK_PATH}.SSlibSigner", fake_sslib_signer)
        service._secrets_handler = pretend.call_recorder(lambda pwd: pwd)
        result = service.get(fake_key)

        assert result == "fake_signer"
        assert fake_sslib_signer.from_priv_key_uri.calls == [
            pretend.call(
                "file:/test/key_vault/key1.key?encrypted=true",
                "fake_public_key",
                "pass1",
            )
        ]
        assert fake_sslibkey.from_dict.calls == [
            pretend.call("keyid", {"k": "v"})
        ]
        assert service._secrets_handler.calls == [pretend.call("pass1")]

    def test_get_file_base64(self, monkeypatch):
        local_keys = [
            local.LocalKey(file="fake_hash", password="pass1"),
            local.LocalKey(file="key2.key", password="pass2", type="rsa"),
        ]
        service = local.LocalKeyVault("/test/key_vault", local_keys)
        fake_key = pretend.stub(
            keyid="keyid", to_dict=pretend.call_recorder(lambda: {"k": "v"})
        )
        fake_sslibkey = pretend.stub(
            from_dict=pretend.call_recorder(lambda *a: "fake_public_key")
        )
        monkeypatch.setattr(f"{MOCK_PATH}.SSlibKey", fake_sslibkey)
        fake_sslib_signer = pretend.stub(
            from_priv_key_uri=pretend.call_recorder(lambda *a: "fake_signer")
        )
        monkeypatch.setattr(f"{MOCK_PATH}.SSlibSigner", fake_sslib_signer)
        service._secrets_handler = pretend.call_recorder(lambda pwd: pwd)
        result = service.get(fake_key)

        assert result == "fake_signer"
        assert fake_sslib_signer.from_priv_key_uri.calls == [
            pretend.call(
                "file:/test/key_vault/fake_hash?encrypted=true",
                "fake_public_key",
                "pass1",
            )
        ]
        assert fake_sslibkey.from_dict.calls == [
            pretend.call("keyid", {"k": "v"})
        ]
        assert service._secrets_handler.calls == [pretend.call("pass1")]

    def test_get_fail_first_key(self, caplog, monkeypatch):
        caplog.set_level(local.logging.ERROR)
        local_keys = [
            local.LocalKey(file="fake_hash", password="pass1"),
            local.LocalKey(file="key2.key", password="pass2", type="rsa"),
        ]
        service = local.LocalKeyVault("/test/key_vault", local_keys)
        fake_key = pretend.stub(
            keyid="keyid", to_dict=pretend.call_recorder(lambda: {"k": "v"})
        )
        mocked_sslibkey_from_dict = MagicMock()
        mocked_sslibkey_from_dict.side_effect = [
            ValueError("Failed load online key"),
            "fake_public_key",
        ]
        fake_sslibkey = pretend.stub(from_dict=mocked_sslibkey_from_dict)
        monkeypatch.setattr(f"{MOCK_PATH}.SSlibKey", fake_sslibkey)
        fake_sslib_signer = pretend.stub(
            from_priv_key_uri=pretend.call_recorder(lambda *a: "fake_signer")
        )
        monkeypatch.setattr(f"{MOCK_PATH}.SSlibSigner", fake_sslib_signer)
        service._secrets_handler = pretend.call_recorder(lambda pwd: pwd)

        result = service.get(fake_key)
        assert result == "fake_signer"
        assert fake_sslib_signer.from_priv_key_uri.calls == [
            pretend.call(
                "file:/test/key_vault/key2.key?encrypted=true",
                "fake_public_key",
                "pass2",
            )
        ]
        assert service._secrets_handler.calls == [pretend.call("pass2")]
        assert caplog.record_tuples == [
            ("root", 40, "Cannot load the online key")
        ]

    def test_get_fail_all_configured_keys(self, caplog, monkeypatch):
        caplog.set_level(local.logging.ERROR)
        local_keys = [
            local.LocalKey(file="fake_hash", password="pass1"),
            local.LocalKey(file="key2.key", password="pass2", type="rsa"),
        ]
        service = local.LocalKeyVault("/test/key_vault", local_keys)
        fake_key = pretend.stub(
            keyid="keyid", to_dict=pretend.call_recorder(lambda: {"k": "v"})
        )
        mocked_sslibkey_from_dict = MagicMock()
        mocked_sslibkey_from_dict.side_effect = [
            FileNotFoundError("Cannot find file"),
            None,
        ]
        fake_sslibkey = pretend.stub(from_dict=mocked_sslibkey_from_dict)
        monkeypatch.setattr(f"{MOCK_PATH}.SSlibKey", fake_sslibkey)
        fake_sslib_signer = pretend.stub(
            from_priv_key_uri=pretend.raiser(
                local.CryptoError("Wrong password")
            )
        )
        monkeypatch.setattr(f"{MOCK_PATH}.SSlibSigner", fake_sslib_signer)
        with pytest.raises(local.KeyVaultError) as err:
            service.get(fake_key)

        assert "Cannot load a valid online key" in str(err)
        assert caplog.record_tuples == [
            ("root", 40, "Cannot read private key"),
            ("root", 40, "Key didn't match"),
            ("root", 50, "Cannot load a valid online key."),
        ]
