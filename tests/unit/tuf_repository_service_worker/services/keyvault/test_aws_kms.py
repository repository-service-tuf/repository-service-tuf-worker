# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import unittest.mock

import pretend
import pytest
from securesystemslib.exceptions import UnsupportedAlgorithmError

from repository_service_tuf_worker.interfaces import KeyVaultError
from repository_service_tuf_worker.services.keyvault import aws_kms

PATH = "repository_service_tuf_worker.services.keyvault.aws_kms"


class TestAWSKMS:
    def test_init(self):
        service = aws_kms.AWSKMS(["AWSSigner1", "AWSSigner2"])
        assert service._signers == ["AWSSigner1", "AWSSigner2"]

    def test__raw_key_parser(self, monkeypatch):
        key1_id = "d15e3ac4-647a-40e5-8a52-197a95eac8e4"
        key1_alg = "RSASSA_PKCS1_V1_5_SHA_256"
        key2_id = "4d315d70-b266-48ea-8b83-ed1aeda57ec6"
        key2_alg = "RSASSA_PSS_SHA_512"
        keys = f"{key1_id},{key1_alg}:{key2_id},{key2_alg}"

        fake_parse_raw_key = unittest.mock.MagicMock()
        fake_parse_raw_key.side_effect = [
            [key1_id, key1_alg],
            [key2_id, key2_alg],
        ]
        monkeypatch.setattr(f"{PATH}.parse_raw_key", fake_parse_raw_key)

        result = aws_kms.AWSKMS._raw_key_parser(keys)
        assert result == [
            aws_kms.AWSKey(key1_id, aws_kms.ALGORITHM_TO_SCHEME[key1_alg]),
            aws_kms.AWSKey(key2_id, aws_kms.ALGORITHM_TO_SCHEME[key2_alg]),
        ]
        fake_parse_raw_key.assert_has_calls(
            [
                unittest.mock.call(f"{key1_id},{key1_alg}"),
                unittest.mock.call(f"{key2_id},{key2_alg}"),
            ]
        )

    def test__raw_key_parser_keys_no_signing_alg(self, monkeypatch):
        key1_id = "d15e3ac4-647a-40e5-8a52-197a95eac8e4"
        key2_id = "4d315d70-b266-48ea-8b83-ed1aeda57ec6"
        keys = f"{key1_id}:{key2_id}"

        fake_parse_raw_key = unittest.mock.MagicMock()
        fake_parse_raw_key.side_effect = [[key1_id], [key2_id]]
        monkeypatch.setattr(f"{PATH}.parse_raw_key", fake_parse_raw_key)

        result = aws_kms.AWSKMS._raw_key_parser(keys)
        assert result == [aws_kms.AWSKey(key1_id), aws_kms.AWSKey(key2_id)]

        fake_parse_raw_key.assert_has_calls(
            [
                unittest.mock.call(f"{key1_id}"),
                unittest.mock.call(f"{key2_id}"),
            ]
        )

    def test__raw_key_parser_with_one_invalid_key(self, monkeypatch, caplog):
        key1_id = ""
        key2_id = "4d315d70-b266-48ea-8b83-ed1aeda57ec6"
        keys = f"{key1_id}:{key2_id}"

        fake_parse_raw_key = unittest.mock.MagicMock()
        fake_parse_raw_key.side_effect = [[], [key2_id]]
        monkeypatch.setattr(f"{PATH}.parse_raw_key", fake_parse_raw_key)

        caplog.set_level(aws_kms.logging.ERROR)

        result = aws_kms.AWSKMS._raw_key_parser(keys)
        assert result == [aws_kms.AWSKey(key2_id)]
        assert "Key  is invalid" in caplog.record_tuples[0]

        fake_parse_raw_key.assert_has_calls(
            [
                unittest.mock.call(f"{key1_id}"),
                unittest.mock.call(f"{key2_id}"),
            ]
        )

    def test__raw_key_parser_keys_no_valid_keys(self, monkeypatch):
        fake_parse_raw_key = pretend.call_recorder(lambda a: [])
        monkeypatch.setattr(f"{PATH}.parse_raw_key", fake_parse_raw_key)

        with pytest.raises(KeyVaultError) as e:
            aws_kms.AWSKMS._raw_key_parser("")

        err_msg = "No valid keys in configuration 'RSTUF_AWSKMS_KEYVAULT_KEYS'"
        assert err_msg in str(e)
        assert fake_parse_raw_key.calls == [pretend.call("")]

    def test__init_signers_from_valid_keys_module_not_found(self):
        import builtins

        real_import = builtins.__import__
        raiser = pretend.raiser(ModuleNotFoundError("Not found"))
        builtins.__import__ = raiser

        with pytest.raises(ModuleNotFoundError) as e:
            aws_kms.AWSKMS._init_signers_from_valid_keys([])

        # Return the original import to not cause other exceptions.
        builtins.__import__ = real_import

        err_msg = "botocore is required by AWSKMS - 'pip install botocore'"
        assert err_msg in str(e)

    def test__init_signers_from_valid_keys(self, monkeypatch):
        fake__import = unittest.mock.MagicMock()
        fake__import.side_effect = [
            ["priv_uri_1", "pub_key1"],
            ["priv_uri_2", "pub_key2"],
        ]

        monkeypatch.setattr(f"{PATH}.AWSSigner.import_", fake__import)

        fake_signer1 = pretend.stub(sign=pretend.call_recorder(lambda a: None))
        fake_signer2 = pretend.stub(sign=pretend.call_recorder(lambda a: None))
        fake_from_priv_key_uri = unittest.mock.MagicMock()
        fake_from_priv_key_uri.side_effect = [fake_signer1, fake_signer2]
        monkeypatch.setattr(
            f"{PATH}.AWSSigner.from_priv_key_uri", fake_from_priv_key_uri
        )
        keys = [
            aws_kms.AWSKey("id1", "scheme1"),
            aws_kms.AWSKey("id2", "scheme2"),
        ]

        result = aws_kms.AWSKMS._init_signers_from_valid_keys(keys)
        assert result == [fake_signer1, fake_signer2]
        fake__import.assert_has_calls(
            [
                unittest.mock.call("id1", "scheme1"),
                unittest.mock.call("id2", "scheme2"),
            ]
        )
        fake_from_priv_key_uri.assert_has_calls(
            [
                unittest.mock.call("priv_uri_1", "pub_key1"),
                unittest.mock.call("priv_uri_2", "pub_key2"),
            ]
        )
        assert fake_signer1.sign.calls == [pretend.call(b"test data")]
        assert fake_signer2.sign.calls == [pretend.call(b"test data")]

    def test__init_signers_from_valid_keys_from_valid_and_invalid_keys(
        self, monkeypatch, caplog
    ):
        fake__import = unittest.mock.MagicMock()
        fake__import.side_effect = [
            ["priv_uri_1", "pub_key1"],
            UnsupportedAlgorithmError("Bad algorithm"),
        ]

        monkeypatch.setattr(f"{PATH}.AWSSigner.import_", fake__import)
        fake_signer = pretend.stub(sign=pretend.call_recorder(lambda a: None))

        fake_from_priv_key_uri = pretend.call_recorder(lambda *a: fake_signer)
        monkeypatch.setattr(
            f"{PATH}.AWSSigner.from_priv_key_uri", fake_from_priv_key_uri
        )
        keys = [aws_kms.AWSKey("id1", "scheme1"), aws_kms.AWSKey("id2", "bad")]

        caplog.set_level(aws_kms.logging.INFO)
        result = aws_kms.AWSKMS._init_signers_from_valid_keys(keys)
        assert result == [fake_signer]
        fake__import.assert_has_calls(
            [
                unittest.mock.call("id1", "scheme1"),
                unittest.mock.call("id2", "bad"),
            ]
        )

        assert "Signer from key id1 created" in caplog.record_tuples[0]
        assert "Bad algorithm" in caplog.record_tuples[1]
        assert "Failed to load id2 AWSKMS key" in caplog.record_tuples[2]
        assert fake_from_priv_key_uri.calls == [
            pretend.call("priv_uri_1", "pub_key1")
        ]
        assert fake_signer.sign.calls == [pretend.call(b"test data")]

    def test__init_signers_from_valid_keys_no_valid_keys(
        self, monkeypatch, caplog
    ):
        fake__import = unittest.mock.MagicMock()
        fake__import.side_effect = [
            UnsupportedAlgorithmError("Bad algorithm key1"),
            UnsupportedAlgorithmError("Bad algorithm key2"),
        ]

        monkeypatch.setattr(f"{PATH}.AWSSigner.import_", fake__import)
        fake_signer = pretend.stub(sign=pretend.call_recorder(lambda a: None))

        fake_from_priv_key_uri = pretend.call_recorder(lambda *a: fake_signer)
        monkeypatch.setattr(
            f"{PATH}.AWSSigner.from_priv_key_uri", fake_from_priv_key_uri
        )
        keys = [aws_kms.AWSKey("id1", "bad1"), aws_kms.AWSKey("id2", "bad2")]

        caplog.set_level(aws_kms.logging.ERROR)
        with pytest.raises(KeyVaultError) as e:
            aws_kms.AWSKMS._init_signers_from_valid_keys(keys)

        assert "No valid keys found in the AWSKMS" in str(e)
        fake__import.assert_has_calls(
            [
                unittest.mock.call("id1", "bad1"),
                unittest.mock.call("id2", "bad2"),
            ]
        )

        assert "Bad algorithm key1" in caplog.record_tuples[0]
        assert "Bad algorithm key2" in caplog.record_tuples[1]
        assert fake_from_priv_key_uri.calls == []
        assert fake_signer.sign.calls == []

    def test_configure(self, monkeypatch):
        fake_os = pretend.stub(environ={})
        monkeypatch.setattr(f"{PATH}.os", fake_os)
        fake__raw_key_parser = pretend.call_recorder(lambda a: "aws-keys")
        monkeypatch.setattr(
            f"{PATH}.AWSKMS._raw_key_parser", fake__raw_key_parser
        )
        fake__init_signers_from_valid_keys = pretend.call_recorder(
            lambda a: ["signer"]
        )
        monkeypatch.setattr(
            f"{PATH}.AWSKMS._init_signers_from_valid_keys",
            fake__init_signers_from_valid_keys,
        )

        def fake_get(key: str) -> str:
            if key == "AWSKMS_KEYVAULT_REGION":
                return "us-east-1"
            elif key == "AWSKMS_KEYVAULT_ENDPOINT_URL":
                return "http://localstack:4566"

        test_settings = pretend.stub(
            AWSKMS_KEYVAULT_ACCESS_KEY="access_key",
            AWSKMS_KEYVAULT_SECRET_KEY="secret_access_key",
            AWSKMS_KEYVAULT_KEYS="keys",
            get=fake_get,
        )

        result: aws_kms.AWSKMS = aws_kms.AWSKMS.configure(test_settings)
        assert isinstance(result, aws_kms.AWSKMS)
        assert result._signers == ["signer"]
        assert fake_os.environ["AWS_ACCESS_KEY_ID"] == "access_key"
        assert fake_os.environ["AWS_SECRET_ACCESS_KEY"] == "secret_access_key"
        assert fake_os.environ["AWS_DEFAULT_REGION"] == "us-east-1"
        assert fake_os.environ["AWS_ENDPOINT_URL"] == "http://localstack:4566"
        assert fake__raw_key_parser.calls == [pretend.call("keys")]
        assert fake__init_signers_from_valid_keys.calls == [
            pretend.call("aws-keys")
        ]

    def test_settings(self):
        service_settings = aws_kms.AWSKMS.settings()

        assert service_settings == [
            aws_kms.ServiceSettings(
                names=["AWSKMS_KEYVAULT_KEYS"],
                required=True,
            ),
            aws_kms.ServiceSettings(
                names=["AWSKMS_KEYVAULT_ACCESS_KEY"],
                required=True,
            ),
            aws_kms.ServiceSettings(
                names=["AWSKMS_KEYVAULT_SECRET_KEY"],
                required=True,
            ),
            aws_kms.ServiceSettings(
                names=["AWSKMS_KEYVAULT_REGION"],
                required=False,
            ),
            aws_kms.ServiceSettings(
                names=["AWSKMS_KEYVAULT_ENDPOINT_URL"],
                required=False,
            ),
        ]

    def test_get(self):
        fake_signer1 = pretend.stub(public_key=pretend.stub(keyid="id1"))
        fake_signer2 = pretend.stub(public_key=pretend.stub(keyid="id2"))
        service = aws_kms.AWSKMS([fake_signer1, fake_signer2])
        fake_public_key = pretend.stub(keyid="id2")

        result = service.get(fake_public_key)
        assert result == fake_signer2

    def test_get_no_valid_keys(self):
        fake_signer1 = pretend.stub(public_key=pretend.stub(keyid="id1"))
        fake_signer2 = pretend.stub(public_key=pretend.stub(keyid="id2"))
        service = aws_kms.AWSKMS([fake_signer1, fake_signer2])
        fake_public_key = pretend.stub(keyid="CUSTOM")

        with pytest.raises(KeyVaultError) as e:
            service.get(fake_public_key)

        m = "Online key in root doesn't match any of the key used by keyvault"
        assert m in str(e)

    def test_get_no_keys(self):
        service = aws_kms.AWSKMS([])
        fake_public_key = pretend.stub(keyid="CUSTOM")

        with pytest.raises(KeyVaultError) as e:
            service.get(fake_public_key)

        m = "Online key in root doesn't match any of the keys used by keyvault"
        assert m in str(e)
