# SPDX-FileCopyrightText: 2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dynaconf import Dynaconf
from pretend import stub
from securesystemslib.signer import AWSSigner, Key, SSlibKey

from repository_service_tuf_worker.signer import (
    RSTUF_ONLINE_KEY_URI_FIELD,
    FileNameSigner,
    SignerStore,
    isolated_env,
    normalize_aws_kms_priv_key_uri,
)

_FILES = Path(__file__).parent.parent.parent / "files"


@pytest.fixture()
def key_metadata():
    return {
        "keytype": "ed25519",
        "scheme": "ed25519",
        "keyval": {
            "public": (
                "4f66dabebcf30628963786001984c0b7"
                "5c175cdcf3bc4855933a2628f0cd0a0f"
            )
        },
    }


class TestSigner:
    def test_get_cached(self):
        fake_id = "fake_id"
        fake_signer = stub()
        fake_key = stub(keyid=fake_id)

        settings = Dynaconf()
        store = SignerStore(settings)
        store._signers[fake_id] = fake_signer

        assert store.get(fake_key) == fake_signer

    def test_get_from_file_name_uri(self, key_metadata):
        dir_ = _FILES / "pem"
        uri = "fn:ed25519_private.pem"

        key_metadata[RSTUF_ONLINE_KEY_URI_FIELD] = uri
        fake_id = "fake_id"
        key = Key.from_dict(fake_id, key_metadata)

        settings = Dynaconf(ONLINE_KEY_DIR=str(dir_))
        store = SignerStore(settings)
        signer = store.get(key)

        assert isinstance(signer, FileNameSigner)

    def test_get_from_file_name_uri_no_filename(self):
        uri = "fn:"
        settings = Dynaconf()
        store = SignerStore(settings)
        fake_key = stub(
            keyid="fake_id",
            unrecognized_fields={RSTUF_ONLINE_KEY_URI_FIELD: uri},
        )

        with pytest.raises(ValueError):
            store.get(fake_key)

    def test_get_from_file_name_uri_no_envvar(self):
        uri = "fn:foo.pem"
        settings = Dynaconf()
        store = SignerStore(settings)
        fake_key = stub(
            keyid="fake_id",
            unrecognized_fields={RSTUF_ONLINE_KEY_URI_FIELD: uri},
        )

        with patch.dict("os.environ", {}, clear=True), pytest.raises(KeyError):
            store.get(fake_key)

    @pytest.mark.parametrize(
        "uri, expected_awskms",
        [
            ("aws-kms:alias/aws-test-key", "awskms:alias/aws-test-key"),
            (
                "aws-kms:arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
                "awskms:arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
            ),
            ("aws-kms:///alias/aws-test-key", "awskms:alias/aws-test-key"),
            (
                "aws-kms://arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
                "awskms:arn:aws:kms:us-east-1:123456789012:key/abcd-1234",
            ),
            (
                "aws-kms://alias/nested-name",
                "awskms:alias/nested-name",
            ),
            ("fn:still-fn", "fn:still-fn"),
            ("awskms:alias/x", "awskms:alias/x"),
        ],
    )
    def test_normalize_aws_kms_priv_key_uri(self, uri, expected_awskms):
        assert normalize_aws_kms_priv_key_uri(uri) == expected_awskms

    @pytest.mark.parametrize(
        "bad_uri",
        ["aws-kms:", "aws-kms://", "aws-kms:///"],
    )
    def test_normalize_aws_kms_priv_key_uri_empty(self, bad_uri):
        with pytest.raises(ValueError):
            normalize_aws_kms_priv_key_uri(bad_uri)

    @patch("securesystemslib.signer.AWSSigner.from_priv_key_uri")
    def test_signer_store_get_aws_kms_uri_alias(self, mock_from_uri):
        """``aws-kms:`` URIs resolve via alias and call AWSSigner with ``awskms:``."""
        fake_aws_signer = AWSSigner.__new__(AWSSigner)
        mock_from_uri.return_value = fake_aws_signer

        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = (
            priv.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
        key = SSlibKey(
            "aws-kms-test-keyid",
            "rsa",
            "rsassa-pss-sha256",
            {"public": pub_pem},
        )
        key.unrecognized_fields[RSTUF_ONLINE_KEY_URI_FIELD] = (
            "aws-kms:alias/my-delegation-key"
        )

        settings = Dynaconf()
        store = SignerStore(settings)
        signer = store.get(key)

        assert signer is fake_aws_signer
        mock_from_uri.assert_called_once()
        call_uri = mock_from_uri.call_args[0][0]
        assert call_uri == "awskms:alias/my-delegation-key"

    @pytest.mark.skipif(
        not os.environ.get("RSTUF_AWS_ENDPOINT_URL"), reason="No AWS endpoint"
    )
    def test_get_from_aws(self):
        # Import test public key of given key type and keyid alias from AWS KMS
        # - see tests/files/aws/init-kms.sh for how such a key is created
        # - see tox.ini for how credentials etc. are passed via env vars
        scheme = "rsassa-pss-sha256"
        aws_keyid = "alias/aws-test-key"

        settings = Dynaconf(envvar_prefix="RSTUF")
        with isolated_env(settings.to_dict()):
            uri, key = AWSSigner.import_(aws_keyid, scheme)

        key.unrecognized_fields[RSTUF_ONLINE_KEY_URI_FIELD] = uri

        # Load signer from AWS KMS
        store = SignerStore(settings)
        signer = store.get(key)
        assert isinstance(signer, AWSSigner)
