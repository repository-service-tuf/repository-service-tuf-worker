# SPDX-FileCopyrightText: 2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

from pathlib import Path
from unittest.mock import patch

import pytest
from dynaconf import Dynaconf
from pretend import stub
from securesystemslib.signer import CryptoSigner, Key

from repository_service_tuf_worker.interfaces import IKeyVault
from repository_service_tuf_worker.signer import (
    RSTUF_ONLINE_KEY_URI_FIELD,
    FileNameSigner,
    SignerStore,
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

    def test_get_load_and_cache(self):
        class FakeKeyVault(IKeyVault):
            @classmethod
            def configure(cls, settings):
                pass

            @classmethod
            def settings(cls):
                pass

            def get(self, public_key):
                return fake_signer

        fake_id = "fake_id"
        fake_signer = stub()
        fake_key = stub(keyid=fake_id, unrecognized_fields={})

        settings = Dynaconf(KEYVAULT=FakeKeyVault())
        store = SignerStore(settings)

        assert not store._signers
        assert store.get(fake_key) == fake_signer
        assert fake_id in store._signers

    def test_get_no_vault(self):
        fake_id = "fake_id"
        fake_key = stub(keyid=fake_id, unrecognized_fields={})

        settings = Dynaconf()
        store = SignerStore(settings)

        with pytest.raises(ValueError):
            store.get(fake_key)

    def test_get_from_file_uri(self, key_metadata):
        path = _FILES / "pem" / "ed25519_private.pem"
        uri = f"file:{path}?encrypted=false"
        key_metadata[RSTUF_ONLINE_KEY_URI_FIELD] = uri

        fake_id = "fake_id"
        key = Key.from_dict(fake_id, key_metadata)

        settings = Dynaconf()
        store = SignerStore(settings)
        signer = store.get(key)

        assert isinstance(signer, CryptoSigner)

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
