# SPDX-FileCopyrightText: 2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import pytest
from pretend import stub

from repository_service_tuf_worker.interfaces import IKeyVault
from repository_service_tuf_worker.signer import SignerStore


class TestSigner:
    def test_get_cached(self):
        fake_id = "fake_id"
        fake_signer = stub()
        fake_key = stub(keyid=fake_id)
        fake_settings = stub()

        store = SignerStore(fake_settings)
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
        fake_key = stub(keyid=fake_id)
        fake_settings = stub(get=lambda x: FakeKeyVault())

        store = SignerStore(fake_settings)

        assert not store._signers
        assert store.get(fake_key) == fake_signer
        assert fake_id in store._signers

    def test_get_no_vault(self):
        fake_id = "fake_id"
        fake_key = stub(keyid=fake_id)
        fake_settings = stub(get=lambda x: None)

        store = SignerStore(fake_settings)

        with pytest.raises(ValueError):
            store.get(fake_key)
