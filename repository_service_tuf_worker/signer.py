# SPDX-FileCopyrightText: 2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

from dynaconf import Dynaconf
from securesystemslib.signer import (
    SIGNER_FOR_URI_SCHEME,
    CryptoSigner,
    Key,
    Signer,
)

from repository_service_tuf_worker.interfaces import IKeyVault

RSTUF_ONLINE_KEY_URI_FIELD = "x-rstuf-online-key-uri"

# Register non-default securesystemslib file signer
# secure-systems-lab/securesystemslib#617
SIGNER_FOR_URI_SCHEME[CryptoSigner.FILE_URI_SCHEME] = CryptoSigner


class SignerStore:
    """Generic signer store."""

    def __init__(self, settings: Dynaconf):
        self._settings = settings
        self._signers: dict[str, Signer] = {}

    def get(self, key: Key) -> Signer:
        """Return signer for passed key.

        - signer is loaded from the uri included in the passed public key
          (see SIGNER_FOR_URI_SCHEME for available uri schemes)
        - RSTUF_KEYVAULT_BACKEND is used as fallback, if no URI is included

        """

        if key.keyid not in self._signers:
            if uri := key.unrecognized_fields.get(RSTUF_ONLINE_KEY_URI_FIELD):
                self._signers[key.keyid] = Signer.from_priv_key_uri(uri, key)

            else:
                vault = self._settings.get("KEYVAULT")
                if not isinstance(vault, IKeyVault):
                    raise ValueError(
                        "RSTUF_KEYVAULT_BACKEND is required for online signing"
                    )

                self._signers[key.keyid] = vault.get(key)

        return self._signers[key.keyid]
