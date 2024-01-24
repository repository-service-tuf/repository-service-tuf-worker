# SPDX-FileCopyrightText: 2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

from dynaconf import Dynaconf
from securesystemslib.signer import Key, Signer

from repository_service_tuf_worker.interfaces import IKeyVault


class SignerStore:
    """Generic signer store."""

    def __init__(self, settings: Dynaconf):
        self._settings = settings
        self._signers: dict[str, Signer] = {}

    def get(self, key: Key) -> Signer:
        """Return signer for passed key."""

        if key.keyid not in self._signers:
            vault = self._settings.get("KEYVAULT")
            if not isinstance(vault, IKeyVault):
                raise ValueError(
                    "RSTUF_KEYVAULT_BACKEND is required for online signing"
                )

            self._signers[key.keyid] = vault.get(key)

        return self._signers[key.keyid]
