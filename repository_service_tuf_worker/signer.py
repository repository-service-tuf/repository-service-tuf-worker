# SPDX-FileCopyrightText: 2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

from dynaconf import Dynaconf
from securesystemslib.signer import Key, Signer


class SignerStore:
    """Generic signer store."""

    def __init__(self, settings: Dynaconf):
        self._settings = settings
        self._signers: dict[str, Signer] = {}

    def get(self, key: Key) -> Signer:
        """Return signer for passed key."""

        if key.keyid not in self._signers:
            self._signers[key.keyid] = self._settings.KEYVAULT.get(key)

        return self._signers[key.keyid]
