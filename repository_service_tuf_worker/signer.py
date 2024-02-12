# SPDX-FileCopyrightText: 2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT
import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from dynaconf import Dynaconf
from securesystemslib.signer import (
    SIGNER_FOR_URI_SCHEME,
    CryptoSigner,
    Key,
    SecretsHandler,
    Signer,
)

from repository_service_tuf_worker.interfaces import IKeyVault


class FileNameSigner(CryptoSigner):
    """File-based signer implementation.

    Provide method to load **unencrypted** PKCS8/PEM private key from file.

    File path is constructed by joining base path in envrionment variable
    ``RSTUF_ONLINE_KEY_DIR`` with file in ``priv_key_uri``.

    NOTE: Make sure to use the secrets management service of your deployment
    platform to protect your private key!

    Example::

        RSTUF_ONLINE_KEY_DIR (env) "/run/secrets"
        priv_key_uri (arg): "fn:foo"

        File path: "/run/secrets/foo"

    Raises:
        KeyError: RSTUF_ONLINE_KEY_DIR environment variable not set
        OSError: file cannot be loaded
        ValueError: uri has no filenmae, or private key cannot be decoded,
                or type does not match public key
        cryptography.exceptions.UnsupportedAlgorithm: key type not supported

    """

    SCHEME = "fn"
    DIR_VAR = "RSTUF_ONLINE_KEY_DIR"

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "FileNameSigner":
        _, _, file_name = priv_key_uri.partition(":")
        if not file_name:
            raise ValueError(
                f"bad uri: expected '{cls.SCHEME}:<file name>', "
                f"'got {priv_key_uri}'"
            )

        dir_ = os.environ[cls.DIR_VAR]

        with open(Path(dir_, file_name), "rb") as f:
            private_pem = f.read()

        private_key = load_pem_private_key(private_pem, None)
        return cls(private_key, public_key)


RSTUF_ONLINE_KEY_URI_FIELD = "x-rstuf-online-key-uri"

# Register non-default securesystemslib file signer
# secure-systems-lab/securesystemslib#617
SIGNER_FOR_URI_SCHEME[CryptoSigner.FILE_URI_SCHEME] = CryptoSigner
# Register custom FileNameSigner
SIGNER_FOR_URI_SCHEME[FileNameSigner.SCHEME] = FileNameSigner


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
