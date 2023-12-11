import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from securesystemslib.signer import (
    SIGNER_FOR_URI_SCHEME,
    CryptoSigner,
    Key,
    SecretsHandler,
    Signer,
)


class FileSigner(CryptoSigner):
    """File-based signer implementation.

    Overrides `CryptoSigner.from_priv_key_uri` to load private key file from a

    * directory, defined in envvar: `RSTUF_ONLINE_KEY_DIR`, and a
    * file name, defined in the passed uri: `fn:<file name>`

    """

    SCHEME = "fn"
    DIR_VAR = "RSTUF_ONLINE_KEY_DIR"

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "FileSigner":
        _, _, file_name = priv_key_uri.partition(":")
        dir_ = os.environ[cls.DIR_VAR]

        with open(Path(dir_, file_name), "rb") as f:
            private_pem = f.read()

        private_key = load_pem_private_key(private_pem, None)
        return FileSigner(private_key, public_key)


class EnvSigner(CryptoSigner):
    """Environment variable -based signer implementation.

    Overrides `CryptoSigner.from_priv_key_uri` to load private key from an
    environment variable defined in the passed uri:

    `env:<environment variable name>`

    """

    SCHEME = "env"

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "EnvSigner":
        _, _, env_name = priv_key_uri.partition(":")
        private_pem = os.environ[env_name]
        private_key = load_pem_private_key(private_pem, None)
        return EnvSigner(private_key, public_key)


# Register signer for scheme for usage via generic `Signer.from_priv_key_uri`
SIGNER_FOR_URI_SCHEME.update({FileSigner.SCHEME: FileSigner})
SIGNER_FOR_URI_SCHEME.update({EnvSigner.SCHEME: EnvSigner})


class SignerStore:
    """Generic signer store.

    Provides method to load and cache signer for passed public key, using a URI
    configured in a custom field of the passed key.

    """

    def __init__(self):
        self._signers: dict[str, Signer] = {}

    def get(self, key: Key) -> Signer:
        """Return signer for passed key.

        NOTE: the passed `key` is expected to have an "x-rstuf-online-key-uri"
        field in its `unrecognized_fields` attribute. This uri is used with the
        generic `Signer.from_priv_key_uri` interface, and, along with the
        public key, it encodes all information necessary to load the signer.

        Additional required information, e.g. to authenticate with a Cloud KMS,
        may be provided via signer type specific environment variables.

        """

        # If signer not in cache, load it using config
        if key.keyid not in self._signers:
            uri = key.unrecognized_fields["x-rstuf-online-key-uri"]
            self._signers[key.keyid] = Signer.from_priv_key_uri(uri, key)

        return self._signers[key.keyid]
