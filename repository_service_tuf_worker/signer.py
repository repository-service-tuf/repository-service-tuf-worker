# SPDX-FileCopyrightText: 2024 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT
import os
from contextlib import contextmanager
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


class FileNameSigner(CryptoSigner):
    """File-based signer implementation.

    Provide method to load **unencrypted** PKCS8/PEM private key from file.

    File path is constructed by joining base path in environment variable
    ``ONLINE_KEY_DIR`` with file in ``priv_key_uri``.

    NOTE: Make sure to use the secrets management service of your deployment
    platform to protect your private key!

    Example:
        ONLINE_KEY_DIR (env) "/run/secrets"
        priv_key_uri (arg): "fn:foo"
        File path: "/run/secrets/foo"

    Raises:
        KeyError: ONLINE_KEY_DIR environment variable not set
        OSError: file cannot be loaded
        ValueError: uri has no file name, or private key cannot be decoded,
        or type does not match public key
        `cryptography.exceptions.UnsupportedAlgorithm`: key type not supported
    """

    SCHEME = "fn"
    DIR_VAR = "ONLINE_KEY_DIR"

    @classmethod
    def from_priv_key_uri(
        cls,
        priv_key_uri: str,
        public_key: Key,
        secrets_handler: Optional[SecretsHandler] = None,
    ) -> "FileNameSigner":
        """Factory constructor for a given private key URI."""

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


# Register custom FileNameSigner
SIGNER_FOR_URI_SCHEME[FileNameSigner.SCHEME] = FileNameSigner


@contextmanager
def isolated_env(env: dict[str, str]):
    """Temporarily replace environment."""
    orig_env = dict(os.environ)
    os.environ.clear()
    os.environ.update(env)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(orig_env)


# List of Dyanconf settings needed in the signer environment
_AMBIENT_SETTING_NAMES = [
    "ONLINE_KEY_DIR",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ENDPOINT_URL",
    "AWS_DEFAULT_REGION",
    "GOOGLE_APPLICATION_CREDENTIALS",
]


class SignerStore:
    """Generic signer store.

    Parses ambient signer settings and provides them in an isolated environment
    under the expected names.
    """

    def __init__(self, settings: Dynaconf):
        # Cache known ambient settings
        self._ambient_settings: dict[str, str] = {}
        for name in _AMBIENT_SETTING_NAMES:
            if value := settings.get(name):
                self._ambient_settings[name] = value

        self._signers: dict[str, Signer] = {}

    def get(self, key: Key) -> Signer:
        """Return signer for passed key.

        - signer is loaded from the uri included in the passed public key
          (see SIGNER_FOR_URI_SCHEME for available uri schemes)
        - additional signer settings can be provided "ambiently" (see __init__)
        """

        if key.keyid not in self._signers:
            if uri := key.unrecognized_fields.get(RSTUF_ONLINE_KEY_URI_FIELD):
                # (Re-)export ambient settings in isolated environment
                with isolated_env(self._ambient_settings):
                    signer = Signer.from_priv_key_uri(uri, key)

                self._signers[key.keyid] = signer

        return self._signers[key.keyid]
