# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT

from typing import Callable, List, Optional

from securesystemslib.exceptions import (
    Error,
    FormatError,
    StorageError,
    UnsupportedLibraryError,
)
from securesystemslib.interface import import_privatekey_from_file
from securesystemslib.signer import Key, SSlibSigner

from repository_service_tuf_worker.interfaces import IKeyVault, ServiceSettings


class KeyVaultError(Exception):
    pass


class LocalKeyVault(IKeyVault):
    """Local KeyVault type"""

    def __init__(
        self,
        key_pass: str,
        key_path: Optional[str] = "online.key",
        key_type: Optional[str] = "ed25519",
    ):
        """Configuration class for RSTUF Worker LocalKeyVault service.
        Manages all settings related to the usage of the online key.

        Args:
            key_pass: password to load the online key.
            key_path: file path of the online key.
            key_type: cryptography type of the online key.
        """
        self._password: str = key_pass
        self._path: str = key_path
        self._type: str = key_type

        if self._password.startswith("/run/secrets/"):
            # The user has stored their password using container secrets.
            with open(self._password) as f:
                secrets_password = f.read().rstrip("\n")

            self._password = secrets_password

        self._secrets_handler: Callable = lambda *a: self._password

    @classmethod
    def configure(cls, settings) -> None:
        """
        Run actions to check and configure the service using the settings.
        """
        # Check that the online key can be loaded without an error.
        try:
            path = settings.LOCAL_KEYVAULT_PATH
            password: str
            if settings.LOCAL_KEYVAULT_PASSWORD.startswith("/run/secrets/"):
                # The user has stored their password using container secrets.
                with open(settings.LOCAL_KEYVAULT_PASSWORD) as f:
                    password = f.read().rstrip("\n")
            else:
                password = settings.LOCAL_KEYVAULT_PASSWORD

            import_privatekey_from_file(
                path, settings.LOCAL_KEYVAULT_TYPE, password
            )
        except (
            FormatError,
            ValueError,
            UnsupportedLibraryError,
            StorageError,
            Error,
        ) as e:
            raise KeyVaultError(f"Cannot read private key file {path}") from e

    @classmethod
    def settings(cls) -> List[ServiceSettings]:
        """Define the settings parameters."""
        return [
            ServiceSettings(
                name="LOCAL_KEYVAULT_PATH",
                argument="key_path",
                required=False,
                default="online.key",
            ),
            ServiceSettings(
                name="LOCAL_KEYVAULT_PASSWORD",
                argument="key_pass",
                required=True,
            ),
            ServiceSettings(
                name="LOCAL_KEYVAULT_TYPE",
                argument="key_type",
                required=False,
                default="ed25519",
            ),
        ]

    def get(self, public_key: Key) -> SSlibSigner:
        """Return a signer using the online key."""
        try:
            priv_key_uri = f"file:{self._path}?encrypted=true"
            return SSlibSigner.from_priv_key_uri(
                priv_key_uri, public_key, self._secrets_handler
            )
        except ValueError as e:
            raise KeyVaultError("Cannot load the online key") from e
        except OSError:
            raise KeyVaultError(f"Cannot read private key file {self._path}")
