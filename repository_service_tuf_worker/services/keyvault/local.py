# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT

import os
from typing import Callable, List, Optional

from securesystemslib.signer import Key, SSlibSigner

from repository_service_tuf_worker.interfaces import IKeyVault, ServiceSettings


class KeyVaultError(Exception):
    pass


class LocalKeyVault(IKeyVault):
    """Local KeyVault type"""

    def __init__(
        self,
        path: str,
        key_name: Optional[str] = "online.key",
        key_pass: Optional[str] = None,
        key_type: Optional[str] = "ed25519",
    ):
        """Configuration class for RSTUF Worker LocalKeyVault service.

        Args:
            path: directory of the key vault.
            key_name: file name of the online key.
            key_pass: password to load the online key.
            key_type: cryptography type of the online key.
        """
        self._path: str = path
        self._key_name: Optional[str] = key_name
        self._key_password: Optional[str] = key_pass
        self._key_type: Optional[str] = key_type
        self._secrets_handler: Callable = lambda *a: self._key_password

    @classmethod
    def configure(cls, settings) -> None:
        """Configure using the settings."""
        os.makedirs(settings.LOCAL_KEYVAULT_PATH, exist_ok=True)

    @classmethod
    def settings(cls) -> List[ServiceSettings]:
        """Define the settings parameters."""
        return [
            ServiceSettings(
                name="LOCAL_KEYVAULT_PATH",
                argument="path",
                required=True,
            ),
            ServiceSettings(
                name="LOCAL_KEYVAULT_KEY_NAME",
                argument="key_name",
                required=False,
            ),
            ServiceSettings(
                name="LOCAL_KEYVAULT_KEY_PASSWORD",
                argument="key_pass",
                required=False,
            ),
            ServiceSettings(
                name="LOCAL_KEYVAULT_KEY_TYPE",
                argument="key_type",
                required=False,
            ),
        ]

    def get(self, public_key: Key) -> SSlibSigner:
        """Return a signer using the online key."""
        try:
            priv_key_uri = f"file:{self._key_name}?encrypted=true"
            return SSlibSigner.from_priv_key_uri(
                priv_key_uri, public_key, self._secrets_handler
            )
        except ValueError as e:
            raise KeyVaultError("Cannot load the online key") from e
        except OSError:
            raise KeyVaultError(
                f"Cannot read private key file {self._key_name}"
            )
