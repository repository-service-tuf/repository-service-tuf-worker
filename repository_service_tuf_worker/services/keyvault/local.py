# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT

import os
from typing import Any, Dict, List, Optional

from dynaconf import Dynaconf
from securesystemslib.exceptions import (
    CryptoError,
    Error,
    FormatError,
    StorageError,
    UnsupportedLibraryError,
)
from securesystemslib.interface import import_privatekey_from_file
from securesystemslib.signer import SSlibSigner

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
        self._secrets_file: str = os.path.join(self._path, ".secrets.yaml")
        self._key_name: Optional[str] = key_name
        self._key_password: Optional[str] = key_pass
        self._key_type: Optional[str] = key_type
        self._keyvault = Dynaconf(
            envvar_prefix="LOCALKEYVAULT",
            settings_files=[self._secrets_file],
        )

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

    def get(self) -> SSlibSigner:
        """Return a signer using the online key."""
        try:
            key_info: Dict[str, Any] = import_privatekey_from_file(
                self._key_name,
                self._key_type,
                self._key_password,
            )
            return SSlibSigner(key_info)
        except (
            FormatError,
            ValueError,
            UnsupportedLibraryError,
            StorageError,
            CryptoError,
            Error,
        ) as err:
            raise KeyVaultError("Cannot load the online key") from err
