# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import logging
import os
from dataclasses import dataclass
from typing import Callable, List, Optional

from securesystemslib.exceptions import (
    CryptoError,
    Error,
    FormatError,
    StorageError,
    UnsupportedLibraryError,
)
from securesystemslib.interface import import_privatekey_from_file
from securesystemslib.signer import Key, SSlibKey, SSlibSigner

from repository_service_tuf_worker.interfaces import IKeyVault, ServiceSettings


@dataclass
class LocalKey:
    filename: str
    password: str
    type: Optional[str] = "ed25519"


class KeyVaultError(Exception):
    pass


class LocalKeyVault(IKeyVault):
    """Local KeyVault type"""

    def __init__(
        self,
        path: str,
        keys: str,
    ):
        """Configuration class for RSTUF Worker LocalKeyVault service.
        Manages all settings related to the usage of the online key(s).

        Args:
            path: path for key vault (used to define the volume)
            keys: list of online keys to be used. String uses two separators
               `:` to separate the keys and `,` to separate the field.
               `<filename>,<password>,<type>`
               filename: the filename
               password: the key password
               type: optional, default=ed25519
               Example:`key1.key,pass1:key2.key,pass2,rsa`
        """
        self._path: str = path
        self._keys: str = keys

    @classmethod
    def _raw_key_parser(cls, keys: str) -> List[LocalKey]:
        parsed_keys: List[LocalKey] = []
        for raw_key in keys.split(":"):
            if raw_key.startswith("/run/secrets/"):
                # The user has stored their keys using container secrets.
                with open(raw_key) as f:
                    key_data = f.read().rstrip("\n").split(",")
            else:
                key_data = raw_key.split(",")

            if len(key_data) == 1:
                logging.error(f"Key {keys.index(raw_key)} is invalid")
                pass

            if len(key_data) == 2:  # filename and password
                parsed_keys.append(
                    LocalKey(filename=key_data[0], password=key_data[1])
                )

            elif len(key_data) == 3:  # filename, type, password
                parsed_keys.append(
                    LocalKey(
                        filename=key_data[0],
                        password=key_data[1],
                        type=key_data[2],
                    )
                )
            else:
                logging.error(f"Key {keys.index(raw_key)} is invalid")
                pass

        if len(parsed_keys) == 0:
            raise KeyVaultError(
                "No valid keys in configuration 'RSTUF_LOCAL_KEYVAULT_KEYS'"
            )

        return parsed_keys

    @classmethod
    def configure(cls, settings) -> None:
        """
        Run actions to check and configure the service using the settings.
        """
        # Check that the online key can be loaded without an error.
        path = settings.LOCAL_KEYVAULT_PATH
        local_keys = cls._raw_key_parser(settings.LOCAL_KEYVAULT_KEYS)
        valid_key_found = False  # we look for at least one key is load
        for local_key in local_keys:
            local_key_path = os.path.join(path, local_key.filename)
            try:
                import_privatekey_from_file(
                    local_key_path, local_key.type, local_key.password
                )
                valid_key_found = True
            except (
                FormatError,
                ValueError,
                UnsupportedLibraryError,
                StorageError,
                Error,
            ) as e:
                logging.error(str(e))
                logging.warning(
                    f"Failed to load {local_key.filename} LocalKeyVault key"
                )

        if valid_key_found is False:
            error = KeyVaultError("No valid keys found in the LocalKeyVault")
            logging.error("No valid keys found in the LocalKeyVault")
            raise error

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
                name="LOCAL_KEYVAULT_KEYS",
                argument="keys",
                required=True,
            ),
        ]

    def _secrets_handler(self, password: str) -> Callable:
        """Generates simple Callable with password - required by SSLibSigner"""
        return lambda *a: password

    def get(self, public_key: Key) -> SSlibSigner:
        """Return a signer using the online key."""
        keys = self._raw_key_parser(self._keys)
        valid_key = False
        for key in keys:
            key_path = os.path.join(self._path, key.filename)
            priv_key_uri = f"file:{key_path}?encrypted=true"
            try:
                sslib_public_key = SSlibKey.from_dict(
                    public_key.keyid, public_key.to_dict()
                )
            except ValueError:
                logging.error(f"Cannot load the online key {key.filename}")
                continue
            except OSError:
                logging.error(f"Cannot read private key file {key.filename}")
                continue

            try:
                sslib_signer = SSlibSigner.from_priv_key_uri(
                    priv_key_uri,
                    sslib_public_key,
                    self._secrets_handler(key.password),
                )
                valid_key = True
            except CryptoError:
                logging.error(f"Key {key.filename} didn't match")
                continue

            return sslib_signer

        # if no valid keys found, raise a error to fail the task
        if valid_key is False:
            logging.critical("Cannot load a valid online key.")
            raise KeyVaultError("Cannot load a valid online key")
