# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT
import base64
import hashlib
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
    file: str
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
               `<file>,<password>,<type>`
               file: the file or base64 content (base64|<key body in base64>)
               password: the key password
               type: optional, default=ed25519
               Example:`key1.key,pass1:key2.key,pass2,rsa`
        """
        self._path: str = path
        self._keys: str = keys

    @classmethod
    def _base64_key(cls, keyvault_path, base64_key) -> str:
        key_content = base64_key.split("base64|")[1]
        hash_key = hashlib.blake2b(key_content.encode("utf-8"), digest_size=16)
        file_name = hash_key.hexdigest()
        key_path = os.path.join(keyvault_path, file_name)
        if os.path.isfile(key_path):
            return key_path
        else:
            with open(key_path, "w") as f:
                f.write(base64.b64decode(key_content).decode())

            return key_path

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
                logging.error("Key is invalid")
                pass

            if len(key_data) == 2:  # filename and password
                parsed_keys.append(
                    LocalKey(file=key_data[0], password=key_data[1])
                )

            elif len(key_data) == 3:  # filename, type, password
                parsed_keys.append(
                    LocalKey(
                        file=key_data[0],
                        password=key_data[1],
                        type=key_data[2],
                    )
                )
            else:
                logging.error("Key is invalid")
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
            if local_key.file.startswith("base64|"):
                local_key_path = cls._base64_key(path, local_key.file)
            else:
                local_key_path = os.path.join(path, local_key.file)
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
                logging.warning("Failed to load LocalKeyVault key")

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
            if key.file.startswith("base64|"):
                key_path = self._base64_key(self._path, key.file)
            else:
                key_path = os.path.join(self._path, key.file)
            priv_key_uri = f"file:{key_path}?encrypted=true"
            try:
                sslib_public_key = SSlibKey.from_dict(
                    public_key.keyid, public_key.to_dict()
                )
            except ValueError:
                logging.error("Cannot load the online key")
                continue
            except OSError:
                logging.error("Cannot read private key")
                continue

            try:
                sslib_signer = SSlibSigner.from_priv_key_uri(
                    priv_key_uri,
                    sslib_public_key,
                    self._secrets_handler(key.password),
                )
                valid_key = True
            except CryptoError:
                logging.error("Key didn't match")
                continue

            return sslib_signer

        # if no valid keys found, raise a error to fail the task
        if valid_key is False:
            logging.critical("Cannot load a valid online key.")
            raise KeyVaultError("Cannot load a valid online key")
