# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT

import os
from typing import Any, Dict, List, Optional

from dynaconf import Dynaconf, loaders
from dynaconf.utils.boxing import DynaBox
from dynaconf.vendor.box.exceptions import BoxKeyError
from securesystemslib.keys import decrypt_key, encrypt_key

from repository_service_tuf_worker.interfaces import IKeyVault, ServiceSettings


class KeyVaultError(Exception):
    pass


class LocalKeyVault(IKeyVault):
    """Local KeyVault type"""

    def __init__(
        self,
        path: str,
        online_key_name: Optional[str] = "online.key",
        online_key_pass: Optional[str] = None,
        online_key_type: Optional[str] = "ed25519",
    ):
        """Configuration class for RSTUF Worker LocalKeyVault service.

        Args:
            path: directory of the key vault.
            online_key_name: file name of the online key.
            online_key_pass: password to load the online key.
            online_key_type: cryptography type of the online key.
        """
        self._path: str = path
        self._secrets_file: str = os.path.join(self._path, ".secrets.yaml")
        self._online_key_name: Optional[str] = online_key_name
        self._online_key_password: Optional[str] = online_key_pass
        self._online_key_type: Optional[str] = online_key_type
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
                name="LOCAL_KEYVAULT_ONLINE_KEY_NAME",
                argument="online_key_name",
                required=False,
            ),
            ServiceSettings(
                name="LOCAL_KEYVAULT_ONLINE_KEY_PASSWORD",
                argument="online_key_pass",
                required=False,
            ),
            ServiceSettings(
                name="LOCAL_KEYVAULT_ONLINE_KEY_TYPE",
                argument="online_key_type",
                required=False,
            ),
        ]

    def get(self, rolename: str) -> Dict[str, Any]:
        """Get the Key from local KeyVault by role name."""
        keys_sslib_format: List[Dict[str, Any]] = []
        try:
            keys: Dict[str, Any] = self.keyvault.store[rolename]
            for key in keys:
                keys_sslib_format.append(
                    decrypt_key(key["key"], key["password"])
                )
        except (BoxKeyError, KeyError):
            raise KeyVaultError(f"{rolename} key(s) not found.")

        return keys_sslib_format

    def put(self, rolename: str, keys: List[Dict[str, Any]]) -> None:
        """Save the Key in the local KeyVault."""
        key_vault_data: list = []
        for key in keys:
            ed25519_key = encrypt_key(key.get("key"), key.get("password"))
            key_vault_data.append(
                {
                    "key": ed25519_key,
                    "filename": key["filename"].split("/")[-1],
                    "password": key["password"],
                }
            )

        self.keyvault.store[rolename.upper()] = key_vault_data
        data = self.keyvault.as_dict(env=self.keyvault.current_env)
        loaders.write(self._secrets_file, DynaBox(data).to_dict())
