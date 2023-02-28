# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import os
from typing import Any, Dict, List

from dynaconf import Dynaconf, loaders
from dynaconf.utils.boxing import DynaBox
from dynaconf.vendor.box.exceptions import BoxKeyError
from securesystemslib.keys import decrypt_key, encrypt_key

from repository_service_tuf_worker.interfaces import IKeyVault, ServiceSettings


class KeyVaultError(Exception):
    pass


class LocalKeyVault(IKeyVault):
    """Local KeyVault type"""

    def __init__(self, path: str):
        self._path: str = path
        self._secrets_file: str = os.path.join(self._path, ".secrets.yaml")
        self.keyvault = Dynaconf(
            envvar_prefix="LOCALKEYVAULT",
            settings_files=[self._secrets_file],
        )

    @classmethod
    def configure(cls, settings):
        """Configure using the settings."""
        os.makedirs(settings.LOCAL_KEYVAULT_PATH, exist_ok=True)

    @classmethod
    def settings(cls):
        """Define the settings parameters."""
        return [
            ServiceSettings(
                name="LOCAL_KEYVAULT_PATH",
                argument="path",
                required=True,
            ),
        ]

    def get(self, rolename: str):
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

    def put(self, rolename: str, keys: List[Dict[str, Any]]):
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
