# SPDX-FileCopyrightText: 2023 Repository Service for TUF Contributors
# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT

import glob
import os
from typing import List, Optional

from securesystemslib.exceptions import StorageError  # noqa
from tuf.api.metadata import Metadata, T, Timestamp
from tuf.api.serialization import DeserializationError

from repository_service_tuf_worker.interfaces import (
    Dynaconf,
    IStorage,
    ServiceSettings,
)
from repository_service_tuf_worker.otel_tracer import trace_function


class LocalStorage(IStorage):
    def __init__(self, path: str) -> None:
        self._path: str = path

    @classmethod
    @trace_function()
    def configure(cls, settings: Dynaconf) -> "LocalStorage":
        path = settings.get("LOCAL_STORAGE_BACKEND_PATH") or settings.get(
            "LOCAL_STORAGE_PATH"
        )
        os.makedirs(path, exist_ok=True)
        return cls(path)

    @classmethod
    @trace_function()
    def settings(cls) -> List[ServiceSettings]:
        return [
            ServiceSettings(
                names=["LOCAL_STORAGE_BACKEND_PATH", "LOCAL_STORAGE_PATH"],
                required=True,
            ),
        ]

    @trace_function()
    def get(self, role: str, version: Optional[int] = None) -> Metadata[T]:
        """
        Returns TUF role metadata object for the passed role name, from the
        configured TUF repo path, optionally at the passed version (latest if
        None).
        """

        if role == Timestamp.type:
            filename = os.path.join(self._path, f"{role}.json")
        else:
            if version is None:
                filenames = glob.glob(
                    os.path.join(self._path, f"*.{role}.json")
                )
                versions = [
                    int(name.split("/")[-1].split(".", 1)[0])
                    for name in filenames
                ]
                try:
                    version = max(versions)
                except ValueError:
                    version = 1

            filename = os.path.join(self._path, f"{version}.{role}.json")

        file_object = None
        try:
            file_object = open(filename, "rb")
            return Metadata.from_bytes(file_object.read())
        except (OSError, DeserializationError) as e:
            raise StorageError(f"Can't open Role '{role}'") from e
        finally:
            if file_object is not None:
                file_object.close()

    @trace_function()
    def put(
        self,
        file_data: bytes,
        filename: str,
    ) -> None:
        """
        Writes passed file object to configured TUF repo path using the passed
        filename.
        """
        filename = os.path.join(self._path, filename)

        try:
            with open(filename, "wb") as destination_file:
                destination_file.write(file_data)
                destination_file.flush()
                os.fsync(destination_file.fileno())
        except OSError:
            raise StorageError(f"Can't write role file '{filename}'")
