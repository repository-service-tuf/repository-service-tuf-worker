# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT

import glob
import os
import shutil
from contextlib import contextmanager
from io import BufferedReader, TextIOBase
from typing import List

from securesystemslib.exceptions import StorageError  # noqa

from repository_service_tuf_worker.interfaces import IStorage, ServiceSettings
from repository_service_tuf_worker.repository import Timestamp


class LocalStorage(IStorage):
    def __init__(self, path: str) -> None:
        self._path: str = path

    @classmethod
    def configure(cls, settings) -> None:
        os.makedirs(settings.LOCAL_STORAGE_BACKEND_PATH, exist_ok=True)

    @classmethod
    def settings(cls) -> List[ServiceSettings]:
        return [
            ServiceSettings(
                name="LOCAL_STORAGE_BACKEND_PATH",
                argument="path",
                required=True,
            ),
        ]

    @contextmanager
    def get(self, role, version=None) -> BufferedReader:
        """
        Yields TUF role metadata file object for the passed role name, from the
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
            yield file_object
        except OSError:
            raise StorageError(f"Can't open Role '{role}'")
        finally:
            if file_object is not None:
                file_object.close()

    def put(self, file_object: TextIOBase, filename: str) -> None:
        """
        Writes passed file object to configured TUF repo path using the passed
        filename.
        """
        file_path = os.path.join(self._path, filename)
        if not file_object.closed:
            file_object.seek(0)

        try:
            with open(file_path, "wb") as destination_file:
                shutil.copyfileobj(file_object, destination_file)
                destination_file.flush()
                os.fsync(destination_file.fileno())
        except OSError:
            raise StorageError(f"Can't write role file '{filename}'")
