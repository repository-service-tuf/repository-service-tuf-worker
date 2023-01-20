# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from abc import ABC, abstractmethod
from dataclasses import dataclass
from io import TextIOBase
from typing import Any, Dict, List, Optional

from tuf.api.metadata import (  # type: ignore
    Metadata,
    StorageBackendInterface,
    T,
)


@dataclass
class ServiceSettings:
    """Dataclass for service settings."""

    name: str
    argument: str
    required: bool


class IKeyVault(ABC):
    @classmethod
    @abstractmethod
    def configure(cls, settings):
        """
        Run actions to test, configure using the settings.
        """
        pass  # pragma: no cover

    @classmethod
    @abstractmethod
    def settings(cls):
        """
        Define all the ServiceSettings required in settings.
        """
        pass  # pragma: no cover

    @abstractmethod
    def get(self, rolename: List[str]) -> Dict[str, Any]:
        """Return a key from specific rolename."""
        pass  # pragma: no cover

    @abstractmethod
    def put(self, file_object: str, filename: str) -> None:
        """
        Stores file object with a specific filename.
        """
        pass  # pragma: no cover


class IStorage(StorageBackendInterface):
    @classmethod
    @abstractmethod
    def configure(cls, settings: Any):
        """
        Run actions to test, configure using the settings.
        """
        raise NotImplementedError  # pragma: no cover

    @classmethod
    @abstractmethod
    def settings(cls) -> List[ServiceSettings]:
        """
        Define all the ServiceSettings required in settings.
        """
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def get(self, rolename: str, version: int) -> "Metadata[T]":
        """
        Return metadata from specific role name, optionally specific version.
        """
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def put(
        self,
        file_object: TextIOBase,
        filename: str,
        restrict: Optional[bool] = True,
    ) -> None:
        """
        Stores file object with a specific filename.
        """
        raise NotImplementedError  # pragma: no cover
