# SPDX-FileCopyrightText: 2022-2023 VMware Inc
#
# SPDX-License-Identifier: MIT


from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List

from tuf.api.metadata import Metadata, T


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


class IStorage(ABC):
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
        file_data: bytes,
        filename: str,
    ) -> None:
        """
        Stores file bytes within a file with a specific filename.
        """
        raise NotImplementedError  # pragma: no cover
