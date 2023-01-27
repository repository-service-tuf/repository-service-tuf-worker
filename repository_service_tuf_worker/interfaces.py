# SPDX-FileCopyrightText: 2022 VMware Inc
#
# SPDX-License-Identifier: MIT


from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, List, Optional

from securesystemslib.signer import Key, Signer
from tuf.api.metadata import Metadata, T


@dataclass
class ServiceSettings:
    """Dataclass for service settings."""

    name: str
    argument: str
    required: bool
    default: Optional[Any] = None


class IKeyVault(ABC):
    @classmethod
    @abstractmethod
    def configure(cls, settings) -> None:
        """
        Run actions to check and configure the service using the settings.
        """
        pass  # pragma: no cover

    @classmethod
    @abstractmethod
    def settings(cls) -> List[ServiceSettings]:
        """
        Define all the ServiceSettings required in settings.
        """
        pass  # pragma: no cover

    @abstractmethod
    def get(self, public_key: Key) -> Signer:
        """Return a signer using the online key."""
        pass  # pragma: no cover


class IStorage(ABC):
    @classmethod
    @abstractmethod
    def configure(cls, settings: Any) -> None:
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
    def get(self, rolename: str, version: Optional[int]) -> Metadata[T]:
        """
        Return metadata from specific role name, optionally specific version
        (latest if None).
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
