# SPDX-FileCopyrightText: 2023-2025 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import os
import tempfile
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from repository_service_tuf_worker.models.targets import Base
from repository_service_tuf_worker.repository import MetadataRepository
from repository_service_tuf_worker import repository
from dynaconf import Dynaconf

@pytest.fixture
def mock_dynaconf_settings(monkeypatch):
    """Provides a mocked Dynaconf with SQLite and LocalStorage."""
    with tempfile.TemporaryDirectory() as temp_dir:
        test_settings = Dynaconf(
            envvar_prefix="RSTUF",
            settings_files=[],
        )
        test_settings.update({
            "DB_SERVER": "sqlite:///:memory:",
            "REDIS_SERVER": "redis://localhost:6379",
            "STORAGE_BACKEND": "LocalStorage",
            "LOCAL_STORAGE_BACKEND_PATH": temp_dir,
            "KEYVAULT_BACKEND": "LocalAuth",
        })
        
        # Patch the global get_worker_settings in the repository module
        monkeypatch.setattr(repository, "get_worker_settings", lambda: test_settings)
        
        # Patch __init__ get_worker_settings so get_repository_settings uses our mock
        import repository_service_tuf_worker
        monkeypatch.setattr(repository_service_tuf_worker, "get_worker_settings", lambda: test_settings)
        
        # In-memory DB setup for the repository
        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=engine)
        
        # Patch the global rstuf_db to use our engine's session
        TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        def fake_rstuf_db(*args, **kwargs):
            return TestingSessionLocal()
            
        monkeypatch.setattr(repository, "rstuf_db", fake_rstuf_db)
        
        yield test_settings

class TestMetadataRepositoryIntegration:
    def test_repository_initialization_with_local_storage(self, mock_dynaconf_settings):
        # Full initialization without mocks for the internal parts
        repo = MetadataRepository.create_service()
        
        assert repo is not None
        assert repo._worker_settings is not None
        
        # It should have instantiated a LocalStorage backend correctly
        assert hasattr(repo, "_storage_backend")
        assert repo._storage_backend.__class__.__name__ == "LocalStorage"
        
        # The storage path should be our temporary directory
        storage_path = mock_dynaconf_settings.get("LOCAL_STORAGE_BACKEND_PATH")
        assert repo._storage_backend._path == storage_path

    def test_repository_refresh_settings(self, mock_dynaconf_settings):
        repo = MetadataRepository.create_service()
        
        # Verify settings refresh works correctly
        repo.refresh_settings(mock_dynaconf_settings)
        assert repo._worker_settings.get("STORAGE_BACKEND").__name__ == "LocalStorage"
