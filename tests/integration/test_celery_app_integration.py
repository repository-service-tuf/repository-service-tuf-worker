# SPDX-FileCopyrightText: 2023-2025 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import os
import tempfile
import pytest

from dynaconf import Dynaconf
import repository_service_tuf_worker

def test_celery_app_integration(monkeypatch):
    """
    Tests that the main Celery app in app.py can be fully initialized
    without heavy mocking, ensuring all tasks are registered correctly.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        # Provide valid test settings so the app initializes its repository
        # without failing on missing backend configs
        test_settings = Dynaconf(
            envvar_prefix="RSTUF",
            settings_files=[],
        )
        test_settings.update({
            "DB_SERVER": "sqlite:///:memory:",
            "REDIS_SERVER": "redis://localhost:6379",
            "BROKER_SERVER": "redis://localhost:6379",
            "STORAGE_BACKEND": "LocalStorage",
            "LOCAL_STORAGE_BACKEND_PATH": temp_dir,
            "KEYVAULT_BACKEND": "LocalAuth",
            "WORKER_ID": "test_worker_1",
        })
        
        # Patch the get_worker_settings globally before importing app
        monkeypatch.setattr(
            repository_service_tuf_worker, 
            "get_worker_settings", 
            lambda: test_settings
        )
        
        monkeypatch.setattr(
            "repository_service_tuf_worker.repository.get_worker_settings",
            lambda: test_settings
        )
        
        # In-memory DB setup
        from repository_service_tuf_worker.models.targets import Base
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        
        engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=engine)
        TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        
        def fake_rstuf_db(*args, **kwargs):
            return TestingSessionLocal()
            
        monkeypatch.setattr("repository_service_tuf_worker.repository.rstuf_db", fake_rstuf_db)

        # Now import the app safely
        import app
        
        # Check that the celery application is properly configured
        assert app.app is not None
        assert app.app.conf is not None
        
        # Check that the expected broker is set in the celery config
        # (Based on our REDIS_SERVER setting)
        assert app.app.conf.broker_url == "redis://localhost:6379"

        # Verify that all expected celery tasks have been successfully registered
        registered_tasks = app.app.tasks.keys()
        
        assert "app.repository_service_tuf_worker" in registered_tasks
        assert "app.bump_online_roles" in registered_tasks
        assert "app._update_online_role" in registered_tasks
        assert "app._update_snapshot_timestamp" in registered_tasks
        assert "app._end_bor_chain_callback" in registered_tasks
