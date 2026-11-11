# SPDX-FileCopyrightText: 2023-2025 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import os
import tempfile
import pytest

from dynaconf import Dynaconf
from tuf.api.metadata import Metadata, Timestamp, Snapshot

from repository_service_tuf_worker.services.storage.local import LocalStorage

def test_local_storage_integration():
    """
    Tests that the LocalStorage backend can properly configure itself,
    save TUF metadata files (put), and read/deserialize them (get)
    from a real filesystem without mocks.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        # 1. Test configuration parsing
        test_settings = Dynaconf(
            envvar_prefix="RSTUF",
            settings_files=[],
        )
        test_settings.update({
            "LOCAL_STORAGE_BACKEND_PATH": temp_dir,
        })
        
        storage = LocalStorage.configure(test_settings)
        
        # 2. Test 'put' operations with real TUF Metadata payloads
        timestamp_metadata = Metadata(Timestamp())
        timestamp_bytes = timestamp_metadata.to_bytes()
        
        snapshot_metadata_v1 = Metadata(Snapshot())
        snapshot_v1_bytes = snapshot_metadata_v1.to_bytes()
        
        # Modify version to simulate a new snapshot version
        snapshot_metadata_v2 = Metadata(Snapshot())
        snapshot_metadata_v2.signed.version = 2
        snapshot_v2_bytes = snapshot_metadata_v2.to_bytes()
        
        # Put timestamp (unversioned, usually just timestamp.json)
        storage.put(timestamp_bytes, "timestamp.json")
        
        # Put snapshots (versioned)
        storage.put(snapshot_v1_bytes, "1.snapshot.json")
        storage.put(snapshot_v2_bytes, "2.snapshot.json")
        
        # 3. Test 'get' operations
        # Timestamp role has special handling (no versioning)
        retrieved_timestamp = storage.get("timestamp")
        assert retrieved_timestamp.signed.version == 1
        assert retrieved_timestamp.signed._type == "timestamp"
        
        # Snapshot role with specific version
        retrieved_snapshot_v1 = storage.get("snapshot", version=1)
        assert retrieved_snapshot_v1.signed.version == 1
        assert retrieved_snapshot_v1.signed._type == "snapshot"
        
        # Snapshot role without specific version (should resolve to highest version)
        retrieved_snapshot_latest = storage.get("snapshot")
        assert retrieved_snapshot_latest.signed.version == 2
        assert retrieved_snapshot_latest.signed._type == "snapshot"
        
        # 4. Verify physical files are actually there
        assert os.path.isfile(os.path.join(temp_dir, "timestamp.json"))
        assert os.path.isfile(os.path.join(temp_dir, "1.snapshot.json"))
        assert os.path.isfile(os.path.join(temp_dir, "2.snapshot.json"))
