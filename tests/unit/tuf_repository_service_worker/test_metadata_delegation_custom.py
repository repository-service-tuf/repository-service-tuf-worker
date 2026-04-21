# SPDX-FileCopyrightText: 2025 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import pretend
import pytest
from tuf.api.metadata import (
    Metadata,
    Targets,
    DelegatedRole,
    Delegations,
    MetaFile,
    Snapshot
)
from repository_service_tuf_worker import repository
from repository_service_tuf_worker.repository import TaskName

class TestMetadataDelegationCustom:
    @pytest.fixture()
    def test_repo(self, monkeypatch):
        # Mock dependencies to avoid real initialization
        mock_settings = pretend.stub(
            get_fresh=lambda k, d=None: None,
            get=lambda k, d=None: "redis://localhost" if "REDIS" in k else "postgresql://localhost",
            KEYVAULT_BACKEND="local",
            STORAGE_BACKEND="local",
        )
        monkeypatch.setattr(repository, "get_worker_settings", lambda: mock_settings)
        monkeypatch.setattr(repository, "get_repository_settings", lambda *a: mock_settings)
        monkeypatch.setattr(repository, "rstuf_db", lambda *a: pretend.stub())
        
        repo = repository.MetadataRepository.__new__(repository.MetadataRepository)
        repo._db = pretend.stub()
        repo._signer_store = pretend.stub()
        repo._storage_backend = pretend.stub()
        repo._timeout = 30
        repo._uses_succinct_roles = None
        
        # Monkeypatch properties if needed, but since they call get_repository_settings,
        # and we mocked it, it should be fine. Actually, _settings is just a property.
        
        return repo

    def test_metadata_delegation_add_custom(self, test_repo, monkeypatch):
        """Test metadata_delegation 'add' with externally signed metadata"""
        import datetime
        rolename = "dev"
        # Mock pre-signed metadata with FUTURE expiration
        signed_md = Metadata(Targets(version=2))
        signed_md.signed.expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        payload = {
            "action": "add",
            "rolename": rolename,
            "metadata": signed_md.to_dict()
        }

        # Mock targets with delegation
        delegated_role = DelegatedRole(
            name=rolename,
            keyids=["k1"],
            threshold=1,
            terminating=False,
            paths=["*"]
        )
        targets = Metadata(Targets())
        targets.signed.delegations = Delegations(
            keys={"k1": pretend.stub()},
            roles={rolename: delegated_role}
        )
        test_repo._storage_load_targets = pretend.call_recorder(lambda: targets)

        # Mock validation
        test_repo._validate_threshold = pretend.call_recorder(
            lambda md, delegator, role: True
        )

        # Mock persistence
        test_repo._persist = pretend.call_recorder(lambda md, role: None)

        # Mock storage backend get for version check (not found = new role)
        from securesystemslib.exceptions import StorageError
        def raise_storage_error(name):
            raise StorageError("Not found")
        test_repo._storage_backend = pretend.stub(
            get=pretend.call_recorder(raise_storage_error)
        )
        # Mock snapshot update
        snapshot = Metadata(Snapshot())
        test_repo._storage_load_snapshot = pretend.call_recorder(
            lambda: snapshot
        )
        test_repo._bump_and_persist = pretend.call_recorder(
            lambda md, role: None
        )
        test_repo._update_timestamp = pretend.call_recorder(
            lambda version: None
        )

        # Mock DB update
        monkeypatch.setattr(
            repository.targets_crud,
            "update_roles_expire_version_by_rolenames",
            pretend.call_recorder(lambda db, meta: None)
        )

        # Run action
        result = test_repo.metadata_delegation(payload)

        # Verify results
        assert result["status"] is True
        assert result["task"] == TaskName.METADATA_DELEGATION
        assert rolename in result["details"]["delegated_roles"]

        # Verify mocks
        assert len(test_repo._storage_load_targets.calls) == 1
        assert len(test_repo._validate_threshold.calls) == 1
        # Check second and third args for validate_threshold
        assert test_repo._validate_threshold.calls[0].args[1] == targets
        assert test_repo._validate_threshold.calls[0].args[2] == rolename

        assert len(test_repo._persist.calls) == 1
        assert test_repo._persist.calls[0].args[1] == rolename

        assert len(test_repo._storage_load_snapshot.calls) == 1
        assert test_repo._bump_and_persist.calls == [
            pretend.call(snapshot, Snapshot.type)
        ]
        assert test_repo._update_timestamp.calls == [
            pretend.call(snapshot.signed.version)
        ]
        assert repository.targets_crud.update_roles_expire_version_by_rolenames.calls == [
            pretend.call(
                test_repo._db,
                {
                    rolename: (
                        signed_md.signed.expires,
                        signed_md.signed.version
                    )
                }
            )
        ]

    def test_metadata_delegation_add_custom_not_delegated(self, test_repo):
        """Test metadata_delegation 'add' custom fails if not delegated"""
        import datetime
        rolename = "dev"
        signed_md = Metadata(Targets(version=2))
        signed_md.signed.expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        payload = {
            "action": "add",
            "rolename": rolename,
            "metadata": signed_md.to_dict()
        }

        # Mock targets WITHOUT delegation
        targets = Metadata(Targets())
        targets.signed.delegations = Delegations(keys={}, roles={})
        test_repo._storage_load_targets = pretend.call_recorder(lambda: targets)

        with pytest.raises(repository.RepositoryError) as e:
            test_repo.metadata_delegation(payload)
        
        assert f"Role '{rolename}' is not delegated in Targets" in str(e.value)

    def test_metadata_delegation_add_custom_invalid_threshold(self, test_repo):
        """Test metadata_delegation 'add' custom fails if threshold not met"""
        import datetime
        rolename = "dev"
        signed_md = Metadata(Targets(version=2))
        signed_md.signed.expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        payload = {
            "action": "add",
            "rolename": rolename,
            "metadata": signed_md.to_dict()
        }

        # Mock targets with delegation
        targets = Metadata(Targets())
        targets.signed.delegations = Delegations(
            keys={"k1": pretend.stub()},
            roles={rolename: pretend.stub()}
        )
        test_repo._storage_load_targets = pretend.call_recorder(lambda: targets)

        # Mock validation FAILURE
        test_repo._validate_threshold = pretend.call_recorder(
            lambda md, delegator, role: False
        )

        with pytest.raises(repository.RepositoryError) as e:
            test_repo.metadata_delegation(payload)
        
        assert f"Metadata for '{rolename}' does not meet the threshold" in str(e.value)

    def test_metadata_delegation_add_custom_expired(self, test_repo):
        """Test metadata_delegation 'add' custom fails if expired"""
        import datetime
        rolename = "dev"
        # Metadata expires in the past
        signed_md = Metadata(Targets(version=2))
        signed_md.signed.expires = datetime.datetime(2018, 1, 1, tzinfo=datetime.timezone.utc)
        
        payload = {
            "action": "add",
            "rolename": rolename,
            "metadata": signed_md.to_dict()
        }

        # Mock targets with delegation
        targets = Metadata(Targets())
        targets.signed.delegations = Delegations(
            keys={"k1": pretend.stub()},
            roles={rolename: pretend.stub()}
        )
        test_repo._storage_load_targets = pretend.call_recorder(lambda: targets)
        test_repo._validate_threshold = pretend.call_recorder(lambda md, d, r: True)

        with pytest.raises(repository.RepositoryError) as e:
            test_repo.metadata_delegation(payload)
        
        assert f"Metadata for '{rolename}' is expired" in str(e.value)

    def test_metadata_delegation_add_custom_lower_version(self, test_repo):
        """Test metadata_delegation 'add' custom fails if version is lower"""
        import datetime
        rolename = "dev"
        signed_md = Metadata(Targets(version=1)) # New version 1
        signed_md.signed.expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        payload = {
            "action": "add",
            "rolename": rolename,
            "metadata": signed_md.to_dict()
        }

        # Mock targets with delegation
        targets = Metadata(Targets())
        targets.signed.delegations = Delegations(
            keys={"k1": pretend.stub()},
            roles={rolename: pretend.stub()}
        )
        test_repo._storage_load_targets = pretend.call_recorder(lambda: targets)
        test_repo._validate_threshold = pretend.call_recorder(lambda md, d, r: True)

        # Mock existing metadata with version 2
        current_md = Metadata(Targets(version=2))
        test_repo._storage_backend = pretend.stub(
            get=pretend.call_recorder(lambda name: current_md)
        )

        with pytest.raises(repository.RepositoryError) as e:
            test_repo.metadata_delegation(payload)
        
        assert "is lower than current version 2" in str(e.value)
