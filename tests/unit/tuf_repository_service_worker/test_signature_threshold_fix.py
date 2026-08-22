import pretend
import pytest
from tuf.api.metadata import Metadata, Root, VerificationResult
from tuf.api.exceptions import UnsignedMetadataError, RepositoryError
from repository_service_tuf_worker import repository

@pytest.fixture()
def signature_test_repo(monkeypatch):
    """A minimal test_repo for signature threshold tests."""
    # Mock __init__ to avoid settings/storage issues
    monkeypatch.setattr(repository.MetadataRepository, "__init__", lambda *a: None)
    repo = repository.MetadataRepository()
    return repo

class TestSignatureThresholdFix:
    def test_validate_threshold_returns_verification_result(self, signature_test_repo, monkeypatch):
        """Test that _validate_threshold returns a VerificationResult (#367)."""
        # Create a mock root with a threshold
        metadata = Metadata(Root())
        metadata.signed.threshold = 2
        metadata.signatures = {"key1": pretend.stub()}
        
        # Mock get_verification_result to return a result
        mock_result = VerificationResult(
            threshold=2,
            signed={"key1": pretend.stub()},
            unsigned={"key2": pretend.stub()}
        )
        
        monkeypatch.setattr(
            metadata.signed, "get_verification_result", 
            lambda *a: mock_result
        )
        
        result = signature_test_repo._validate_threshold(metadata)
        
        assert isinstance(result, VerificationResult)
        assert result.threshold == 2
        assert len(result.signed) == 1
        assert result.missing == 1
        assert bool(result) is False

    def test_root_metadata_update_sanity_check(self, signature_test_repo, monkeypatch):
        """Test that _root_metadata_update enforces at least one valid signature."""
        
        # Mock required attributes and methods manually
        monkeypatch.setattr(signature_test_repo, "_storage_load_root", pretend.call_recorder(lambda *a: Metadata(Root())))
        monkeypatch.setattr(signature_test_repo, "write_repository_settings", pretend.call_recorder(lambda *a: None))
        monkeypatch.setattr(signature_test_repo, "_task_result", pretend.call_recorder(lambda **kwargs: kwargs) )
        
        # New root with NO signatures
        new_root = Metadata(Root())
        new_root.signatures = {} 
        
        # Mock _verify_new_root_signing to raise UnsignedMetadataError
        monkeypatch.setattr(
            signature_test_repo, "_verify_new_root_signing",
            pretend.call_recorder(pretend.raiser(UnsignedMetadataError("Missing signatures")))
        )
        
        # Call and expect RepositoryError
        with pytest.raises(RepositoryError, match="has no valid signatures"):
            signature_test_repo._root_metadata_update(new_root)
        
        # Ensure settings were NOT written
        assert signature_test_repo.write_repository_settings.calls == []

    def test_root_metadata_update_with_one_signature(self, signature_test_repo, monkeypatch):
        """Test that _root_metadata_update accepts a root with at least one signature (even if threshold not met)."""
        monkeypatch.setattr(signature_test_repo, "_storage_load_root", pretend.call_recorder(lambda *a: Metadata(Root())))
        monkeypatch.setattr(signature_test_repo, "write_repository_settings", pretend.call_recorder(lambda *a: None))
        monkeypatch.setattr(signature_test_repo, "_task_result", pretend.call_recorder(lambda **kwargs: kwargs))
        
        # New root with at least one signature
        new_root = Metadata(Root())
        new_root.signatures = {"key1": pretend.stub()} 
        # Mock to_dict and version to avoid issues with stubs/empty objects
        monkeypatch.setattr(new_root, "to_dict", lambda: {})
        
        # Mock _verify_new_root_signing to raise UnsignedMetadataError
        monkeypatch.setattr(
            signature_test_repo, "_verify_new_root_signing",
            pretend.call_recorder(pretend.raiser(UnsignedMetadataError("Missing signatures")))
        )
        
        # Mock _validate_threshold to return a result with 1 signature
        mock_result = VerificationResult(
            threshold=2,
            signed={"key1": pretend.stub()},
            unsigned={"key2": pretend.stub()}
        )
        monkeypatch.setattr(
            signature_test_repo, "_validate_threshold",
            lambda *a: mock_result
        )
        
        signature_test_repo._root_metadata_update(new_root)
        
        # Ensure settings WERE written (pending state)
        assert len(signature_test_repo.write_repository_settings.calls) == 1
