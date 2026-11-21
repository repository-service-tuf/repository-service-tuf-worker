# SPDX-FileCopyrightText: 2023-2025 Repository Service for TUF Contributors
#
# SPDX-License-Identifier: MIT

import os
import tempfile
import pytest

from securesystemslib.signer import CryptoSigner
from dynaconf import Dynaconf
from repository_service_tuf_worker.signer import SignerStore

def test_local_file_signer_integration():
    """
    Tests that SignerStore can correctly initialize and use a local file signer
    via securesystemslib without heavy mocking.
    """
    # Create a real ed25519 key pair for testing
    crypto_signer = CryptoSigner.generate_ed25519()
    
    with tempfile.TemporaryDirectory() as temp_dir:
        key_path = os.path.join(temp_dir, "test_key")
        
        # We save the private key so the SignerStore can load it
        # securesystemslib expects an unencrypted PEM file format (or similar based on signer)
        # Note: We must write it out correctly.
        with open(key_path, "wb") as f:
            f.write(crypto_signer.private_bytes)
            
        uri = "fn:test_key"
        
        # Setup settings
        test_settings = Dynaconf(
            envvar_prefix="RSTUF",
            settings_files=[],
        )
        test_settings.update({
            "ONLINE_KEY_URI": uri,
            "ONLINE_KEY_DIR": temp_dir,
        })
        
        # Initialize SignerStore
        store = SignerStore(test_settings)
        
        # Get the signer object (this will load it from disk via SSlibSigner/CryptoSigner)
        # SignerStore expects a TUF Key object containing the 'x-rstuf-online-key-uri'
        tuf_key = crypto_signer.public_key
        tuf_key.unrecognized_fields["x-rstuf-online-key-uri"] = uri
        signer = store.get(tuf_key)
        
        # Verify the signer can actually sign data!
        test_data = b"hello integration test"
        signature = signer.sign(test_data)
        
        # Validate the signature
        assert signature.signature is not None
        assert signature.keyid == signer.public_key.keyid
        
        # Attempt to verify the signature using the public key
        signer.public_key.verify_signature(signature, test_data)
