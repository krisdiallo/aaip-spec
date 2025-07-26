"""
Tests for AAIP cryptographic functionality.

Run with: python -m pytest test_crypto.py
"""

import pytest

# Import AAIP core modules
from aaip.core import (
    AAIPCrypto,
    generate_keypair,
    serialize_canonical,
    create_signed_delegation,
    verify_delegation,
    SignatureError,
    DelegationError
)


class TestCryptographicOperations:
    """Test cryptographic operations."""
    
    def test_generate_keypair(self):
        """Test Ed25519 keypair generation."""
        private_key, public_key = generate_keypair()
        
        assert isinstance(private_key, str)
        assert isinstance(public_key, str)
        assert len(private_key) == 64  # 32 bytes * 2 (hex)
        assert len(public_key) == 64   # 32 bytes * 2 (hex)
        
        # Generate another pair and ensure they're different
        private_key2, public_key2 = generate_keypair()
        assert private_key != private_key2
        assert public_key != public_key2
    
    def test_canonical_serialization(self):
        """Test canonical JSON serialization."""
        test_data = {
            "z_last": "value",
            "a_first": "value",
            "nested": {
                "z_nested": "value",
                "a_nested": "value"
            }
        }
        
        canonical = serialize_canonical(test_data)
        expected = '{"a_first":"value","nested":{"a_nested":"value","z_nested":"value"},"z_last":"value"}'
        assert canonical == expected
    
    def test_sign_and_verify_delegation(self):
        """Test signing and verifying delegations."""
        private_key, public_key = generate_keypair()
        
        delegation_data = {
            "aaip_version": "1.0",
            "delegation": {
                "id": "del_test_001",
                "issuer": {
                    "identity": "user@example.com",
                    "identity_system": "oauth",
                    "public_key": public_key
                },
                "subject": {
                    "identity": "test_agent",
                    "identity_system": "custom"
                },
                "scope": ["payments:authorize"],
                "constraints": {"max_amount": {"value": 500.0, "currency": "USD"}},
                "issued_at": "2025-07-24T10:00:00Z",
                "expires_at": "2025-07-24T18:00:00Z",
                "not_before": "2025-07-24T10:00:00Z"
            }
        }
        
        # Sign the delegation
        signature = AAIPCrypto.sign_delegation(delegation_data, private_key)
        
        # Verify the signature
        assert AAIPCrypto.verify_delegation_signature(delegation_data, signature, public_key) is True
        
        # Test with wrong public key
        wrong_private, wrong_public = generate_keypair()
        assert AAIPCrypto.verify_delegation_signature(delegation_data, signature, wrong_public) is False
    
    def test_create_signed_delegation(self):
        """Test creating a complete signed delegation."""
        private_key, public_key = generate_keypair()
        
        constraints = {"max_amount": {"value": 500.0, "currency": "USD"}}
        delegation = create_signed_delegation(
            issuer_identity="user@example.com",
            issuer_identity_system="custom",
            issuer_private_key=private_key,
            subject_identity="test_agent",
            subject_identity_system="custom",
            scope=["payments:authorize"],
            expires_at="2025-08-24T10:00:00Z",
            not_before="2025-07-25T10:00:00Z",
            constraints=constraints
        )
        
        # Verify structure
        assert "aaip_version" in delegation
        assert "delegation" in delegation
        assert "signature" in delegation
        
        # Verify delegation content
        del_data = delegation["delegation"]
        assert del_data["issuer"]["id"] == "user@example.com"
        assert del_data["subject"]["id"] == "test_agent"
        assert del_data["scope"] == ["payments:authorize"]
        assert del_data["constraints"]["max_amount"]["value"] == 500.0
        
        # Verify delegation is valid
        assert verify_delegation(delegation) is True
    
    def test_verify_delegation_complete(self):
        """Test complete delegation verification."""
        private_key, public_key = generate_keypair()
        
        # Create a signed delegation
        delegation = create_signed_delegation(
            issuer_identity="user@example.com",
            issuer_identity_system="custom",
            issuer_private_key=private_key,
            subject_identity="test_agent",
            subject_identity_system="custom",
            scope=["payments:authorize"],
            expires_at="2025-08-24T10:00:00Z",
            not_before="2025-07-25T10:00:00Z"
        )
        
        # Verify the delegation
        assert verify_delegation(delegation) is True
        
        # Test with modified delegation (should fail)
        modified_delegation = delegation.copy()
        modified_delegation["delegation"]["scope"] = ["email:send"]  # Modify scope
        assert verify_delegation(modified_delegation) is False


class TestCryptographicErrorHandling:
    """Test cryptographic error handling."""
    
    def test_invalid_signature_format(self):
        """Test handling of invalid signature formats."""
        delegation_data = {
            "aaip_version": "1.0", 
            "delegation": {
                "id": "del_test_001",
                "issuer": {"identity": "user", "identity_system": "custom", "public_key": "invalid"},
                "subject": {"identity": "agent", "identity_system": "custom"},
                "scope": ["test"],
                "issued_at": "2025-07-24T10:00:00Z",
                "expires_at": "2025-07-24T18:00:00Z",
                "not_before": "2025-07-24T10:00:00Z"
            },
            "signature": "invalid_signature"
        }
        
        assert AAIPCrypto.verify_delegation_signature(delegation_data, "fake_sig", "invalid_public_key") is False
    
    def test_invalid_private_key(self):
        """Test handling of invalid private keys."""
        delegation_data = {
            "aaip_version": "1.0",
            "delegation": {
                "id": "del_test_001",
                "issuer": {"identity": "user", "identity_system": "custom"},
                "subject": {"identity": "agent", "identity_system": "custom"},
                "scope": ["test"],
                "issued_at": "2025-07-24T10:00:00Z",
                "expires_at": "2025-07-24T18:00:00Z",
                "not_before": "2025-07-24T10:00:00Z"
            }
        }
        
        with pytest.raises(SignatureError):
            AAIPCrypto.sign_delegation(delegation_data, "invalid_private_key")
    
    def test_missing_signature(self):
        """Test handling of delegations without signatures."""
        delegation_data = {
            "aaip_version": "1.0",
            "delegation": {
                "id": "del_test_001",
                "issuer": {"identity": "user", "identity_system": "custom", "public_key": "test"},
                "subject": {"identity": "agent", "identity_system": "custom"},
                "scope": ["test"],
                "issued_at": "2025-07-24T10:00:00Z",
                "expires_at": "2025-07-24T18:00:00Z",
                "not_before": "2025-07-24T10:00:00Z"
            }
            # No signature field
        }
        
        assert verify_delegation(delegation_data) is False


class TestAAIPCrypto:
    """Test AAIPCrypto class functionality."""
    
    def test_crypto_instance(self):
        """Test AAIPCrypto instance creation and methods."""
        crypto = AAIPCrypto()
        
        # Test keypair generation
        private_key, public_key = crypto.generate_keypair()
        assert isinstance(private_key, str)
        assert isinstance(public_key, str)
        
        # Test delegation signing and verification
        delegation_data = {
            "aaip_version": "1.0",
            "delegation": {
                "id": "del_test_001",
                "issuer": {"identity": "user", "identity_system": "custom"},
                "subject": {"identity": "agent", "identity_system": "custom"},
                "scope": ["test"],
                "issued_at": "2025-07-24T10:00:00Z",
                "expires_at": "2025-07-24T18:00:00Z",
                "not_before": "2025-07-24T10:00:00Z"
            }
        }
        
        signature = crypto.sign_delegation(delegation_data, private_key)
        assert isinstance(signature, str)
        
        # Test verification
        assert crypto.verify_delegation_signature(delegation_data, signature, public_key) is True
        
        # Test with wrong public key
        wrong_private, wrong_public = crypto.generate_keypair()
        assert crypto.verify_delegation_signature(delegation_data, signature, wrong_public) is False


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_empty_delegation_data(self):
        """Test handling of empty delegation data."""
        assert verify_delegation({}) is False
    
    def test_malformed_delegation_structure(self):
        """Test handling of malformed delegation structures."""
        malformed_delegation = {
            "aaip_version": "1.0",
            # Missing delegation field
            "signature": "test_signature"
        }
        
        assert verify_delegation(malformed_delegation) is False
    
    def test_unicode_in_delegation(self):
        """Test handling of unicode characters in delegation data."""
        private_key, public_key = generate_keypair()
        
        delegation = create_signed_delegation(
            issuer_identity="用户@example.com",  # Unicode characters
            issuer_identity_system="custom",
            issuer_private_key=private_key,
            subject_identity="тест_агент",  # Cyrillic characters
            subject_identity_system="custom",
            scope=["测试:授权"],  # Chinese characters
            expires_at="2025-08-24T10:00:00Z",
            not_before="2025-07-25T10:00:00Z"
        )
        
        # Should handle unicode properly
        assert verify_delegation(delegation) is True
    
    def test_large_delegation_data(self):
        """Test handling of large delegation data."""
        private_key, public_key = generate_keypair()
        
        # Create delegation with large constraint data
        large_constraints = {
            "max_amount": {"value": 500.0, "currency": "USD"},
            "large_list": ["item_" + str(i) for i in range(1000)],  # Large list
            "large_dict": {f"key_{i}": f"value_{i}" for i in range(100)}  # Large dict
        }
        
        delegation = create_signed_delegation(
            issuer_identity="user@example.com",
            issuer_identity_system="custom",
            issuer_private_key=private_key,
            subject_identity="test_agent",
            subject_identity_system="custom",
            scope=["payments:authorize"],
            expires_at="2025-08-24T10:00:00Z",
            not_before="2025-07-25T10:00:00Z",
            constraints=large_constraints
        )
        
        # Should handle large data properly
        assert verify_delegation(delegation) is True