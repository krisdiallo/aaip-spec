"""
Tests for AAIP delegation functionality.

Run with: python -m pytest test_delegation.py
"""

import pytest

# Import AAIP core modules
from aaip.core import (
    check_delegation_authorization,
)

# Import test utilities
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from utils import create_test_delegation_payload, create_test_delegation_with_signature


class TestDelegationCreation:
    """Test delegation creation and verification."""
    
    
    def test_delegation_authorization_check(self):
        """Test delegation authorization checking."""
        delegation_payload = create_test_delegation_payload(
            issuer_identity="user@example.com",
            issuer_identity_system="oauth",
            subject_identity="test_agent",
            subject_identity_system="custom",
            scope=["payments:authorize"],
            constraints={"max_amount": {"value": 500.0}}
        )
        
        # Create a complete delegation with test signature
        complete_delegation = create_test_delegation_with_signature(delegation_payload)
        
        # Test authorization check
        assert check_delegation_authorization(
            complete_delegation, 
            "payments", 
            "authorize"
        ) is True
        
        # Test with wrong scope
        assert check_delegation_authorization(
            complete_delegation, 
            "email", 
            "send"
        ) is False


class TestDelegationErrorHandling:
    """Test delegation-specific error handling."""
    
    def test_empty_scope(self):
        """Test error handling for empty scope."""
        with pytest.raises(ValueError):
            create_test_delegation_payload(
                issuer_identity="user@example.com",
                issuer_identity_system="oauth",
                subject_identity="test_agent",
                subject_identity_system="custom",
                scope=[]  # Empty scope should raise ValueError
            )
    
    def test_invalid_parameters(self):
        """Test error handling for invalid parameters."""
        # Test with empty issuer identity (this should raise ValueError from the internal function)
        with pytest.raises(ValueError):
            create_test_delegation_payload(
                issuer_identity="",  # Empty identity should raise ValueError
                issuer_identity_system="oauth",
                subject_identity="test_agent",
                subject_identity_system="custom",
                scope=["test"]
            )