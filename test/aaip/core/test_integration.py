"""
Integration tests for AAIP core functionality.

Run with: python -m pytest test_integration.py
"""

import json
import os

# Import test utilities
import sys

import pytest

# Import AAIP core modules
from aaip.core import (
    ConstraintError,
    check_delegation_authorization,
    generate_keypair,
    serialize_canonical,
    validate_constraints,
    verify_delegation,
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from utils import create_test_delegation_payload


class TestEndToEndScenarios:
    """Test complete end-to-end scenarios."""

    def test_simple_delegation_scenario(self):
        """Test a simple delegation scenario."""
        # Create delegation for a simple agent
        delegation = create_test_delegation_payload(
            issuer_identity="user@example.com",
            issuer_identity_system="oauth",
            subject_identity="simple_agent",
            subject_identity_system="custom",
            scope=["email:send", "payments:authorize"],
            constraints={"max_amount": {"value": 1000, "currency": "USD"}},
            expires_at="2025-08-26T10:00:00Z",
            not_before="2025-07-26T10:00:00Z",
        )

        # Verify delegation structure
        assert delegation.id is not None
        assert delegation.issuer.id == "user@example.com"
        assert delegation.subject.id == "simple_agent"
        assert "email:send" in delegation.scope
        assert "payments:authorize" in delegation.scope
        assert delegation.constraints["max_amount"]["value"] == 1000

        # Create a complete delegation (this would normally be signed)
        from aaip.core import Delegation

        complete_delegation = Delegation(
            aaip_version="1.0", delegation=delegation, signature="dummy_signature"
        )

        # Test authorization check
        assert (
            check_delegation_authorization(complete_delegation, "email", "send") is True
        )

        assert (
            check_delegation_authorization(complete_delegation, "payments", "authorize")
            is True
        )

        # Test constraint validation
        valid_request = {"amount": 500, "currency": "USD", "action": "send_email"}

        assert validate_constraints(delegation.constraints, valid_request) is True

        # Test constraint violation - amount too high
        invalid_request = {
            "amount": 1500,  # Exceeds max_amount
            "currency": "USD",
            "action": "send_email",
        }

        with pytest.raises(ConstraintError):
            validate_constraints(delegation.constraints, invalid_request)

    def test_constraint_creation_integration(self):
        """Test integration between constraint creation and validation."""
        # Create spending constraints
        constraints = {
            "max_amount": {"value": 500.0, "currency": "USD"},
            "allowed_domains": ["amazon.com", "stripe.com"],
        }

        # Test valid request
        valid_request = {"amount": 100.0, "currency": "USD", "domain": "amazon.com"}

        assert validate_constraints(constraints, valid_request) is True

        # Test invalid request - amount too high
        invalid_request = {"amount": 600.0, "currency": "USD", "domain": "amazon.com"}

        with pytest.raises(ConstraintError):
            validate_constraints(constraints, invalid_request)

    def test_delegation_with_constraints(self):
        """Test delegation with various constraint types."""
        # Create delegation with multiple constraint types
        delegation = create_test_delegation_payload(
            issuer_identity="user@example.com",
            issuer_identity_system="oauth",
            subject_identity="complex_agent",
            subject_identity_system="custom",
            scope=["email:send", "payments:authorize"],
            constraints={
                "max_amount": {"value": 2000, "currency": "USD"},
                "blocked_domains": ["competitor.com", "spam.com"],
            },
            expires_at="2025-08-26T10:00:00Z",
            not_before="2025-07-26T10:00:00Z",
        )

        # Verify constraint structure
        constraints = delegation.constraints
        assert constraints["max_amount"]["value"] == 2000
        assert "competitor.com" in constraints["blocked_domains"]

        # Test constraint validation
        valid_request = {
            "amount": 500,
            "currency": "USD",
            "email": "prospect@goodcompany.com",
        }

        assert validate_constraints(constraints, valid_request) is True

        # Test constraint violation - blocked domain
        invalid_request = {"amount": 500, "currency": "USD", "domain": "competitor.com"}

        with pytest.raises(ConstraintError):
            validate_constraints(constraints, invalid_request)


if __name__ == "__main__":
    # Run a simple smoke test
    print("Running AAIP integration smoke test...")

    try:
        # Test basic integration
        user_private_key, _ = generate_keypair()

        delegation = create_test_delegation_payload(
            issuer_identity="user@example.com",
            issuer_identity_system="custom",
            subject_identity="integration_test_agent",
            subject_identity_system="custom",
            scope=["test:action"],
            constraints={"max_amount": {"value": 100.0, "currency": "USD"}},
            expires_at="2025-08-26T10:00:00Z",
            not_before="2025-07-26T10:00:00Z",
        )

        assert verify_delegation(delegation) is True

        # Test constraint validation
        request = {"action": "test.action", "amount": 50.0}
        assert validate_constraints(delegation.delegation.constraints, request) is True

        # Test serialization
        json_str = serialize_canonical(delegation)
        restored = json.loads(json_str)
        assert verify_delegation(restored) is True

        print("\033[92mIntegration tests passed!\033[0m")

    except Exception as e:
        print(f"\033[91mIntegration smoke test failed: {e}\033[0m")
        raise
