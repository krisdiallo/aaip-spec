"""
Tests for AAIP error handling functionality.

Run with: python -m pytest test_errors.py
"""

import pytest

# Import AAIP core modules
from aaip.core import (
    AAIPError,
    AAIPErrorCode,
    ConstraintError,
    DelegationError,
    ValidationError,
)


class TestErrorTypes:
    """Test different error types and their properties."""

    def test_aaip_error_base(self):
        """Test the base AAIP error class."""
        error = AAIPError(AAIPErrorCode.INVALID_DELEGATION, "Test error message")
        assert "Test error message" in str(error)
        assert isinstance(error, Exception)

    def test_delegation_error(self):
        """Test delegation-specific errors."""
        error = DelegationError(
            AAIPErrorCode.INVALID_DELEGATION, "Invalid delegation format"
        )
        assert "Invalid delegation format" in str(error)
        assert isinstance(error, AAIPError)

    def test_constraint_violation_error(self):
        """Test constraint violation errors."""
        error = ConstraintError(
            AAIPErrorCode.CONSTRAINT_VIOLATED, "Amount exceeds limit"
        )
        assert "Amount exceeds limit" in str(error)
        assert isinstance(error, AAIPError)

    def test_identity_verification_error(self):
        """Test identity verification errors."""
        error = ValidationError(
            AAIPErrorCode.IDENTITY_VERIFICATION_FAILED, "Identity verification failed"
        )
        assert "Identity verification failed" in str(error)
        assert isinstance(error, AAIPError)


class TestErrorCreation:
    """Test error creation convenience functions."""

    def test_invalid_delegation_error(self):
        """Test invalid delegation error creation."""
        error = DelegationError(AAIPErrorCode.INVALID_DELEGATION, "Invalid JSON format")
        assert "Invalid JSON format" in str(error)
        assert isinstance(error, DelegationError)

    def test_missing_field_error(self):
        """Test missing field error creation."""
        error = DelegationError(
            AAIPErrorCode.MISSING_REQUIRED_FIELD, "Missing field: signature"
        )
        assert "signature" in str(error)
        assert isinstance(error, DelegationError)

    def test_signature_verification_error(self):
        """Test signature verification error creation."""
        from aaip.core import SignatureError

        error = SignatureError(AAIPErrorCode.SIGNATURE_INVALID, "Invalid signature")
        assert "Invalid signature" in str(error)
        assert isinstance(error, SignatureError)

    def test_delegation_expired_error(self):
        """Test delegation expired error creation."""
        from aaip.core import AuthorizationError

        error = AuthorizationError(
            AAIPErrorCode.DELEGATION_EXPIRED,
            "Delegation expired at: 2025-01-01T00:00:00Z",
        )
        assert "2025-01-01T00:00:00Z" in str(error)
        assert isinstance(error, AuthorizationError)

    def test_delegation_not_valid_yet_error(self):
        """Test delegation not valid yet error creation."""
        from aaip.core import AuthorizationError

        error = AuthorizationError(
            AAIPErrorCode.DELEGATION_NOT_YET_VALID,
            "Delegation not valid until: 2025-12-31T23:59:59Z",
        )
        assert "2025-12-31T23:59:59Z" in str(error)
        assert isinstance(error, AuthorizationError)

    def test_scope_insufficient_error(self):
        """Test scope insufficient error creation."""
        from aaip.core import AuthorizationError

        error = AuthorizationError(
            AAIPErrorCode.SCOPE_INSUFFICIENT,
            "Required scope payments:authorize not in granted scopes: email:send",
        )
        assert "payments:authorize" in str(error)
        assert "email:send" in str(error)
        assert isinstance(error, AuthorizationError)


class TestErrorCodes:
    """Test error code enumeration."""

    def test_error_codes_exist(self):
        """Test that expected error codes exist."""
        expected_codes = [
            "INVALID_DELEGATION",
            "MISSING_REQUIRED_FIELD",
            "INVALID_FIELD_FORMAT",
            "SIGNATURE_INVALID",
            "DELEGATION_EXPIRED",
            "DELEGATION_NOT_YET_VALID",
            "SCOPE_INSUFFICIENT",
            "CONSTRAINT_VIOLATED",
            "IDENTITY_VERIFICATION_FAILED",
        ]

        for code_name in expected_codes:
            assert hasattr(AAIPErrorCode, code_name)

    def test_error_code_values(self):
        """Test that error codes have string values."""
        for code in AAIPErrorCode:
            assert isinstance(code.value, str)
            assert len(code.value) > 0


class TestErrorHandlingScenarios:
    """Test error handling in various scenarios."""

    def test_delegation_creation_errors(self):
        """Test errors during delegation creation."""
        # Import test utilities
        import os
        import sys

        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
        from utils import create_test_delegation_payload

        # Test with empty scope
        with pytest.raises(ValueError) as exc_info:
            create_test_delegation_payload(
                issuer_identity="user123",
                issuer_identity_system="custom",
                subject_identity="test_agent",
                subject_identity_system="custom",
                scope=[],  # Empty scope should raise ValueError
            )
        assert "invalid" in str(exc_info.value).lower()

        # Test with invalid identity type
        with pytest.raises(ValueError) as exc_info:
            create_test_delegation_payload(
                issuer_identity="",  # Empty identity
                issuer_identity_system="custom",
                subject_identity="test_agent",
                subject_identity_system="custom",
                scope=["test:action"],
            )
        assert "identity" in str(exc_info.value).lower()

    def test_constraint_validation_errors(self):
        """Test constraint validation errors."""
        from aaip.core import validate_constraints

        constraints = {"max_amount": {"value": 100, "currency": "USD"}}

        # Test amount too high
        with pytest.raises(ConstraintError) as exc_info:
            validate_constraints(constraints, {"amount": 150.0})
        assert "exceeds" in str(exc_info.value)

        # Test missing required field
        with pytest.raises(ConstraintError) as exc_info:
            validate_constraints(constraints, {"currency": "USD"})  # Missing amount
        assert "amount" in str(exc_info.value)

    def test_identity_verification_errors(self):
        """Test identity verification errors."""
        from aaip.core import validate_identity_format

        # Test identity format validation
        assert validate_identity_format("did:example:123", "did")
        assert validate_identity_format("user@example.com", "oauth")
        assert not validate_identity_format("", "custom")  # Empty identity invalid
        assert not validate_identity_format("invalid", "did")  # Invalid DID format

    def test_json_parsing_errors(self):
        """Test JSON parsing errors."""
        import json

        from aaip.core import verify_delegation

        # Test malformed JSON
        with pytest.raises((json.JSONDecodeError, ValueError)) as exc_info:
            json.loads("invalid json")
        assert (
            "json" in str(exc_info.value).lower()
            or "expecting" in str(exc_info.value).lower()
        )

        # Test missing required fields - our verify_delegation returns False for invalid data
        # instead of raising exceptions, so we test that it returns False
        result = verify_delegation({"aaip_version": "1.0"})
        assert result is False


class TestErrorRecovery:
    """Test error recovery and handling patterns."""

    def test_error_chaining(self):
        """Test that errors can be chained properly."""
        try:
            raise DelegationError(AAIPErrorCode.INVALID_DELEGATION, "Original error")
        except DelegationError as e:
            # Chain with additional context
            chained_error = DelegationError(
                AAIPErrorCode.INVALID_DELEGATION, f"Failed to process delegation: {e}"
            )
            assert "Original error" in str(chained_error)
            assert "Failed to process delegation" in str(chained_error)

    def test_error_with_context(self):
        """Test errors with additional context."""
        error = ConstraintError(
            AAIPErrorCode.CONSTRAINT_VIOLATED,
            "Amount exceeds limit",
            {"requested_amount": 150, "max_amount": 100},
        )

        assert "Amount exceeds limit" in str(error)
        # Context should be accessible through the details attribute
        if hasattr(error, "details"):
            assert error.details["requested_amount"] == 150
            assert error.details["max_amount"] == 100


if __name__ == "__main__":
    # Run a simple smoke test
    print("Running AAIP errors smoke test...")

    try:
        # Test error creation
        error = AAIPError(AAIPErrorCode.INVALID_DELEGATION, "Test error")
        print("✓ Error creation works")

        # Test error codes
        assert AAIPErrorCode.INVALID_DELEGATION.value == "INVALID_DELEGATION"
        print("✓ Error codes work")

        # Test convenience functions
        error = DelegationError(AAIPErrorCode.INVALID_DELEGATION, "Test")
        assert isinstance(error, DelegationError)
        print("✓ Convenience error functions work")

        print("\033[92mError handling smoke tests passed!\033[0m")

    except Exception as e:
        print(f"\033[91mError handling smoke test failed: {e}\033[0m")
        raise
