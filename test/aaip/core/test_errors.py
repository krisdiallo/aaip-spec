"""
Tests for AAIP error handling functionality.
"""

import os
import sys

import pytest

from aaip.core import (
    AAIPError,
    AAIPErrorCode,
    AuthorizationError,
    ChainError,
    ConstraintError,
    DelegationError,
    KeyResolutionError,
    SignatureError,
    ValidationError,
    validate_constraints,
    validate_identity_format,
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from utils import create_test_delegation_token


class TestErrorTypes:
    def test_aaip_error_base(self):
        error = AAIPError(AAIPErrorCode.INVALID_DELEGATION, "Test error message")
        assert "Test error message" in str(error)
        assert isinstance(error, Exception)

    def test_delegation_error(self):
        error = DelegationError(
            AAIPErrorCode.INVALID_DELEGATION, "Invalid delegation format"
        )
        assert "Invalid delegation format" in str(error)
        assert isinstance(error, AAIPError)

    def test_constraint_violation_error(self):
        error = ConstraintError(
            AAIPErrorCode.CONSTRAINT_VIOLATED, "Amount exceeds limit"
        )
        assert "Amount exceeds limit" in str(error)
        assert isinstance(error, AAIPError)

    def test_identity_verification_error(self):
        error = ValidationError(
            AAIPErrorCode.IDENTITY_VERIFICATION_FAILED, "Identity verification failed"
        )
        assert "Identity verification failed" in str(error)
        assert isinstance(error, AAIPError)

    def test_key_resolution_error(self):
        error = KeyResolutionError(AAIPErrorCode.KEY_RESOLUTION_FAILED, "Key not found")
        assert "Key not found" in str(error)
        assert isinstance(error, AAIPError)

    def test_chain_error(self):
        error = ChainError(AAIPErrorCode.CHAIN_VALIDATION_FAILED, "Chain too deep")
        assert "Chain too deep" in str(error)
        assert isinstance(error, AAIPError)


class TestErrorCreation:
    def test_invalid_delegation_error(self):
        error = DelegationError(AAIPErrorCode.INVALID_DELEGATION, "Invalid JSON format")
        assert "Invalid JSON format" in str(error)

    def test_missing_field_error(self):
        error = DelegationError(
            AAIPErrorCode.MISSING_REQUIRED_FIELD, "Missing field: signature"
        )
        assert "signature" in str(error)

    def test_signature_verification_error(self):
        error = SignatureError(AAIPErrorCode.SIGNATURE_INVALID, "Invalid signature")
        assert "Invalid signature" in str(error)

    def test_delegation_expired_error(self):
        error = AuthorizationError(
            AAIPErrorCode.DELEGATION_EXPIRED,
            "Delegation expired at: 2025-01-01T00:00:00Z",
        )
        assert "2025-01-01T00:00:00Z" in str(error)

    def test_attenuation_violated_error(self):
        error = ChainError(
            AAIPErrorCode.ATTENUATION_VIOLATED,
            "Child scope is wider than parent",
        )
        assert "wider" in str(error)
        assert error.code == AAIPErrorCode.ATTENUATION_VIOLATED

    def test_scope_insufficient_error(self):
        error = AuthorizationError(
            AAIPErrorCode.SCOPE_INSUFFICIENT,
            "Required scope payments:authorize not in granted scopes: email:send",
        )
        assert "payments:authorize" in str(error)
        assert "email:send" in str(error)


class TestErrorCodes:
    def test_error_codes_exist(self):
        expected_codes = [
            "INVALID_DELEGATION",
            "MISSING_REQUIRED_FIELD",
            "INVALID_FIELD_FORMAT",
            "SIGNATURE_INVALID",
            "INVALID_TOKEN",
            "UNSUPPORTED_ALGORITHM",
            "DELEGATION_EXPIRED",
            "DELEGATION_NOT_YET_VALID",
            "SCOPE_INSUFFICIENT",
            "CONSTRAINT_VIOLATED",
            "IDENTITY_VERIFICATION_FAILED",
            "KEY_RESOLUTION_FAILED",
            "CHAIN_VALIDATION_FAILED",
            "ATTENUATION_VIOLATED",
        ]
        for code_name in expected_codes:
            assert hasattr(AAIPErrorCode, code_name)

    def test_error_code_values(self):
        for code in AAIPErrorCode:
            assert isinstance(code.value, str)
            assert len(code.value) > 0


class TestErrorHandlingScenarios:
    def test_delegation_creation_errors(self):
        with pytest.raises(ValueError) as exc_info:
            create_test_delegation_token(scope=[])
        assert "invalid" in str(exc_info.value).lower()

        with pytest.raises(ValueError) as exc_info:
            create_test_delegation_token(issuer_identity="")
        assert "identity" in str(exc_info.value).lower()

    def test_constraint_validation_errors(self):
        constraints = {"max_amount": {"value": 100, "currency": "USD"}}

        with pytest.raises(ConstraintError) as exc_info:
            validate_constraints(constraints, {"amount": 150.0})
        assert "exceeds" in str(exc_info.value)

        with pytest.raises(ConstraintError) as exc_info:
            validate_constraints(constraints, {"currency": "USD"})
        assert "amount" in str(exc_info.value)

    def test_identity_verification_errors(self):
        assert validate_identity_format("did:example:123", "did")
        assert validate_identity_format("user@example.com", "oauth")
        assert not validate_identity_format("", "custom")
        assert not validate_identity_format("invalid", "did")

    def test_invalid_token_verification(self):
        from aaip.core import verify_delegation
        from aaip.core.crypto import generate_keypair

        _, pub, kid = generate_keypair()
        with pytest.raises(DelegationError):
            verify_delegation("not-a-jwt", pub)


class TestErrorRecovery:
    def test_error_chaining(self):
        try:
            raise DelegationError(AAIPErrorCode.INVALID_DELEGATION, "Original error")
        except DelegationError as e:
            chained_error = DelegationError(
                AAIPErrorCode.INVALID_DELEGATION, f"Failed to process delegation: {e}"
            )
            assert "Original error" in str(chained_error)
            assert "Failed to process delegation" in str(chained_error)

    def test_error_with_context(self):
        error = ConstraintError(
            AAIPErrorCode.CONSTRAINT_VIOLATED,
            "Amount exceeds limit",
            {"requested_amount": 150, "max_amount": 100},
        )
        assert "Amount exceeds limit" in str(error)
        assert error.details["requested_amount"] == 150
        assert error.details["max_amount"] == 100
