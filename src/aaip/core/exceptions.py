"""
AAIP Exceptions

Core exception classes for AAIP v1.0 protocol.
Aligned with specification Section 9 error codes.
"""

from enum import Enum
from typing import Any, Optional


class AAIPErrorCode(Enum):
    """Standard AAIP error codes as defined in specification."""

    # Core delegation errors
    INVALID_DELEGATION = "INVALID_DELEGATION"
    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
    INVALID_FIELD_FORMAT = "INVALID_FIELD_FORMAT"

    # Signature errors
    SIGNATURE_INVALID = "SIGNATURE_INVALID"

    # Time-based errors
    DELEGATION_EXPIRED = "DELEGATION_EXPIRED"
    DELEGATION_NOT_YET_VALID = "DELEGATION_NOT_YET_VALID"

    # Authorization errors
    SCOPE_INSUFFICIENT = "SCOPE_INSUFFICIENT"
    CONSTRAINT_VIOLATED = "CONSTRAINT_VIOLATED"

    # Identity errors
    IDENTITY_VERIFICATION_FAILED = "IDENTITY_VERIFICATION_FAILED"


class AAIPError(Exception):
    """Base exception for all AAIP errors."""

    def __init__(
        self,
        code: AAIPErrorCode,
        message: str,
        details: Optional[dict[str, Any]] = None,
    ):
        """
        Initialize AAIP error.

        Args:
            code: Error code from AAIPErrorCode enum
            message: Human-readable error message
            details: Optional additional error details
        """
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


class DelegationError(AAIPError):
    """Errors related to delegation format and structure."""

    pass


class SignatureError(AAIPError):
    """Errors related to cryptographic signatures."""

    pass


class AuthorizationError(AAIPError):
    """Errors related to authorization and permissions."""

    pass


class ConstraintError(AAIPError):
    """Errors related to constraint validation."""

    pass


class ValidationError(AAIPError):
    """Errors related to data validation."""

    pass


# Convenience functions for common errors
def invalid_delegation_error(
    message: str, details: Optional[dict[str, Any]] = None
) -> DelegationError:
    """Create an invalid delegation error."""
    return DelegationError(AAIPErrorCode.INVALID_DELEGATION, message, details)


def missing_field_error(field_name: str) -> DelegationError:
    """Create a missing required field error."""
    return DelegationError(
        AAIPErrorCode.MISSING_REQUIRED_FIELD,
        f"Missing required field: {field_name}",
        {"field_name": field_name},
    )


def signature_invalid_error(
    message: str = "Signature verification failed",
) -> SignatureError:
    """Create a signature invalid error."""
    return SignatureError(AAIPErrorCode.SIGNATURE_INVALID, message)


def delegation_expired_error(expires_at: str) -> AuthorizationError:
    """Create a delegation expired error."""
    return AuthorizationError(
        AAIPErrorCode.DELEGATION_EXPIRED,
        f"Delegation expired at {expires_at}",
        {"expires_at": expires_at},
    )


def scope_insufficient_error(
    required_scope: str, available_scopes: list
) -> AuthorizationError:
    """Create a scope insufficient error."""
    return AuthorizationError(
        AAIPErrorCode.SCOPE_INSUFFICIENT,
        f"Insufficient scope: requires {required_scope}",
        {"required_scope": required_scope, "available_scopes": available_scopes},
    )


def constraint_violated_error(constraint_name: str, message: str) -> ConstraintError:
    """Create a constraint violation error."""
    return ConstraintError(
        AAIPErrorCode.CONSTRAINT_VIOLATED,
        f"Constraint '{constraint_name}' violated: {message}",
        {"constraint_name": constraint_name},
    )
