"""
AAIP Exceptions

Core exception classes for AAIP v2.0 protocol.
Aligned with specification error codes.
"""

from enum import Enum
from typing import Any, Optional


class AAIPErrorCode(Enum):
    """Standard AAIP error codes."""

    INVALID_DELEGATION = "INVALID_DELEGATION"
    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
    INVALID_FIELD_FORMAT = "INVALID_FIELD_FORMAT"

    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    INVALID_TOKEN = "INVALID_TOKEN"
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM"

    DELEGATION_EXPIRED = "DELEGATION_EXPIRED"
    DELEGATION_NOT_YET_VALID = "DELEGATION_NOT_YET_VALID"

    SCOPE_INSUFFICIENT = "SCOPE_INSUFFICIENT"
    CONSTRAINT_VIOLATED = "CONSTRAINT_VIOLATED"

    IDENTITY_VERIFICATION_FAILED = "IDENTITY_VERIFICATION_FAILED"

    KEY_RESOLUTION_FAILED = "KEY_RESOLUTION_FAILED"

    CHAIN_VALIDATION_FAILED = "CHAIN_VALIDATION_FAILED"
    ATTENUATION_VIOLATED = "ATTENUATION_VIOLATED"


class AAIPError(Exception):
    """Base exception for all AAIP errors."""

    def __init__(
        self,
        code: AAIPErrorCode,
        message: str,
        details: Optional[dict[str, Any]] = None,
    ):
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


class KeyResolutionError(AAIPError):
    """Errors related to JWKS key resolution."""

    pass


class ChainError(AAIPError):
    """Errors related to delegation chain validation."""

    pass


def invalid_delegation_error(
    message: str, details: Optional[dict[str, Any]] = None
) -> DelegationError:
    return DelegationError(AAIPErrorCode.INVALID_DELEGATION, message, details)


def missing_field_error(field_name: str) -> DelegationError:
    return DelegationError(
        AAIPErrorCode.MISSING_REQUIRED_FIELD,
        f"Missing required field: {field_name}",
        {"field_name": field_name},
    )


def signature_invalid_error(
    message: str = "Signature verification failed",
) -> SignatureError:
    return SignatureError(AAIPErrorCode.SIGNATURE_INVALID, message)


def invalid_token_error(message: str = "Invalid JWT token") -> DelegationError:
    return DelegationError(AAIPErrorCode.INVALID_TOKEN, message)


def delegation_expired_error(expires_at: str) -> AuthorizationError:
    return AuthorizationError(
        AAIPErrorCode.DELEGATION_EXPIRED,
        f"Delegation expired at {expires_at}",
        {"expires_at": expires_at},
    )


def scope_insufficient_error(
    required_scope: str, available_scopes: list
) -> AuthorizationError:
    return AuthorizationError(
        AAIPErrorCode.SCOPE_INSUFFICIENT,
        f"Insufficient scope: requires {required_scope}",
        {"required_scope": required_scope, "available_scopes": available_scopes},
    )


def constraint_violated_error(constraint_name: str, message: str) -> ConstraintError:
    return ConstraintError(
        AAIPErrorCode.CONSTRAINT_VIOLATED,
        f"Constraint '{constraint_name}' violated: {message}",
        {"constraint_name": constraint_name},
    )


def key_resolution_error(kid: str) -> KeyResolutionError:
    return KeyResolutionError(
        AAIPErrorCode.KEY_RESOLUTION_FAILED,
        f"Failed to resolve key for kid: {kid}",
        {"kid": kid},
    )


def chain_error(message: str) -> ChainError:
    return ChainError(AAIPErrorCode.CHAIN_VALIDATION_FAILED, message)


def attenuation_error(message: str) -> ChainError:
    return ChainError(AAIPErrorCode.ATTENUATION_VIOLATED, message)
