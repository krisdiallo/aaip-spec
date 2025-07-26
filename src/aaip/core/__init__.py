"""
AAIP Core Module

This module contains the core functionality for the AAIP library.
"""

# Core module exports - only what's actually defined in core/
from .authorization import (
    Delegation,
    check_delegation_authorization,
    create_signed_delegation,
    generate_delegation_id,
    validate_constraints,
    verify_delegation,
)
from .crypto import (
    AAIPCrypto,
    generate_keypair,
    serialize_canonical,
)
from .exceptions import (
    AAIPError,
    AAIPErrorCode,
    AuthorizationError,
    ConstraintError,
    DelegationError,
    SignatureError,
    ValidationError,
)
from .identity import (
    Identity,
    validate_identity_format,
)

__all__ = [
    # Core Identity types and functions
    "Identity",
    "validate_identity_format",
    # Core Authorization types and functions
    "Delegation",
    "check_delegation_authorization",
    "generate_delegation_id",
    "create_signed_delegation",
    "verify_delegation",
    "validate_constraints",
    # Core Cryptography
    "AAIPCrypto",
    "generate_keypair",
    "serialize_canonical",
    # Core Exceptions
    "AAIPError",
    "AAIPErrorCode",
    "DelegationError",
    "SignatureError",
    "AuthorizationError",
    "ConstraintError",
    "ValidationError",
]
