"""
AAIP Core Module

Core functionality for the AAIP v2.0 library.
"""

from .authorization import (
    Delegation,
    are_constraints_attenuated,
    check_delegation_authorization,
    create_signed_delegation,
    generate_delegation_id,
    is_scope_subset,
    validate_constraints,
    verify_delegation,
)
from .crypto import (
    AAIPCrypto,
    create_jwks,
    generate_keypair,
    public_key_to_jwk,
)
from .exceptions import (
    AAIPError,
    AAIPErrorCode,
    AuthorizationError,
    ChainError,
    ConstraintError,
    DelegationError,
    KeyResolutionError,
    SignatureError,
    ValidationError,
)
from .identity import (
    Identity,
    validate_identity_format,
)
from .jwks import (
    JWKSClient,
    KeyResolver,
    StaticKeyResolver,
)

__all__ = [
    "Identity",
    "validate_identity_format",
    "Delegation",
    "check_delegation_authorization",
    "generate_delegation_id",
    "create_signed_delegation",
    "verify_delegation",
    "validate_constraints",
    "is_scope_subset",
    "are_constraints_attenuated",
    "AAIPCrypto",
    "generate_keypair",
    "public_key_to_jwk",
    "create_jwks",
    "KeyResolver",
    "StaticKeyResolver",
    "JWKSClient",
    "AAIPError",
    "AAIPErrorCode",
    "DelegationError",
    "SignatureError",
    "AuthorizationError",
    "ConstraintError",
    "ValidationError",
    "KeyResolutionError",
    "ChainError",
]
