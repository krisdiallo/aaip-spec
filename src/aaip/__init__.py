"""
AAIP - AI Agent Identity Protocol

JWT-based delegation format for AI agent authorization with EdDSA signatures
and UCAN-style delegation chains.

Basic Usage:
    from aaip import create_signed_delegation, verify_delegation, generate_keypair

    # Generate a keypair for signing
    private_key, public_key, kid = generate_keypair()

    # Create a signed JWT delegation
    token = create_signed_delegation(
        issuer_identity="user@example.com",
        issuer_identity_system="oauth",
        private_key=private_key,
        kid=kid,
        subject_identity="agent_001",
        subject_identity_system="custom",
        scope=["payments:authorize"],
        expires_at="2025-08-26T10:00:00Z",
        not_before="2025-07-26T10:00:00Z",
    )

    # Verify the delegation
    from aaip import StaticKeyResolver
    resolver = StaticKeyResolver({kid: public_key})
    delegation = verify_delegation(token, resolver)

"""

__version__ = "2.0.0"
__author__ = "AAIP Working Group"

from .core import (
    AAIPError,
    AAIPErrorCode,
    AuthorizationError,
    ChainError,
    Delegation,
    DelegationError,
    Identity,
    JWKSClient,
    KeyResolutionError,
    KeyResolver,
    StaticKeyResolver,
    ValidationError,
    check_delegation_authorization,
    create_jwks,
    create_signed_delegation,
    generate_keypair,
    public_key_to_jwk,
    validate_constraints,
    verify_delegation,
)

AAIP_VERSION = "2.0"

__all__ = [
    "__version__",
    "__author__",
    "AAIP_VERSION",
    "create_signed_delegation",
    "verify_delegation",
    "generate_keypair",
    "check_delegation_authorization",
    "validate_constraints",
    "public_key_to_jwk",
    "create_jwks",
    "Delegation",
    "Identity",
    "KeyResolver",
    "StaticKeyResolver",
    "JWKSClient",
    "AAIPError",
    "AAIPErrorCode",
    "DelegationError",
    "ValidationError",
    "AuthorizationError",
    "KeyResolutionError",
    "ChainError",
]
