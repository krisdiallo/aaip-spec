"""
AAIP - AI Agent Identity Protocol

Standard delegation format for AI agent authorization with Ed25519 cryptographic signatures.

Basic Usage:
    from aaip import create_signed_delegation, verify_delegation, generate_keypair

    # Generate a keypair for signing
    private_key, public_key = generate_keypair()

    # Create a signed delegation
    delegation = create_signed_delegation(
        issuer_identity="user@example.com",
        issuer_identity_system="oauth",
        issuer_private_key=private_key,
        subject_identity="agent_001",
        subject_identity_system="custom",
        scope=["payments:authorize"],
        expires_at="2025-08-26T10:00:00Z",
        not_before="2025-07-26T10:00:00Z"
    )

    # Verify the delegation
    is_valid = verify_delegation(delegation)

"""

__version__ = "1.0.0"
__author__ = "AAIP Working Group"


# Core public API - Essential delegation functions
from .core import (
    # Essential errors
    AAIPError,
    AAIPErrorCode,
    AuthorizationError,
    # Core types most users need
    Delegation,
    DelegationError,
    Identity,
    ValidationError,
    check_delegation_authorization,
    # Primary delegation functions
    create_signed_delegation,
    generate_keypair,
    # Basic constraint functions
    validate_constraints,
    verify_delegation,
)

AAIP_VERSION = "1.0"

__all__ = [
    # Version info
    "__version__",
    "__author__",
    "AAIP_VERSION",
    # Core delegation functions
    "create_signed_delegation",
    "verify_delegation",
    "generate_keypair",
    "check_delegation_authorization",
    # Core types
    "Delegation",
    "Identity",
    # Essential errors
    "AAIPError",
    "AAIPErrorCode",
    "DelegationError",
    "ValidationError",
    "AuthorizationError",
    # Basic constraints
    "validate_constraints",
]
