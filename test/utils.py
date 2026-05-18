"""
Test utilities for AAIP v2.0 tests.
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aaip.core.authorization import Delegation, create_signed_delegation
from aaip.core.crypto import generate_keypair
from aaip.core.jwks import StaticKeyResolver


def create_test_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey, str]:
    """Generate a test keypair with kid."""
    return generate_keypair()


def create_test_key_resolver(
    *key_pairs: tuple[Ed25519PublicKey, str],
) -> StaticKeyResolver:
    """Create a StaticKeyResolver from (public_key, kid) pairs."""
    keys = {kid: pub for pub, kid in key_pairs}
    return StaticKeyResolver(keys)


def create_test_delegation_token(
    issuer_identity: str = "test_user@example.com",
    issuer_identity_system: str = "oauth",
    subject_identity: str = "test_agent",
    subject_identity_system: str = "custom",
    scope: Optional[list[str]] = None,
    constraints: Optional[dict[str, Any]] = None,
    expires_at: Optional[str] = None,
    not_before: Optional[str] = None,
    private_key: Optional[Ed25519PrivateKey] = None,
    kid: Optional[str] = None,
    proofs: Optional[list[str]] = None,
) -> tuple[str, Ed25519PublicKey, str]:
    """
    Create a test JWT delegation token.

    Returns (token, public_key, kid).
    """
    if scope is None:
        scope = ["test:action"]

    if expires_at is None:
        expires_at = (
            (datetime.now(timezone.utc) + timedelta(days=365))
            .isoformat()
            .replace("+00:00", "Z")
        )

    if not_before is None:
        not_before = (
            (datetime.now(timezone.utc) - timedelta(hours=1))
            .isoformat()
            .replace("+00:00", "Z")
        )

    if private_key is None or kid is None:
        private_key, pub, kid = generate_keypair()
    else:
        pub = private_key.public_key()

    token = create_signed_delegation(
        issuer_identity=issuer_identity,
        issuer_identity_system=issuer_identity_system,
        private_key=private_key,
        kid=kid,
        subject_identity=subject_identity,
        subject_identity_system=subject_identity_system,
        scope=scope,
        expires_at=expires_at,
        not_before=not_before,
        constraints=constraints,
        proofs=proofs,
    )

    return token, pub, kid


def create_test_delegation(
    **kwargs: Any,
) -> Delegation:
    """Create a decoded test Delegation object."""
    from aaip.core.authorization import verify_delegation

    token, pub, kid = create_test_delegation_token(**kwargs)
    return verify_delegation(token, pub)
