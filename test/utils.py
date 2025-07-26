"""
Test utilities for AAIP tests.

This module provides helper functions for creating test data and common test operations.
"""

from typing import Dict, Any, List, Optional
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from aaip.core.authorization import DelegationPayload, Delegation
from aaip.core.identity import Identity


def create_test_delegation_payload(
    issuer_identity: str = "test_user@example.com",
    issuer_identity_system: str = "oauth",
    subject_identity: str = "test_agent",
    subject_identity_system: str = "custom",
    scope: List[str] = None,
    constraints: Optional[Dict[str, Any]] = None,
    expires_at: str = "2025-08-26T10:00:00Z",
    not_before: str = "2025-07-26T10:00:00Z",
    issuer_public_key: Optional[str] = None
) -> DelegationPayload:
    """
    Create a delegation payload for testing purposes using public APIs only.
    
    Args:
        issuer_identity: Identity of the user granting permission
        issuer_identity_system: Type of issuer's identity system  
        subject_identity: Identity of the agent receiving permission
        subject_identity_system: Type of agent's identity system
        scope: List of permissions being granted
        constraints: Optional constraints on the delegation
        expires_at: ISO 8601 expiration timestamp
        not_before: ISO 8601 timestamp when delegation becomes valid
        issuer_public_key: Optional public key for the issuer
        
    Returns:
        Delegation payload for testing
    """
    if scope is None:
        scope = ["test:action"]
    
    # Validate inputs like the internal function does
    if not scope:
        raise ValueError("Invalid delegation: must include at least one scope")
    
    if not issuer_identity or not issuer_identity.strip():
        raise ValueError("Invalid delegation: issuer identity cannot be empty")
        
    if not subject_identity or not subject_identity.strip():
        raise ValueError("Invalid delegation: subject identity cannot be empty")
    
    from datetime import datetime, timezone
    import secrets
    
    # Create delegation payload using public API pattern
    issuer = Identity(
        id=issuer_identity,
        type=issuer_identity_system,
        public_key=issuer_public_key
    )
    
    subject = Identity(
        id=subject_identity,
        type=subject_identity_system
    )
    
    return DelegationPayload(
        id=f"del_{secrets.token_urlsafe(20)}",
        issuer=issuer,
        subject=subject,
        scope=scope,
        constraints=constraints or {},
        issued_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        expires_at=expires_at,
        not_before=not_before
    )


def create_test_delegation_with_signature(
    delegation_payload: DelegationPayload,
    signature: str = "test_signature_hex"
) -> Delegation:
    """
    Create a complete delegation with a test signature for testing purposes.
    
    Args:
        delegation_payload: The delegation payload
        signature: Test signature (default: "test_signature_hex")
        
    Returns:
        Complete delegation with test signature
    """
    return Delegation(
        aaip_version="1.0",
        delegation=delegation_payload,
        signature=signature
    )


def create_test_identity(
    identity_id: str = "test_identity",
    identity_type: str = "custom",
    public_key: Optional[str] = None
) -> Identity:
    """
    Create a test identity.
    
    Args:
        identity_id: Identity ID
        identity_type: Type of identity system
        public_key: Optional public key
        
    Returns:
        Test Identity object
    """
    return Identity(
        id=identity_id,
        type=identity_type,
        public_key=public_key
    )