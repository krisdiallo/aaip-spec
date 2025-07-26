"""
AAIP Cryptographic Operations

This module provides cryptographic primitives for AAIP delegation signing and verification.
Implements Ed25519 signatures per RFC 8037 standards.
"""

import json
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .exceptions import AAIPErrorCode, SignatureError


class AAIPCrypto:
    """AAIP cryptographic operations manager."""

    @staticmethod
    def generate_keypair() -> tuple[str, str]:
        """
        Generate an Ed25519 keypair for AAIP delegation signing.
        
        Returns:
            Tuple of (private_key_hex, public_key_hex)
        """
        # Generate Ed25519 private key
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Convert to hex strings
        private_key_hex = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ).hex()

        public_key_hex = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()

        return private_key_hex, public_key_hex

    @staticmethod
    def sign_delegation(delegation_dict: Dict[str, Any], private_key_hex: str) -> str:
        """
        Sign a delegation using Ed25519.
        
        Args:
            delegation_dict: Delegation dictionary (without signature field)
            private_key_hex: Private key in hex format
            
        Returns:
            Signature in hex format
            
        Raises:
            SignatureError: If signing fails
        """
        try:
            # Convert private key from hex
            private_key_bytes = bytes.fromhex(private_key_hex)
            private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)

            # Create canonical JSON representation
            canonical_json = AAIPCrypto.serialize_canonical(delegation_dict)

            # Sign the canonical JSON
            signature = private_key.sign(canonical_json.encode('utf-8'))

            return signature.hex()

        except (ValueError, TypeError) as e:
            raise SignatureError(
                AAIPErrorCode.SIGNATURE_INVALID,
                f"Failed to sign delegation: {e}"
            )

    @staticmethod
    def verify_delegation_signature(
        delegation_dict: Dict[str, Any],
        signature_hex: str,
        public_key_hex: str
    ) -> bool:
        """
        Verify a delegation signature using Ed25519.
        
        Args:
            delegation_dict: Delegation dictionary (without signature field)
            signature_hex: Signature in hex format
            public_key_hex: Public key in hex format
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Convert from hex
            signature_bytes = bytes.fromhex(signature_hex)
            public_key_bytes = bytes.fromhex(public_key_hex)
        except ValueError:
            return False

        try:
            # Create public key
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        except (ValueError, TypeError):
            return False

        try:
            # Create canonical JSON representation
            canonical_json = AAIPCrypto.serialize_canonical(delegation_dict)

            # Verify signature
            public_key.verify(signature_bytes, canonical_json.encode('utf-8'))
            return True
        except InvalidSignature:
            return False
        except (ValueError, TypeError):
            return False

    @staticmethod
    def serialize_canonical(data: Dict[str, Any]) -> str:
        """
        Serialize data to canonical JSON format per AAIP specification.
        
        Args:
            data: Dictionary to serialize
            
        Returns:
            Canonical JSON string
        """
        return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)

    @staticmethod
    def create_signed_delegation(
        delegation_payload: Dict[str, Any],
        private_key_hex: str,
        aaip_version: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a signed delegation.
        
        Args:
            delegation_payload: The delegation payload to sign
            private_key_hex: Private key for signing
            aaip_version: AAIP protocol version
            
        Returns:
            Signed delegation with signature
            
        Raises:
            SignatureError: If signing fails
        """
        # Use default AAIP version if not provided
        if aaip_version is None:
            from .. import AAIP_VERSION
            aaip_version = AAIP_VERSION
            
        # Create the delegation structure
        delegation_dict = {
            "aaip_version": aaip_version,
            "delegation": delegation_payload
        }

        # Sign the delegation
        signature = AAIPCrypto.sign_delegation(delegation_dict, private_key_hex)

        # Add signature to create final delegation
        delegation_dict["signature"] = signature

        return delegation_dict


    @staticmethod
    def extract_public_key_from_private(private_key_hex: str) -> str:
        """
        Extract public key from private key.
        
        Args:
            private_key_hex: Private key in hex format
            
        Returns:
            Public key in hex format
            
        Raises:
            SignatureError: If key extraction fails
        """
        try:
            private_key_bytes = bytes.fromhex(private_key_hex)
            private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
            public_key = private_key.public_key()

            return public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex()

        except (ValueError, TypeError) as e:
            raise SignatureError(
                AAIPErrorCode.SIGNATURE_INVALID,
                f"Failed to extract public key: {e}"
            )


# Convenience functions for public API
def generate_keypair() -> tuple[str, str]:
    """Generate Ed25519 keypair - convenience function."""
    return AAIPCrypto.generate_keypair()


def serialize_canonical(data: Dict[str, Any]) -> str:
    """Serialize to canonical JSON - convenience function."""
    return AAIPCrypto.serialize_canonical(data)
