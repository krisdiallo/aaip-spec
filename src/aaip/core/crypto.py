"""
AAIP Cryptographic Operations

JWT-based signing and verification using EdDSA (Ed25519) per RFC 8037.
Key management utilities for JWK/JWKS interop.
"""

import hashlib
import json
from base64 import urlsafe_b64decode, urlsafe_b64encode
from typing import Any, Optional

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .exceptions import AAIPErrorCode, DelegationError, SignatureError

ALLOWED_ALGORITHMS = ["EdDSA"]


class AAIPCrypto:
    """AAIP cryptographic operations manager."""

    @staticmethod
    def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey, str]:
        """
        Generate an Ed25519 keypair with a JWK Thumbprint kid.

        Returns:
            Tuple of (private_key, public_key, kid)
        """
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        kid = AAIPCrypto.compute_kid(public_key)
        return private_key, public_key, kid

    @staticmethod
    def compute_kid(public_key: Ed25519PublicKey) -> str:
        """Compute JWK Thumbprint (RFC 7638) as kid."""
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        x_b64 = urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")
        thumbprint_input = json.dumps(
            {"crv": "Ed25519", "kty": "OKP", "x": x_b64},
            separators=(",", ":"),
            sort_keys=True,
        )
        digest = hashlib.sha256(thumbprint_input.encode("ascii")).digest()
        return urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    @staticmethod
    def public_key_to_jwk(
        public_key: Ed25519PublicKey, kid: str
    ) -> dict[str, str]:
        """Convert Ed25519 public key to JWK format."""
        raw_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        x_b64 = urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x_b64,
            "kid": kid,
            "use": "sig",
            "alg": "EdDSA",
        }

    @staticmethod
    def private_key_to_jwk(
        private_key: Ed25519PrivateKey, kid: str
    ) -> dict[str, str]:
        """Convert Ed25519 private key to JWK format."""
        raw_private = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_key = private_key.public_key()
        raw_public = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        d_b64 = urlsafe_b64encode(raw_private).rstrip(b"=").decode("ascii")
        x_b64 = urlsafe_b64encode(raw_public).rstrip(b"=").decode("ascii")
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x_b64,
            "d": d_b64,
            "kid": kid,
            "use": "sig",
            "alg": "EdDSA",
        }

    @staticmethod
    def jwk_to_public_key(jwk_dict: dict[str, str]) -> Ed25519PublicKey:
        """Convert a JWK dict to an Ed25519PublicKey."""
        if jwk_dict.get("kty") != "OKP" or jwk_dict.get("crv") != "Ed25519":
            raise SignatureError(
                AAIPErrorCode.UNSUPPORTED_ALGORITHM,
                f"Unsupported key type: kty={jwk_dict.get('kty')}, crv={jwk_dict.get('crv')}",
            )
        x_b64 = jwk_dict["x"]
        padding = 4 - len(x_b64) % 4
        if padding != 4:
            x_b64 += "=" * padding
        raw_bytes = urlsafe_b64decode(x_b64)
        return Ed25519PublicKey.from_public_bytes(raw_bytes)

    @staticmethod
    def create_jwks(keys: list[dict[str, str]]) -> dict[str, Any]:
        """Wrap public JWK dicts into a JWKS document."""
        return {"keys": keys}

    @staticmethod
    def encode_delegation_jwt(
        payload: dict[str, Any],
        private_key: Ed25519PrivateKey,
        kid: str,
    ) -> str:
        """
        Encode a delegation payload as a signed JWT.

        Args:
            payload: JWT claims dict
            private_key: Ed25519 private key for signing
            kid: Key identifier for the JWT header

        Returns:
            Compact JWT string
        """
        try:
            return pyjwt.encode(
                payload,
                private_key,
                algorithm="EdDSA",
                headers={"kid": kid, "typ": "JWT"},
            )
        except Exception as e:
            raise SignatureError(
                AAIPErrorCode.SIGNATURE_INVALID,
                f"Failed to encode JWT: {e}",
            ) from e

    @staticmethod
    def decode_delegation_jwt(
        token: str,
        public_key: Ed25519PublicKey,
        options: Optional[dict[str, Any]] = None,
        leeway: int = 300,
        audience: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Decode and verify a delegation JWT.

        Args:
            token: Compact JWT string
            public_key: Ed25519 public key for verification
            options: Optional PyJWT decode options
            leeway: Clock skew tolerance in seconds (default 5 minutes)
            audience: Optional expected audience (aud claim)

        Returns:
            Decoded payload dict

        Raises:
            DelegationError: If token is invalid or expired
            SignatureError: If signature verification fails
        """
        decode_options = options or {}
        if audience is None and "verify_aud" not in decode_options:
            decode_options["verify_aud"] = False

        kwargs: dict[str, Any] = {
            "jwt": token,
            "key": public_key,
            "algorithms": ALLOWED_ALGORITHMS,
            "options": decode_options,
            "leeway": leeway,
        }
        if audience is not None:
            kwargs["audience"] = audience

        try:
            return pyjwt.decode(**kwargs)
        except pyjwt.exceptions.ExpiredSignatureError as e:
            raise DelegationError(
                AAIPErrorCode.DELEGATION_EXPIRED,
                f"Delegation token has expired: {e}",
            ) from e
        except pyjwt.exceptions.ImmatureSignatureError as e:
            raise DelegationError(
                AAIPErrorCode.DELEGATION_NOT_YET_VALID,
                f"Delegation token is not yet valid: {e}",
            ) from e
        except pyjwt.exceptions.InvalidSignatureError as e:
            raise SignatureError(
                AAIPErrorCode.SIGNATURE_INVALID,
                f"JWT signature verification failed: {e}",
            ) from e
        except pyjwt.exceptions.InvalidAlgorithmError as e:
            raise SignatureError(
                AAIPErrorCode.UNSUPPORTED_ALGORITHM,
                f"Unsupported JWT algorithm: {e}",
            ) from e
        except pyjwt.exceptions.DecodeError as e:
            raise DelegationError(
                AAIPErrorCode.INVALID_TOKEN,
                f"Failed to decode JWT: {e}",
            ) from e
        except pyjwt.exceptions.InvalidTokenError as e:
            raise DelegationError(
                AAIPErrorCode.INVALID_TOKEN,
                f"Invalid JWT token: {e}",
            ) from e

    @staticmethod
    def get_unverified_header(token: str) -> dict[str, Any]:
        """Extract the JWT header without verification."""
        try:
            return pyjwt.get_unverified_header(token)
        except pyjwt.exceptions.DecodeError as e:
            raise DelegationError(
                AAIPErrorCode.INVALID_TOKEN,
                f"Failed to read JWT header: {e}",
            ) from e


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey, str]:
    """Generate Ed25519 keypair with kid — convenience function."""
    return AAIPCrypto.generate_keypair()


def public_key_to_jwk(
    public_key: Ed25519PublicKey, kid: str
) -> dict[str, str]:
    """Convert public key to JWK — convenience function."""
    return AAIPCrypto.public_key_to_jwk(public_key, kid)


def create_jwks(keys: list[dict[str, str]]) -> dict[str, Any]:
    """Create JWKS document — convenience function."""
    return AAIPCrypto.create_jwks(keys)
