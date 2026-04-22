"""
Tests for AAIP v2.0 cryptographic functionality.
"""

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aaip.core import (
    AAIPCrypto,
    DelegationError,
    SignatureError,
    create_jwks,
    generate_keypair,
    public_key_to_jwk,
)


class TestKeyGeneration:
    def test_generate_keypair(self):
        private_key, public_key, kid = generate_keypair()

        assert isinstance(private_key, Ed25519PrivateKey)
        assert isinstance(public_key, Ed25519PublicKey)
        assert isinstance(kid, str)
        assert len(kid) > 0

    def test_keypairs_are_unique(self):
        _, _, kid1 = generate_keypair()
        _, _, kid2 = generate_keypair()
        assert kid1 != kid2

    def test_kid_is_deterministic_for_same_key(self):
        priv, pub, kid = generate_keypair()
        kid2 = AAIPCrypto.compute_kid(pub)
        assert kid == kid2


class TestJWKConversion:
    def test_public_key_to_jwk(self):
        _, pub, kid = generate_keypair()
        jwk = public_key_to_jwk(pub, kid)

        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert jwk["kid"] == kid
        assert jwk["use"] == "sig"
        assert jwk["alg"] == "EdDSA"
        assert "x" in jwk
        assert "d" not in jwk

    def test_private_key_to_jwk(self):
        priv, _, kid = generate_keypair()
        jwk = AAIPCrypto.private_key_to_jwk(priv, kid)

        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert "d" in jwk
        assert "x" in jwk

    def test_jwk_roundtrip(self):
        _, pub, kid = generate_keypair()
        jwk = public_key_to_jwk(pub, kid)
        restored = AAIPCrypto.jwk_to_public_key(jwk)

        original_bytes = pub.public_bytes(
            encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
            format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.Raw,
        )
        restored_bytes = restored.public_bytes(
            encoding=__import__("cryptography.hazmat.primitives.serialization", fromlist=["Encoding"]).Encoding.Raw,
            format=__import__("cryptography.hazmat.primitives.serialization", fromlist=["PublicFormat"]).PublicFormat.Raw,
        )
        assert original_bytes == restored_bytes

    def test_jwk_rejects_non_ed25519(self):
        with pytest.raises(SignatureError):
            AAIPCrypto.jwk_to_public_key({"kty": "RSA", "crv": "P-256"})

    def test_create_jwks(self):
        _, pub1, kid1 = generate_keypair()
        _, pub2, kid2 = generate_keypair()
        jwk1 = public_key_to_jwk(pub1, kid1)
        jwk2 = public_key_to_jwk(pub2, kid2)
        jwks = create_jwks([jwk1, jwk2])

        assert "keys" in jwks
        assert len(jwks["keys"]) == 2
        assert jwks["keys"][0]["kid"] == kid1
        assert jwks["keys"][1]["kid"] == kid2


class TestJWTEncodeDecode:
    def test_encode_decode_roundtrip(self):
        priv, pub, kid = generate_keypair()

        payload = {
            "iss": "user@example.com",
            "aud": "agent_001",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "nbf": int(time.time()) - 60,
            "jti": "del_test_001",
            "scope": "payments:authorize",
            "aaip": {"version": "2.0", "issuer_type": "oauth", "subject_type": "custom", "constraints": {}},
        }

        token = AAIPCrypto.encode_delegation_jwt(payload, priv, kid)
        assert isinstance(token, str)
        assert token.count(".") == 2

        decoded = AAIPCrypto.decode_delegation_jwt(token, pub)
        assert decoded["iss"] == "user@example.com"
        assert decoded["aud"] == "agent_001"
        assert decoded["scope"] == "payments:authorize"

    def test_jwt_header_contains_kid(self):
        priv, _, kid = generate_keypair()

        payload = {
            "iss": "test",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "nbf": int(time.time()) - 60,
        }
        token = AAIPCrypto.encode_delegation_jwt(payload, priv, kid)
        header = AAIPCrypto.get_unverified_header(token)

        assert header["alg"] == "EdDSA"
        assert header["kid"] == kid
        assert header["typ"] == "JWT"

    def test_wrong_key_rejected(self):
        priv1, _, kid1 = generate_keypair()
        _, pub2, _ = generate_keypair()

        payload = {
            "iss": "test",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "nbf": int(time.time()) - 60,
        }
        token = AAIPCrypto.encode_delegation_jwt(payload, priv1, kid1)

        with pytest.raises(SignatureError):
            AAIPCrypto.decode_delegation_jwt(token, pub2)

    def test_expired_jwt_rejected(self):
        priv, pub, kid = generate_keypair()

        payload = {
            "iss": "test",
            "iat": int(time.time()) - 7200,
            "exp": int(time.time()) - 3600,
            "nbf": int(time.time()) - 7200,
        }
        token = AAIPCrypto.encode_delegation_jwt(payload, priv, kid)

        with pytest.raises(DelegationError) as exc_info:
            AAIPCrypto.decode_delegation_jwt(token, pub, leeway=0)
        assert "expired" in str(exc_info.value).lower()

    def test_tampered_jwt_rejected(self):
        priv, pub, kid = generate_keypair()

        payload = {
            "iss": "test",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "nbf": int(time.time()) - 60,
        }
        token = AAIPCrypto.encode_delegation_jwt(payload, priv, kid)

        # Tamper with the payload segment
        parts = token.split(".")
        parts[1] = parts[1][:-3] + "abc"
        tampered = ".".join(parts)

        with pytest.raises((SignatureError, DelegationError)):
            AAIPCrypto.decode_delegation_jwt(tampered, pub)

    def test_malformed_token_rejected(self):
        _, pub, _ = generate_keypair()

        with pytest.raises(DelegationError):
            AAIPCrypto.decode_delegation_jwt("not-a-jwt", pub)


class TestEdgeCases:
    def test_unicode_in_claims(self):
        priv, pub, kid = generate_keypair()

        payload = {
            "iss": "用户@example.com",
            "aud": "тест_агент",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "nbf": int(time.time()) - 60,
            "scope": "测试:授权",
        }
        token = AAIPCrypto.encode_delegation_jwt(payload, priv, kid)
        decoded = AAIPCrypto.decode_delegation_jwt(token, pub)

        assert decoded["iss"] == "用户@example.com"
        assert decoded["aud"] == "тест_агент"
        assert decoded["scope"] == "测试:授权"
