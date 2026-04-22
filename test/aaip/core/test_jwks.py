"""
Tests for AAIP v2.0 JWKS key resolution.
"""

import pytest

from aaip.core import (
    KeyResolutionError,
    StaticKeyResolver,
    generate_keypair,
)
from aaip.core.crypto import AAIPCrypto
from aaip.core.jwks import resolve_key_from_token


class TestStaticKeyResolver:
    def test_resolve_known_key(self):
        _, pub, kid = generate_keypair()
        resolver = StaticKeyResolver({kid: pub})

        resolved = resolver.resolve_key(kid)
        assert resolved is pub

    def test_resolve_unknown_kid_raises(self):
        _, pub, kid = generate_keypair()
        resolver = StaticKeyResolver({kid: pub})

        with pytest.raises(KeyResolutionError):
            resolver.resolve_key("unknown_kid")

    def test_multiple_keys(self):
        _, pub1, kid1 = generate_keypair()
        _, pub2, kid2 = generate_keypair()
        resolver = StaticKeyResolver({kid1: pub1, kid2: pub2})

        assert resolver.resolve_key(kid1) is pub1
        assert resolver.resolve_key(kid2) is pub2

    def test_empty_resolver(self):
        resolver = StaticKeyResolver({})
        with pytest.raises(KeyResolutionError):
            resolver.resolve_key("any_kid")


class TestResolveKeyFromToken:
    def test_resolves_key_from_valid_token(self):
        priv, pub, kid = generate_keypair()
        resolver = StaticKeyResolver({kid: pub})

        import time
        payload = {
            "iss": "test",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "nbf": int(time.time()) - 60,
        }
        token = AAIPCrypto.encode_delegation_jwt(payload, priv, kid)

        resolved = resolve_key_from_token(token, resolver)
        assert resolved is pub

    def test_missing_kid_raises(self):
        import jwt as pyjwt
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        priv = Ed25519PrivateKey.generate()

        # Encode without kid in header
        import time
        token = pyjwt.encode(
            {"iss": "test", "iat": int(time.time()), "exp": int(time.time()) + 3600},
            priv,
            algorithm="EdDSA",
        )

        resolver = StaticKeyResolver({})
        with pytest.raises(KeyResolutionError):
            resolve_key_from_token(token, resolver)


class TestKeyResolverProtocol:
    def test_static_resolver_is_key_resolver(self):
        from aaip.core.jwks import KeyResolver
        resolver = StaticKeyResolver({})
        assert isinstance(resolver, KeyResolver)
