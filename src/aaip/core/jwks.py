"""
AAIP JWKS Key Resolution

Provides key resolution for verifying JWT delegations by kid.
Supports static key sets (testing/offline) and HTTP-based JWKS endpoints.
"""

from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import AAIPCrypto
from .exceptions import AAIPErrorCode, KeyResolutionError


@runtime_checkable
class KeyResolver(Protocol):
    """Protocol for resolving public keys by kid."""

    def resolve_key(self, kid: str) -> Ed25519PublicKey: ...


class StaticKeyResolver:
    """Resolves keys from a pre-loaded dict. Useful for tests and offline use."""

    def __init__(self, keys: dict[str, Ed25519PublicKey]) -> None:
        self._keys = keys

    def resolve_key(self, kid: str) -> Ed25519PublicKey:
        key = self._keys.get(kid)
        if key is None:
            raise KeyResolutionError(
                AAIPErrorCode.KEY_RESOLUTION_FAILED,
                f"No key found for kid: {kid}",
                {"kid": kid},
            )
        return key


class JWKSClient:
    """Resolves keys by fetching a JWKS endpoint over HTTP."""

    _ALLOWED_SCHEMES = frozenset(("https", "http"))

    def __init__(
        self,
        jwks_uri: str,
        cache_ttl: int = 300,
        timeout: int = 30,
    ) -> None:
        from urllib.parse import urlparse

        parsed = urlparse(jwks_uri)
        if parsed.scheme not in self._ALLOWED_SCHEMES:
            raise ValueError(
                f"JWKS URI must use http or https scheme, got: {parsed.scheme!r}"
            )
        self._jwks_uri = jwks_uri
        self._cache_ttl = cache_ttl
        self._timeout = timeout
        self._cache: dict[str, Ed25519PublicKey] = {}
        self._last_fetch: float = 0.0

    def resolve_key(self, kid: str) -> Ed25519PublicKey:
        if kid in self._cache:
            import time

            if time.time() - self._last_fetch < self._cache_ttl:
                return self._cache[kid]

        self._refresh_keys()

        key = self._cache.get(kid)
        if key is None:
            raise KeyResolutionError(
                AAIPErrorCode.KEY_RESOLUTION_FAILED,
                f"No key found for kid: {kid} at {self._jwks_uri}",
                {"kid": kid, "jwks_uri": self._jwks_uri},
            )
        return key

    def _refresh_keys(self) -> None:
        import time
        import urllib.request

        try:
            req = urllib.request.Request(
                self._jwks_uri,
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # nosec B310
                jwks_data = resp.read()
        except Exception as e:
            raise KeyResolutionError(
                AAIPErrorCode.KEY_RESOLUTION_FAILED,
                f"Failed to fetch JWKS from {self._jwks_uri}: {e}",
                {"jwks_uri": self._jwks_uri},
            ) from e

        import json

        try:
            jwks = json.loads(jwks_data)
        except (json.JSONDecodeError, ValueError) as e:
            raise KeyResolutionError(
                AAIPErrorCode.KEY_RESOLUTION_FAILED,
                f"Invalid JWKS response from {self._jwks_uri}: {e}",
            ) from e

        new_cache: dict[str, Ed25519PublicKey] = {}
        for key_dict in jwks.get("keys", []):
            if key_dict.get("kty") != "OKP" or key_dict.get("crv") != "Ed25519":
                continue
            key_kid = key_dict.get("kid")
            if not key_kid:
                continue
            try:
                public_key = AAIPCrypto.jwk_to_public_key(key_dict)
                new_cache[key_kid] = public_key
            except (ValueError, KeyError, TypeError):
                continue  # skip malformed keys

        self._cache = new_cache
        self._last_fetch = time.time()


def resolve_key_from_token(token: str, resolver: KeyResolver) -> Ed25519PublicKey:
    """Extract kid from an unverified JWT header and resolve the public key."""
    header = AAIPCrypto.get_unverified_header(token)
    kid = header.get("kid")
    if not kid:
        raise KeyResolutionError(
            AAIPErrorCode.KEY_RESOLUTION_FAILED,
            "JWT header missing kid",
        )
    return resolver.resolve_key(kid)
