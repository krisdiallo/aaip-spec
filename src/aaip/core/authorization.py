"""
AAIP Authorization Types and Functionality

JWT-based delegation model with UCAN-style delegation chain support.
"""

import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import AAIPCrypto
from .exceptions import (
    AAIPErrorCode,
    ChainError,
    ConstraintError,
    DelegationError,
)
from .jwks import KeyResolver, resolve_key_from_token

DEFAULT_MAX_CHAIN_DEPTH = 5


@dataclass
class Delegation:
    """Represents a decoded AAIP v2.0 JWT delegation."""

    iss: str
    aud: str
    iat: int
    exp: int
    nbf: int
    jti: str
    scope: list[str]
    proofs: list[str]
    aaip_version: str
    issuer_type: str
    subject_type: str
    constraints: dict[str, Any]
    token: str

    @classmethod
    def from_jwt_payload(cls, payload: dict[str, Any], token: str) -> "Delegation":
        aaip_claim = payload.get("aaip", {})
        scope_raw = payload.get("scope", "")
        if isinstance(scope_raw, str):
            scope_list = scope_raw.split() if scope_raw else []
        else:
            scope_list = list(scope_raw)

        return cls(
            iss=payload.get("iss", ""),
            aud=payload.get("aud", ""),
            iat=payload.get("iat", 0),
            exp=payload.get("exp", 0),
            nbf=payload.get("nbf", 0),
            jti=payload.get("jti", ""),
            scope=scope_list,
            proofs=payload.get("prf", []),
            aaip_version=aaip_claim.get("version", "2.0"),
            issuer_type=aaip_claim.get("issuer_type", "custom"),
            subject_type=aaip_claim.get("subject_type", "custom"),
            constraints=aaip_claim.get("constraints", {}),
            token=token,
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "iss": self.iss,
            "aud": self.aud,
            "iat": self.iat,
            "exp": self.exp,
            "nbf": self.nbf,
            "jti": self.jti,
            "scope": " ".join(self.scope),
            "aaip": {
                "version": self.aaip_version,
                "issuer_type": self.issuer_type,
                "subject_type": self.subject_type,
                "constraints": self.constraints,
            },
        }
        if self.proofs:
            result["prf"] = self.proofs
        return result


# ---------------------------------------------------------------------------
# Constraint validation (format-independent, unchanged from v1.0)
# ---------------------------------------------------------------------------


def _validate_max_amount(
    constraint: dict[str, Any], request_data: dict[str, Any]
) -> None:
    if "amount" not in request_data:
        raise ConstraintError(
            AAIPErrorCode.CONSTRAINT_VIOLATED,
            "max_amount constraint requires 'amount' field in request",
        )
    request_amount = request_data["amount"]
    max_amount = constraint.get("value", 0)
    constraint_currency = constraint.get("currency", "USD")
    request_currency = request_data.get("currency", "USD")

    if request_currency != constraint_currency:
        raise ConstraintError(
            AAIPErrorCode.CONSTRAINT_VIOLATED,
            f"Currency mismatch: {request_currency} != {constraint_currency}",
        )
    if request_amount > max_amount:
        raise ConstraintError(
            AAIPErrorCode.CONSTRAINT_VIOLATED,
            f"Amount {request_amount} exceeds maximum {max_amount} {constraint_currency}",
        )


def _validate_time_window(
    constraint: dict[str, Any], request_data: dict[str, Any]
) -> None:
    now = datetime.now(timezone.utc)

    if "start" in constraint:
        try:
            start_time = datetime.fromisoformat(
                constraint["start"].replace("Z", "+00:00")
            )
            if now < start_time:
                raise ConstraintError(
                    AAIPErrorCode.CONSTRAINT_VIOLATED,
                    f"Request made before allowed start time {constraint['start']}",
                    {"current_time": now.isoformat(), "start_time": constraint["start"]},
                )
        except ValueError as e:
            raise ConstraintError(
                AAIPErrorCode.INVALID_FIELD_FORMAT, f"Invalid start time format: {e}"
            ) from e

    if "end" in constraint:
        try:
            end_time = datetime.fromisoformat(constraint["end"].replace("Z", "+00:00"))
            if now >= end_time:
                raise ConstraintError(
                    AAIPErrorCode.CONSTRAINT_VIOLATED,
                    f"Request made after allowed end time {constraint['end']}",
                    {"current_time": now.isoformat(), "end_time": constraint["end"]},
                )
        except ValueError as e:
            raise ConstraintError(
                AAIPErrorCode.INVALID_FIELD_FORMAT, f"Invalid end time format: {e}"
            ) from e


def _validate_allowed_domains(
    constraint: list[str], request_data: dict[str, Any]
) -> None:
    domains = request_data.get("domains", [])
    if isinstance(request_data.get("domain"), str):
        domains = [request_data["domain"]]

    for domain in domains:
        if domain in constraint:
            continue
        allowed = False
        for allowed_domain in constraint:
            if allowed_domain.startswith("*."):
                suffix = allowed_domain[2:]
                if domain.endswith(suffix):
                    allowed = True
                    break
            elif allowed_domain.endswith("*"):
                prefix = allowed_domain[:-1]
                if domain.startswith(prefix):
                    allowed = True
                    break
        if not allowed:
            raise ConstraintError(
                AAIPErrorCode.CONSTRAINT_VIOLATED,
                f"Domain '{domain}' not in allowed domains",
            )


def _validate_blocked_domains(
    constraint: list[str], request_data: dict[str, Any]
) -> None:
    domains = request_data.get("domains", [])
    if isinstance(request_data.get("domain"), str):
        domains = [request_data["domain"]]

    for domain in domains:
        if domain in constraint:
            raise ConstraintError(
                AAIPErrorCode.CONSTRAINT_VIOLATED, f"Domain '{domain}' is blocked"
            )
        for blocked_domain in constraint:
            if blocked_domain.startswith("*."):
                suffix = blocked_domain[2:]
                if domain.endswith(suffix):
                    raise ConstraintError(
                        AAIPErrorCode.CONSTRAINT_VIOLATED,
                        f"Domain '{domain}' is blocked by pattern '{blocked_domain}'",
                    )
            elif blocked_domain.endswith("*"):
                prefix = blocked_domain[:-1]
                if domain.startswith(prefix):
                    raise ConstraintError(
                        AAIPErrorCode.CONSTRAINT_VIOLATED,
                        f"Domain '{domain}' is blocked by pattern '{blocked_domain}'",
                    )


def _validate_blocked_keywords(
    constraint: list[str], request_data: dict[str, Any]
) -> None:
    content = request_data.get("content", "")
    if not isinstance(content, str):
        return
    content_lower = content.lower()
    for keyword in constraint:
        if keyword.lower() in content_lower:
            raise ConstraintError(
                AAIPErrorCode.CONSTRAINT_VIOLATED,
                f"Content contains blocked keyword: '{keyword}'",
            )


def validate_constraints(
    constraints: dict[str, Any], request_data: dict[str, Any]
) -> bool:
    """
    Validate delegation constraints against request data.

    Returns True if all constraints pass.
    Raises ConstraintError if any constraint is violated.
    """
    for constraint_name, constraint_value in constraints.items():
        if constraint_name == "max_amount":
            _validate_max_amount(constraint_value, request_data)
        elif constraint_name == "time_window":
            _validate_time_window(constraint_value, request_data)
        elif constraint_name == "allowed_domains":
            _validate_allowed_domains(constraint_value, request_data)
        elif constraint_name == "blocked_domains":
            _validate_blocked_domains(constraint_value, request_data)
        elif constraint_name == "blocked_keywords":
            _validate_blocked_keywords(constraint_value, request_data)
    return True


# ---------------------------------------------------------------------------
# Scope matching
# ---------------------------------------------------------------------------


def _scope_matches(granted: str, required: str) -> bool:
    """Check if a granted scope covers a required scope."""
    if granted == required:
        return True
    if granted == "*":
        return True
    if granted.endswith("*"):
        prefix = granted[:-1]
        if required.startswith(prefix):
            return True
    return False


def is_scope_subset(child_scopes: list[str], parent_scopes: list[str]) -> bool:
    """Check that every child scope is covered by at least one parent scope."""
    for child in child_scopes:
        if not any(_scope_matches(parent, child) for parent in parent_scopes):
            return False
    return True


# ---------------------------------------------------------------------------
# Attenuation checking for delegation chains
# ---------------------------------------------------------------------------


def are_constraints_attenuated(
    child_constraints: dict[str, Any],
    parent_constraints: dict[str, Any],
) -> bool:
    """
    Check that child constraints are equal or stricter than parent constraints.

    Returns True if the child is properly attenuated.
    """
    for key, parent_value in parent_constraints.items():
        if key not in child_constraints:
            return False

        child_value = child_constraints[key]

        if key == "max_amount":
            p_val = parent_value.get("value", 0)
            c_val = child_value.get("value", 0)
            p_cur = parent_value.get("currency", "USD")
            c_cur = child_value.get("currency", "USD")
            if c_cur != p_cur or c_val > p_val:
                return False

        elif key == "time_window":
            p_start = parent_value.get("start", "")
            p_end = parent_value.get("end", "")
            c_start = child_value.get("start", "")
            c_end = child_value.get("end", "")
            if c_start < p_start or c_end > p_end:
                return False

        elif key == "allowed_domains":
            if not set(child_value).issubset(set(parent_value)):
                return False

        elif key == "blocked_domains":
            if not set(parent_value).issubset(set(child_value)):
                return False

        elif key == "blocked_keywords":
            if not set(parent_value).issubset(set(child_value)):
                return False

    return True


# ---------------------------------------------------------------------------
# Authorization checking
# ---------------------------------------------------------------------------


def check_delegation_authorization(
    delegation: Delegation,
    required_resource: str,
    required_action: str,
    context: Optional[dict[str, Any]] = None,
) -> bool:
    """
    Check if a delegation authorizes the requested action.

    Returns True if delegation authorizes the action.
    """
    now = time.time()
    if now >= delegation.exp:
        return False

    required_scope = f"{required_resource}:{required_action}"
    scope_granted = False
    for granted_scope in delegation.scope:
        if _scope_matches(granted_scope, required_scope):
            scope_granted = True
            break

    if not scope_granted:
        return False

    if context and delegation.constraints:
        try:
            validate_constraints(delegation.constraints, context)
        except ConstraintError:
            return False

    return True


# ---------------------------------------------------------------------------
# Delegation creation
# ---------------------------------------------------------------------------


def generate_delegation_id() -> str:
    return f"del_{secrets.token_urlsafe(20)}"


def _to_unix_timestamp(value: Union[int, float, str, datetime]) -> int:
    """Convert various time representations to a unix timestamp."""
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, datetime):
        return int(value.timestamp())
    if isinstance(value, str):
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return int(dt.timestamp())
    raise ValueError(f"Cannot convert {type(value)} to timestamp")


def create_signed_delegation(
    issuer_identity: str,
    issuer_identity_system: str,
    private_key: Any,
    kid: str,
    subject_identity: str,
    subject_identity_system: str,
    scope: list[str],
    expires_at: Union[int, str, datetime],
    not_before: Union[int, str, datetime],
    constraints: Optional[dict[str, Any]] = None,
    proofs: Optional[list[str]] = None,
) -> str:
    """
    Create a cryptographically signed JWT delegation.

    Args:
        issuer_identity: Identity of the user/agent granting permission (JWT iss)
        issuer_identity_system: Identity system type for issuer
        private_key: Ed25519 private key for signing
        kid: Key identifier for JWT header
        subject_identity: Identity of the agent receiving permission (JWT aud)
        subject_identity_system: Identity system type for subject
        scope: List of permission scopes to grant
        expires_at: Expiration time (unix timestamp, ISO string, or datetime)
        not_before: Start time (unix timestamp, ISO string, or datetime)
        constraints: Optional constraints on the delegation
        proofs: Optional parent delegation JWTs (for delegation chains)

    Returns:
        Signed JWT string

    Raises:
        ValueError: If parameters are invalid
        SignatureError: If signing fails
    """
    if not scope:
        raise ValueError("Invalid delegation: must include at least one scope")
    if not issuer_identity or not issuer_identity.strip():
        raise ValueError("Invalid delegation: issuer identity cannot be empty")
    if not subject_identity or not subject_identity.strip():
        raise ValueError("Invalid delegation: subject identity cannot be empty")

    exp_ts = _to_unix_timestamp(expires_at)
    nbf_ts = _to_unix_timestamp(not_before)
    iat_ts = int(datetime.now(timezone.utc).timestamp())

    payload: dict[str, Any] = {
        "iss": issuer_identity,
        "aud": subject_identity,
        "iat": iat_ts,
        "exp": exp_ts,
        "nbf": nbf_ts,
        "jti": generate_delegation_id(),
        "scope": " ".join(scope),
        "aaip": {
            "version": "2.0",
            "issuer_type": issuer_identity_system,
            "subject_type": subject_identity_system,
            "constraints": constraints or {},
        },
    }

    if proofs:
        payload["prf"] = proofs

    return AAIPCrypto.encode_delegation_jwt(payload, private_key, kid)


# ---------------------------------------------------------------------------
# Delegation verification
# ---------------------------------------------------------------------------


def verify_delegation(
    token: str,
    key_resolver: Union["KeyResolver", Ed25519PublicKey],
    allowed_issuers: Optional[list[str]] = None,
    max_chain_depth: int = DEFAULT_MAX_CHAIN_DEPTH,
    _depth: int = 0,
) -> Delegation:
    """
    Verify a delegation JWT and its proof chain.

    Args:
        token: JWT string
        key_resolver: JWKS key resolver or direct Ed25519 public key
        allowed_issuers: Optional whitelist of allowed issuers
        max_chain_depth: Maximum delegation chain depth (default 5)

    Returns:
        Decoded Delegation object

    Raises:
        DelegationError: If token is invalid
        SignatureError: If signature verification fails
        ChainError: If delegation chain is invalid
        KeyResolutionError: If key resolution fails
    """
    if _depth > max_chain_depth:
        raise ChainError(
            AAIPErrorCode.CHAIN_VALIDATION_FAILED,
            f"Delegation chain exceeds maximum depth of {max_chain_depth}",
        )

    if isinstance(key_resolver, Ed25519PublicKey):
        public_key = key_resolver
    else:
        public_key = resolve_key_from_token(token, key_resolver)

    payload = AAIPCrypto.decode_delegation_jwt(token, public_key)

    aaip_claim = payload.get("aaip", {})
    version = aaip_claim.get("version", "")
    if version != "2.0":
        raise DelegationError(
            AAIPErrorCode.INVALID_DELEGATION,
            f"Unsupported AAIP version: {version}",
        )

    scope_raw = payload.get("scope", "")
    scope_list = scope_raw.split() if isinstance(scope_raw, str) else list(scope_raw)
    if not scope_list:
        raise DelegationError(
            AAIPErrorCode.INVALID_DELEGATION,
            "Delegation must have at least one scope",
        )

    if allowed_issuers is not None:
        iss = payload.get("iss", "")
        if iss not in allowed_issuers:
            raise DelegationError(
                AAIPErrorCode.INVALID_DELEGATION,
                f"Issuer '{iss}' not in allowed issuers",
            )

    delegation = Delegation.from_jwt_payload(payload, token)

    if delegation.proofs:
        _verify_chain(delegation, key_resolver, max_chain_depth, _depth)

    return delegation


def _verify_chain(
    child: Delegation,
    key_resolver: Union["KeyResolver", Ed25519PublicKey],
    max_chain_depth: int,
    current_depth: int,
) -> None:
    """Verify the delegation chain (proofs) for a child delegation."""
    for proof_token in child.proofs:
        parent = verify_delegation(
            proof_token,
            key_resolver,
            max_chain_depth=max_chain_depth,
            _depth=current_depth + 1,
        )

        if not is_scope_subset(child.scope, parent.scope):
            raise ChainError(
                AAIPErrorCode.ATTENUATION_VIOLATED,
                f"Child scope {child.scope} is not a subset of parent scope {parent.scope}",
            )

        parent_constraints = parent.constraints
        child_constraints = child.constraints
        if parent_constraints and not are_constraints_attenuated(
            child_constraints, parent_constraints
        ):
            raise ChainError(
                AAIPErrorCode.ATTENUATION_VIOLATED,
                "Child constraints are not properly attenuated from parent",
            )

        if child.exp > parent.exp:
            raise ChainError(
                AAIPErrorCode.ATTENUATION_VIOLATED,
                "Child delegation expires after parent",
            )
