"""
AAIP Authorization Types and Functionality

This module contains all authorization and delegation-related types and functionality.
"""

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Union

from .exceptions import AAIPErrorCode, ConstraintError
from .identity import Identity


@dataclass
class DelegationPayload:
    """The core delegation data structure."""

    id: str
    issuer: Identity
    subject: Identity
    scope: list[str]
    constraints: dict[str, Any]
    issued_at: str
    expires_at: str
    not_before: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": self.id,
            "issuer": self.issuer.to_dict(),
            "subject": self.subject.to_dict(),
            "scope": self.scope,
            "constraints": self.constraints,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "not_before": self.not_before,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DelegationPayload":
        """Create from dictionary representation."""
        return cls(
            id=data["id"],
            issuer=Identity.from_dict(data["issuer"]),
            subject=Identity.from_dict(data["subject"]),
            scope=data["scope"],
            constraints=data["constraints"],
            issued_at=data["issued_at"],
            expires_at=data["expires_at"],
            not_before=data["not_before"],
        )


@dataclass
class Delegation:
    """AAIP delegation with signature."""

    aaip_version: str
    delegation: DelegationPayload
    signature: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "aaip_version": self.aaip_version,
            "delegation": self.delegation.to_dict(),
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Delegation":
        """Create from dictionary representation."""
        return cls(
            aaip_version=data["aaip_version"],
            delegation=DelegationPayload.from_dict(data["delegation"]),
            signature=data["signature"],
        )


# Standard constraint validation functions


def _validate_max_amount(
    constraint: dict[str, Any], request_data: dict[str, Any]
) -> None:
    """Validate maximum amount per transaction."""
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
    """Validate time window constraints."""
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
                    {
                        "current_time": now.isoformat(),
                        "start_time": constraint["start"],
                    },
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
    """Validate that domains in the request are allowed."""
    domains = request_data.get("domains", [])
    if isinstance(request_data.get("domain"), str):
        domains = [request_data["domain"]]

    for domain in domains:
        # Check for exact match first
        if domain in constraint:
            continue

        # Check for wildcard matches
        allowed = False
        for allowed_domain in constraint:
            if allowed_domain.startswith("*."):
                # Subdomain wildcard: *.example.com matches api.example.com
                suffix = allowed_domain[2:]  # Remove *.
                if domain.endswith(suffix):
                    allowed = True
                    break
            elif allowed_domain.endswith("*"):
                # Prefix wildcard: example.* matches example.com, example.org
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
    """Validate that domains in the request are not blocked."""
    domains = request_data.get("domains", [])
    if isinstance(request_data.get("domain"), str):
        domains = [request_data["domain"]]

    for domain in domains:
        # Check for exact match first
        if domain in constraint:
            raise ConstraintError(
                AAIPErrorCode.CONSTRAINT_VIOLATED, f"Domain '{domain}' is blocked"
            )

        # Check for wildcard matches
        for blocked_domain in constraint:
            if blocked_domain.startswith("*."):
                # Subdomain wildcard: *.malicious.com blocks api.malicious.com
                suffix = blocked_domain[2:]  # Remove *.
                if domain.endswith(suffix):
                    raise ConstraintError(
                        AAIPErrorCode.CONSTRAINT_VIOLATED,
                        f"Domain '{domain}' is blocked by pattern '{blocked_domain}'",
                    )
            elif blocked_domain.endswith("*"):
                # Prefix wildcard: competitor.* blocks competitor.com, competitor.org
                prefix = blocked_domain[:-1]
                if domain.startswith(prefix):
                    raise ConstraintError(
                        AAIPErrorCode.CONSTRAINT_VIOLATED,
                        f"Domain '{domain}' is blocked by pattern '{blocked_domain}'",
                    )


def _validate_blocked_keywords(
    constraint: list[str], request_data: dict[str, Any]
) -> None:
    """Validate that content does not contain blocked keywords."""
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

    Args:
        constraints: Delegation constraints to validate
        request_data: Request data to validate against

    Returns:
        True if all constraints pass

    Raises:
        ConstraintError: If any constraint is violated
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
        # Unknown constraints are ignored per spec

    return True


def check_delegation_authorization(
    delegation: Delegation,
    required_resource: str,
    required_action: str,
    context: Optional[dict[str, Any]] = None,
) -> bool:
    """
    Check if a delegation authorizes the requested action.

    Args:
        delegation: Delegation to check
        required_resource: Required resource
        required_action: Required action
        context: Optional context for constraint validation

    Returns:
        True if delegation authorizes the action
    """
    # Check if delegation is expired
    now = datetime.now(timezone.utc)
    try:
        expires_at = datetime.fromisoformat(
            delegation.delegation.expires_at.replace("Z", "+00:00")
        )
        if now >= expires_at:
            return False
    except ValueError:
        return False

    # Check scope with wildcard support
    required_scope = f"{required_resource}:{required_action}"
    scope_granted = False

    for granted_scope in delegation.delegation.scope:
        # Check for exact match
        if granted_scope == required_scope:
            scope_granted = True
            break
        # Check for wildcard match
        elif granted_scope.endswith("*"):
            prefix = granted_scope[:-1]
            if required_scope.startswith(prefix):
                scope_granted = True
                break
        # Check for full wildcard
        elif granted_scope == "*":
            scope_granted = True
            break

    if not scope_granted:
        return False

    # Check constraints if context provided
    if context and delegation.delegation.constraints:
        try:
            validate_constraints(delegation.delegation.constraints, context)
        except ConstraintError:
            return False

    return True


# Delegation creation utilities


def generate_delegation_id() -> str:
    """Generate a unique delegation ID."""
    return f"del_{secrets.token_urlsafe(20)}"


def _create_delegation_payload(
    issuer_identity: str,
    issuer_identity_system: str,
    subject_identity: str,
    subject_identity_system: str,
    scope: list[str],
    expires_at: str,
    not_before: str,
    constraints: Optional[dict[str, Any]] = None,
    issuer_public_key: Optional[str] = None,
) -> DelegationPayload:
    """
    Create a delegation payload (internal function).

    This creates an unsigned delegation payload for use by create_signed_delegation().
    This function is internal and should not be used directly - use create_signed_delegation()
    for creating cryptographically secure delegations.

    Args:
        issuer_identity: Identity of the user granting permission
        issuer_identity_system: Type of issuer's identity system
        subject_identity: Identity of the agent receiving permission
        subject_identity_system: Type of agent's identity system
        scope: List of permissions being granted
        expires_at: ISO 8601 expiration timestamp
        not_before: ISO 8601 start timestamp
        constraints: Optional constraints on the delegation
        issuer_public_key: Optional public key for the issuer (for signed delegations)

    Returns:
        Delegation payload ready for signing
    """
    if not scope:
        raise ValueError("Invalid delegation: must include at least one scope")

    # Validate identities
    if not issuer_identity or not issuer_identity.strip():
        raise ValueError("Invalid delegation: issuer identity cannot be empty")

    if not subject_identity or not subject_identity.strip():
        raise ValueError("Invalid delegation: subject identity cannot be empty")

    # Generate issued_at timestamp
    now = datetime.now(timezone.utc)

    # Create delegation payload
    return DelegationPayload(
        id=generate_delegation_id(),
        issuer=Identity(
            id=issuer_identity,
            type=issuer_identity_system,
            public_key=issuer_public_key,
        ),
        subject=Identity(id=subject_identity, type=subject_identity_system),
        scope=scope,
        constraints=constraints or {},
        issued_at=now.isoformat().replace("+00:00", "Z"),
        expires_at=expires_at,
        not_before=not_before,
    )


def verify_delegation(
    delegation: Union[dict[str, Any], Delegation], verify_signature: bool = True
) -> bool:
    """
    Verify a delegation's structure, timing, and signature.

    Args:
        delegation: Delegation to verify (either dict or Delegation object)
        verify_signature: Whether to perform cryptographic signature verification

    Returns:
        True if delegation is valid, False otherwise
    """
    try:
        # Convert to dict if it's a Delegation object
        if hasattr(delegation, "to_dict"):
            delegation_dict = delegation.to_dict()
        else:
            delegation_dict = delegation

        # Check required fields
        required_fields = ["aaip_version", "delegation", "signature"]
        if not all(field in delegation_dict for field in required_fields):
            return False

        delegation_payload = delegation_dict["delegation"]
        required_payload_fields = [
            "id",
            "issuer",
            "subject",
            "scope",
            "issued_at",
            "expires_at",
        ]
        if not all(field in delegation_payload for field in required_payload_fields):
            return False

        # Verify AAIP version
        from .. import AAIP_VERSION

        if delegation_dict["aaip_version"] != AAIP_VERSION:
            return False

        # Verify time bounds
        now = datetime.now(timezone.utc)

        # Parse timestamps
        try:
            issued_at = datetime.fromisoformat(
                delegation_payload["issued_at"].rstrip("Z")
            ).replace(tzinfo=timezone.utc)
            expires_at = datetime.fromisoformat(
                delegation_payload["expires_at"].rstrip("Z")
            ).replace(tzinfo=timezone.utc)

            if "not_before" in delegation_payload:
                not_before = datetime.fromisoformat(
                    delegation_payload["not_before"].rstrip("Z")
                ).replace(tzinfo=timezone.utc)
                if now < not_before:
                    return False
        except (ValueError, TypeError):
            return False

        # Check if delegation has expired
        if now >= expires_at:
            return False

        # Check if delegation was issued in the future (clock skew tolerance: 5 minutes)
        from datetime import timedelta

        if issued_at > now + timedelta(minutes=5):
            return False

        # Verify scope format
        scope = delegation_payload.get("scope", [])
        if not isinstance(scope, list) or not scope:
            return False

        for scope_item in scope:
            if not isinstance(scope_item, str) or not scope_item.strip():
                return False

        # Verify signature if requested
        if verify_signature:
            signature = delegation_dict.get("signature")
            if not signature or not isinstance(signature, str):
                return False

            # Get public key from issuer (must be present in delegation)
            issuer = delegation_payload.get("issuer", {})
            public_key = issuer.get("public_key")

            if not public_key:
                # No public key available - cannot verify signature
                return False

            # Verify signature with embedded public key
            from .crypto import AAIPCrypto

            delegation_without_sig = {
                "aaip_version": delegation_dict["aaip_version"],
                "delegation": delegation_payload,
            }
            if not AAIPCrypto.verify_delegation_signature(
                delegation_without_sig, signature, public_key
            ):
                return False

        # All validation checks passed
        return True

    except Exception:
        return False


def create_signed_delegation(
    issuer_identity: str,
    issuer_identity_system: str,
    issuer_private_key: str,
    subject_identity: str,
    subject_identity_system: str,
    scope: list[str],
    expires_at: str,
    not_before: str,
    constraints: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Create a cryptographically signed delegation.

    Args:
        issuer_identity: Identity of the user granting permission
        issuer_identity_system: Identity system type for issuer
        issuer_private_key: Private key for signing (hex format)
        subject_identity: Identity of the agent receiving permission
        subject_identity_system: Identity system type for agent
        scope: List of permission scopes to grant
        expires_at: ISO 8601 expiration timestamp (e.g., "2025-07-24T10:00:00Z")
        not_before: ISO 8601 timestamp when delegation becomes valid (e.g., "2025-07-23T10:00:00Z")
        constraints: Optional constraints on the delegation

    Returns:
        Signed delegation dictionary

    Raises:
        ValueError: If parameters are invalid
        SignatureError: If signing fails
    """
    # Validate timestamp formats
    try:
        datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        datetime.fromisoformat(not_before.replace("Z", "+00:00"))
    except ValueError as e:
        raise ValueError(f"Invalid timestamp format: {e}") from e

    # Extract public key from private key
    from .crypto import AAIPCrypto

    public_key = AAIPCrypto.extract_public_key_from_private(issuer_private_key)

    # Create the delegation payload with public key
    delegation_payload = _create_delegation_payload(
        issuer_identity=issuer_identity,
        issuer_identity_system=issuer_identity_system,
        subject_identity=subject_identity,
        subject_identity_system=subject_identity_system,
        scope=scope,
        constraints=constraints,
        expires_at=expires_at,
        not_before=not_before,
        issuer_public_key=public_key,
    )

    # Create signed delegation
    return AAIPCrypto.create_signed_delegation(
        delegation_payload.to_dict(), issuer_private_key
    )


# Type aliases for convenience
DelegationID = str
ResourcePath = str
