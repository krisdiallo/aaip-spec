"""
AAIP Identity Types

Simple identity representation as defined in AAIP v2.0 specification.
"""

from dataclasses import dataclass
from typing import Any


@dataclass
class Identity:
    """Represents an identity in any identity system (user, agent, or service)."""

    id: str
    type: str

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "type": self.type}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Identity":
        return cls(id=data["id"], type=data["type"])


def validate_identity_format(identity: str, identity_type: str) -> bool:
    """
    Validate identity string format for given type.

    Returns True if identity format is valid.
    """
    if not identity or not isinstance(identity, str):
        return False

    if identity_type == "did":
        return identity.startswith("did:")
    elif identity_type == "oauth":
        return "@" in identity
    elif identity_type == "custom":
        return len(identity) > 0
    else:
        return False
