"""
AAIP Identity Types

Simple identity representation as defined in AAIP v1.0 specification.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class Identity:
    """Represents an identity in any identity system (user, agent, or service)."""
    id: str
    type: str
    public_key: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            "id": self.id,
            "type": self.type
        }
        
        if self.public_key:
            result["public_key"] = self.public_key
        
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Identity':
        """Create from dictionary representation."""
        return cls(
            id=data["id"],
            type=data["type"],
            public_key=data.get("public_key")
        )


def validate_identity_format(identity: str, identity_type: str) -> bool:
    """
    Validate identity string format for given type.
    
    Args:
        identity: Identity string to validate
        identity_type: Type of identity system
        
    Returns:
        True if identity format is valid
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
        return False  # Unknown types are rejected