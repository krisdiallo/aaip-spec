# AI Agent Identity Protocol (AAIP) v1.0 Specification

> Complete identity solution for AI agents - verification, authorization, and delegation

**Status**: Draft  
**Version**: 1.0  
**Date**: July 2025  
**Authors**: AAIP Working Group  

## Abstract

The AI Agent Identity Protocol (AAIP) provides a universal authorization layer for AI agents that works with any underlying identity system. While existing identity solutions solve agent verification ("who is this agent?"), AAIP adds the missing piece: user authorization and delegation ("what can this agent do on my behalf?").

AAIP enables users to grant specific, time-bounded, and constrained permissions to AI agents while maintaining cryptographic proof of authorization and complete audit trails.

## 1. Introduction

### 1.1 Problem Statement

Current AI agent infrastructure has a critical gap:

- &#x2713; **Identity Verification**: Multiple solutions exist (Agntcy, DIDs, OAuth, etc.)
- &#x2717; **Authorization & Delegation**: No standardized way for users to grant specific permissions to agents

This creates security risks, limits agent capabilities, and prevents enterprise adoption.

### 1.2 Solution Overview

AAIP provides a universal authorization layer that:

1. **Works with any identity system** via adapters
2. **Enables user delegation** with cryptographic proof
3. **Supports fine-grained permissions** and constraints
4. **Provides audit trails** for accountability
5. **Maintains security** through time-bounded tokens and minimal privilege

### 1.3 Design Principles

- **Identity System Agnostic**: Works with any underlying identity (DIDs, OAuth, custom, etc.)
- **Cryptographically Secure**: Ed25519 signatures and verifiable delegations
- **Minimal Privilege**: Scoped permissions with explicit constraints
- **Time-Bounded**: All delegations have expiration times
- **Auditable**: Complete trail of authorizations and actions
- **Revocable**: Users can instantly withdraw permissions

## 2. Core Concepts

### 2.1 Entities

#### 2.1.1 User
- Human or organization granting permissions
- Controls delegation creation and revocation
- May use any identity system for authentication

#### 2.1.2 Agent
- AI system acting on behalf of users
- Has an identity from any supported identity system
- Presents delegations when accessing services

#### 2.1.3 Service
- API, platform, or system that agents interact with
- Validates both agent identity and AAIP delegations
- Enforces authorization constraints

#### 2.1.4 Identity Adapter
- Bridge between AAIP and specific identity systems
- Standardizes identity verification across systems
- Enables AAIP to work with any identity format

### 2.2 Key Concepts

#### 2.2.1 Delegation
A cryptographically signed authorization token that grants specific permissions to an agent for a limited time with explicit constraints.

#### 2.2.2 Scope
Hierarchical permission identifiers (e.g., `payments.authorize`, `calendar.read`) that define what actions an agent can perform.

#### 2.2.3 Constraints
Additional limitations on delegations (e.g., spending limits, time windows, data filters) that services must enforce.

#### 2.2.4 Audit Trail
Immutable record of delegation creation, usage, and revocation for accountability and compliance.

## 3. Delegation Format

### 3.1 Structure

```json
{
  "aaip_version": "1.0",
  "delegation": {
    "id": "del_01H8QK9J2M3N4P5Q6R7S8T9V0W",
    "issuer": {
      "identity": "user-identity-in-any-format",
      "identity_system": "agntcy|did|oauth|custom",
      "public_key": "ed25519-public-key-hex"
    },
    "subject": {
      "identity": "agent-identity-in-any-format", 
      "identity_system": "agntcy|did|oauth|custom"
    },
    "scope": [
      "payments.authorize",
      "calendar.read"
    ],
    "constraints": {
      "max_amount": {"value": 500, "currency": "USD"},
      "time_window": {
        "start": "2025-07-23T10:00:00Z",
        "end": "2025-07-24T10:00:00Z"
      },
      "rate_limit": {"requests": 100, "period": "1h"}
    },
    "issued_at": "2025-07-23T10:00:00Z",
    "expires_at": "2025-07-24T10:00:00Z",
    "not_before": "2025-07-23T10:00:00Z"
  },
  "signature": "ed25519-signature-hex"
}
```

### 3.2 Field Definitions

#### 3.2.1 Header Fields
- `aaip_version`: Protocol version (currently "1.0")

#### 3.2.2 Delegation Fields
- `id`: Unique delegation identifier (prefixed with `del_`)
- `issuer`: User granting the delegation
  - `identity`: User's identity in their chosen system format
  - `identity_system`: Type of identity system used
  - `public_key`: Ed25519 public key for signature verification
- `subject`: Agent receiving the delegation
  - `identity`: Agent's identity in their identity system format
  - `identity_system`: Type of identity system the agent uses
- `scope`: Array of hierarchical permission identifiers
- `constraints`: Optional additional limitations
- `issued_at`: When delegation was created (ISO 8601)
- `expires_at`: When delegation expires (ISO 8601)
- `not_before`: When delegation becomes valid (ISO 8601)

#### 3.2.3 Signature
Ed25519 signature over the canonical JSON representation of the delegation object.

### 3.3 Canonical Serialization

For signature verification, delegations MUST be serialized using deterministic JSON:

1. Remove all whitespace
2. Sort object keys alphabetically at all levels
3. Use UTF-8 encoding
4. No trailing commas or optional fields

Example canonical form:
```json
{"aaip_version":"1.0","delegation":{"constraints":{"max_amount":{"currency":"USD","value":500}},"expires_at":"2025-07-24T10:00:00Z","id":"del_01H8QK9J2M3N4P5Q6R7S8T9V0W","issued_at":"2025-07-23T10:00:00Z","issuer":{"identity":"user123","identity_system":"custom","public_key":"abc123"},"not_before":"2025-07-23T10:00:00Z","scope":["payments.authorize"],"subject":{"identity":"agent456","identity_system":"custom"}}}
```

## 4. Scope System

### 4.1 Hierarchical Structure

Scopes use dot notation for hierarchical permissions:

```
service.action.resource
├── payments
│   ├── payments.authorize (can authorize payments)
│   ├── payments.read (can view payment history)
│   └── payments.refund (can process refunds)
├── calendar
│   ├── calendar.read (can view calendar events)
│   ├── calendar.write (can create/modify events)
│   └── calendar.share (can share calendar access)
└── data
    ├── data.read.personal (can read personal data)
    ├── data.read.public (can read public data)
    └── data.export (can export data)
```

### 4.2 Scope Inheritance

More specific scopes inherit permissions from broader scopes:
- `payments` grants all payment-related permissions
- `payments.authorize` grants only authorization permission
- Scopes MUST be validated from most specific to least specific

### 4.3 Reserved Scopes

- `*`: Grants all permissions (use with extreme caution)
- `aaip.manage`: Can create/revoke delegations for this user
- `aaip.audit`: Can access delegation audit logs

### 4.4 Custom Scopes

Services can define custom scope hierarchies. Best practices:
- Use reverse domain notation: `com.example.service.action`
- Document all available scopes
- Follow principle of least privilege
- Group related permissions logically

## 5. Constraint System

### 5.1 Standard Constraints

#### 5.1.1 Financial Constraints
```json
{
  "max_amount": {"value": 1000, "currency": "USD"},
  "daily_limit": {"value": 500, "currency": "USD"},
  "merchant_whitelist": ["amazon.com", "stripe.com"]
}
```

#### 5.1.2 Time Constraints
```json
{
  "time_window": {
    "start": "2025-07-23T09:00:00Z",
    "end": "2025-07-23T17:00:00Z"
  },
  "business_hours_only": true,
  "timezone": "America/New_York"
}
```

#### 5.1.3 Rate Limiting
```json
{
  "rate_limit": {"requests": 100, "period": "1h"},
  "burst_limit": {"requests": 10, "period": "1m"}
}
```

#### 5.1.4 Data Constraints
```json
{
  "data_filters": {
    "exclude_pii": true,
    "max_records": 1000,
    "allowed_fields": ["name", "email", "public_data"]
  }
}
```

### 5.2 Custom Constraints

Services can define custom constraints following the pattern:
```json
{
  "custom_constraint_name": {
    "type": "constraint_type",
    "value": "constraint_value",
    "metadata": {}
  }
}
```

### 5.3 Constraint Validation

Services MUST:
1. Validate all constraints before executing agent requests
2. Reject requests that violate any constraint
3. Log constraint violations for audit purposes
4. Return specific error messages for constraint failures

## 6. Identity Adapter Interface

### 6.1 Purpose

Identity adapters enable AAIP to work with any underlying identity system by providing a standardized interface for identity verification.

### 6.2 Adapter Interface

```python
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class IdentityAdapter(ABC):
    @abstractmethod
    def verify_identity(self, identity: str, proof: Dict[str, Any]) -> bool:
        """Verify that the provided proof validates the identity."""
        pass
    
    @abstractmethod
    def extract_public_key(self, identity: str) -> Optional[str]:
        """Extract or derive the public key for this identity."""
        pass
    
    @abstractmethod
    def normalize_identity(self, identity: str) -> str:
        """Convert identity to canonical format for this system."""
        pass
    
    @abstractmethod
    def get_identity_metadata(self, identity: str) -> Dict[str, Any]:
        """Get additional metadata about this identity."""
        pass
```

### 6.3 Standard Adapters

#### 6.3.1 DID Adapter
```python
class DIDAdapter(IdentityAdapter):
    def verify_identity(self, identity: str, proof: Dict[str, Any]) -> bool:
        # Verify DID document signature
        pass
    
    def extract_public_key(self, identity: str) -> Optional[str]:
        # Extract key from DID document
        pass
```

#### 6.3.2 OAuth Adapter
```python
class OAuthAdapter(IdentityAdapter):
    def verify_identity(self, identity: str, proof: Dict[str, Any]) -> bool:
        # Verify OAuth token with issuer
        pass
    
    def extract_public_key(self, identity: str) -> Optional[str]:
        # Derive key from OAuth client credentials
        pass
```

#### 6.3.3 Custom Adapter
```python
class CustomAdapter(IdentityAdapter):
    def __init__(self, identity_resolver_func):
        self.resolver = identity_resolver_func
    
    def verify_identity(self, identity: str, proof: Dict[str, Any]) -> bool:
        return self.resolver(identity, proof)
```

## 7. Cryptographic Security

### 7.1 Signature Algorithm

AAIP uses Ed25519 for all signatures:
- **Public Key**: 32 bytes
- **Private Key**: 32 bytes  
- **Signature**: 64 bytes
- **Encoding**: Hexadecimal for JSON representation

### 7.2 Signature Process

1. **Create delegation object** (without signature field)
2. **Serialize to canonical JSON**
3. **Generate Ed25519 signature** over UTF-8 bytes
4. **Add signature field** with hex-encoded signature

### 7.3 Verification Process

1. **Extract delegation object** (remove signature field)
2. **Serialize to canonical JSON**
3. **Verify Ed25519 signature** using issuer's public key
4. **Validate delegation constraints** and expiration

### 7.4 Key Management

- Users **MUST** securely store private keys
- Public keys **MUST** be discoverable via identity systems
- Key rotation **SHOULD** be supported by identity adapters
- Compromised keys **MUST** result in delegation revocation

### 7.5 Security Considerations

- **Replay attacks**: Prevented by unique delegation IDs and expiration times
- **Man-in-the-middle**: Prevented by cryptographic signatures
- **Privilege escalation**: Prevented by explicit scope validation
- **Data integrity**: Ensured by signature verification

## 8. Protocol Flows

### 8.1 Delegation Creation

```mermaid
sequenceDiagram
    participant User
    participant AAIP
    participant Agent
    participant IdentitySystem
    
    User->>AAIP: Request delegation creation
    AAIP->>IdentitySystem: Verify user identity
    IdentitySystem-->>AAIP: Identity confirmed
    AAIP->>AAIP: Generate delegation
    AAIP->>AAIP: Sign with user's private key
    AAIP-->>User: Return signed delegation
    User->>Agent: Provide delegation
```

### 8.2 Agent Authorization

```mermaid
sequenceDiagram
    participant Agent
    participant Service
    participant AAIP
    participant IdentitySystem
    
    Agent->>Service: Request with delegation
    Service->>IdentitySystem: Verify agent identity
    IdentitySystem-->>Service: Identity valid
    Service->>AAIP: Verify delegation signature
    AAIP-->>Service: Signature valid
    Service->>Service: Check constraints & scope
    Service-->>Agent: Authorized response
```

### 8.3 Delegation Revocation

```mermaid
sequenceDiagram
    participant User
    participant AAIP
    participant Service
    participant Agent
    
    User->>AAIP: Revoke delegation
    AAIP->>AAIP: Add to revocation list
    AAIP->>Service: Notify revocation
    Service->>Service: Update revocation cache
    Agent->>Service: Request with revoked delegation
    Service-->>Agent: 403 Forbidden (revoked)
```

## 9. Error Handling

### 9.1 Error Response Format

```json
{
  "error": {
    "code": "AAIP_ERROR_CODE",
    "message": "Human readable description",
    "details": {
      "delegation_id": "del_01H8QK9J2M3N4P5Q6R7S8T9V0W",
      "constraint_violated": "max_amount",
      "attempted_value": 1500,
      "limit": 1000
    }
  }
}
```

### 9.2 Standard Error Codes

- `INVALID_DELEGATION`: Malformed delegation format
- `SIGNATURE_INVALID`: Cryptographic signature verification failed
- `DELEGATION_EXPIRED`: Delegation past expiration time
- `DELEGATION_NOT_YET_VALID`: Delegation before not_before time
- `DELEGATION_REVOKED`: Delegation has been revoked
- `SCOPE_INSUFFICIENT`: Required permission not granted
- `CONSTRAINT_VIOLATED`: Request violates delegation constraints
- `IDENTITY_VERIFICATION_FAILED`: Agent identity could not be verified
- `RATE_LIMIT_EXCEEDED`: Too many requests within time window

### 9.3 Error Handling Best Practices

- Log all authorization failures for audit
- Provide specific error messages for debugging
- Don't leak sensitive information in error responses
- Implement exponential backoff for rate limiting
- Cache revocation lists to prevent revoked delegation usage

## 10. Implementation Guidelines

### 10.1 For Identity System Providers

1. **Implement AAIP adapter** for your identity format
2. **Provide public key discovery** mechanism
3. **Support delegation metadata** in identity documents
4. **Consider AAIP delegation management** in your tools

### 10.2 For Agent Framework Maintainers

1. **Add AAIP authorization layer** to your framework
2. **Integrate with multiple identity adapters**
3. **Provide delegation management utilities**
4. **Include constraint validation helpers**

### 10.3 For Service Providers

1. **Implement delegation verification** in your APIs
2. **Define clear scope hierarchies** for your services
3. **Enforce all delegation constraints**
4. **Provide audit trails** for delegation usage

### 10.4 For Application Developers

1. **Use existing AAIP libraries** when possible
2. **Follow principle of least privilege** in scope requests
3. **Implement proper error handling**
4. **Respect user privacy** in delegation design

## 11. Compliance and Privacy

### 11.1 GDPR Compliance

- Users retain control over their data through delegation constraints
- Right to be forgotten supported through delegation revocation
- Data minimization achieved through scoped permissions
- Audit trails provide transparency into data usage

### 11.2 Other Regulations

- **CCPA**: User control and transparency through delegations
- **SOX**: Audit trails for financial delegations
- **HIPAA**: Data constraints for healthcare applications
- **PCI DSS**: Payment constraints and secure delegation storage

### 11.3 Privacy Best Practices

- Minimize data in delegation scopes
- Use time-bounded delegations
- Implement delegation revocation
- Audit delegation usage regularly
- Encrypt delegation storage where applicable

## 12. Versioning and Extensions

### 12.1 Version Compatibility

- Major versions indicate breaking changes
- Minor versions add backward-compatible features
- Patch versions fix bugs without breaking changes
- Services MUST support multiple AAIP versions during transitions

### 12.2 Extension Mechanism

Custom fields can be added to delegations using vendor prefixes:

```json
{
  "delegation": {
    "scope": ["payments.authorize"],
    "x-vendor-custom-field": "custom-value",
    "x-another-vendor-extension": {
      "custom": "data"
    }
  }
}
```

### 12.3 Future Considerations

- **Multi-signature delegations**: Multiple users authorizing single agent
- **Delegation chains**: Agents delegating to other agents
- **Zero-knowledge proofs**: Privacy-preserving authorization
- **Quantum-resistant signatures**: Post-quantum cryptography migration

## 13. References

### 13.1 Standards

- [RFC 7515: JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [RFC 8037: CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)](https://tools.ietf.org/html/rfc8037)
- [W3C Decentralized Identifiers (DIDs) v1.0](https://www.w3.org/TR/did-core/)
- [OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)

### 13.2 Cryptography

- [Ed25519: high-speed high-security signatures](https://ed25519.cr.yp.to/)
- [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://tools.ietf.org/html/rfc8032)

### 13.3 Related Work

- [UCAN: User Controlled Authorization Networks](https://ucan.xyz/)
- [Macaroons: Cookies with Contextual Caveats](https://research.google/pubs/pub41892/)
- [Object Capability Model](https://en.wikipedia.org/wiki/Object-capability_model)

---

## Appendix A: Complete Examples

### A.1 Simple Payment Authorization

```json
{
  "aaip_version": "1.0",
  "delegation": {
    "id": "del_payment_example_001",
    "issuer": {
      "identity": "did:example:user123",
      "identity_system": "did",
      "public_key": "b0a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"
    },
    "subject": {
      "identity": "agent_assistant_v2",
      "identity_system": "custom"
    },
    "scope": ["payments.authorize"],
    "constraints": {
      "max_amount": {"value": 100, "currency": "USD"},
      "merchant_whitelist": ["amazon.com", "uber.com"]
    },
    "issued_at": "2025-07-23T10:00:00Z",
    "expires_at": "2025-07-23T18:00:00Z",
    "not_before": "2025-07-23T10:00:00Z"
  },
  "signature": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
}
```

### A.2 Complex Multi-Service Authorization

```json
{
  "aaip_version": "1.0", 
  "delegation": {
    "id": "del_travel_agent_001",
    "issuer": {
      "identity": "alice@example.com",
      "identity_system": "oauth",
      "public_key": "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8e9f0a1b2"
    },
    "subject": {
      "identity": "did:agntcy:travel_assistant_001",
      "identity_system": "agntcy"
    },
    "scope": [
      "flights.search",
      "flights.book", 
      "hotels.search",
      "hotels.book",
      "payments.authorize",
      "calendar.write"
    ],
    "constraints": {
      "max_amount": {"value": 3000, "currency": "USD"},
      "travel_dates": {
        "start": "2025-08-15",
        "end": "2025-08-25"
      },
      "destinations": ["NYC", "LAX", "CHI"],
      "hotel_rating_min": 3,
      "flight_class": ["economy", "premium_economy"]
    },
    "issued_at": "2025-07-23T14:30:00Z",
    "expires_at": "2025-07-30T23:59:59Z",
    "not_before": "2025-07-23T14:30:00Z"
  },
  "signature": "d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8e9f0a1b2c3d4e5f6a7b8c9d0e1f2"
}
```

## Appendix B: Reference Implementation Pseudocode

### B.1 Delegation Creation

```python
def create_delegation(
    issuer_identity: str,
    issuer_private_key: str,
    agent_identity: str,
    scope: List[str],
    constraints: Dict[str, Any],
    expires_in: str = "24h"
) -> Dict[str, Any]:
    
    now = datetime.utcnow()
    expiry = now + parse_duration(expires_in)
    
    delegation = {
        "aaip_version": "1.0",
        "delegation": {
            "id": generate_delegation_id(),
            "issuer": {
                "identity": issuer_identity,
                "identity_system": detect_identity_system(issuer_identity),
                "public_key": derive_public_key(issuer_private_key)
            },
            "subject": {
                "identity": agent_identity,
                "identity_system": detect_identity_system(agent_identity)
            },
            "scope": scope,
            "constraints": constraints,
            "issued_at": now.isoformat() + "Z",
            "expires_at": expiry.isoformat() + "Z",
            "not_before": now.isoformat() + "Z"
        }
    }
    
    canonical_json = serialize_canonical(delegation)
    signature = ed25519_sign(issuer_private_key, canonical_json.encode('utf-8'))
    delegation["signature"] = signature.hex()
    
    return delegation
```

### B.2 Delegation Verification

```python
def verify_delegation(
    delegation: Dict[str, Any],
    identity_adapter: IdentityAdapter
) -> bool:
    
    # Extract signature
    signature_hex = delegation.pop("signature")
    signature = bytes.fromhex(signature_hex)
    
    # Verify delegation format
    if not validate_delegation_format(delegation):
        return False
    
    # Check expiration
    now = datetime.utcnow()
    expires_at = datetime.fromisoformat(delegation["delegation"]["expires_at"].rstrip('Z'))
    not_before = datetime.fromisoformat(delegation["delegation"]["not_before"].rstrip('Z'))
    
    if now >= expires_at or now < not_before:
        return False
    
    # Verify agent identity
    agent_identity = delegation["delegation"]["subject"]["identity"]
    if not identity_adapter.verify_identity(agent_identity, {}):
        return False
    
    # Verify issuer signature
    issuer_public_key = delegation["delegation"]["issuer"]["public_key"]
    canonical_json = serialize_canonical(delegation)
    
    return ed25519_verify(
        bytes.fromhex(issuer_public_key),
        canonical_json.encode('utf-8'),
        signature
    )
```

---

*This specification defines AAIP v1.0 - the complete identity solution for AI agents.*
