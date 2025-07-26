# AI Agent Identity Protocol (AAIP) v1.0 Specification

> Standard delegation format for AI agent authorization

**Status**: Draft  
**Version**: 1.0  
**Date**: July 2025  
**Authors**: AAIP Working Group  

## Abstract

The AI Agent Identity Protocol (AAIP) defines a standard format for users to grant specific, time-bounded, and constrained permissions to AI agents. AAIP delegations are self-contained cryptographically signed messages that enable secure agent authorization without requiring central infrastructure.

## 1. Introduction

### 1.1 Problem Statement

AI agents need to prove they have user authorization to perform specific actions on behalf of users. Current solutions focus on agent identity verification but lack a standardized format for representing user-granted permissions.

### 1.2 Solution Overview

AAIP provides:

1. **Standard delegation format** with Ed25519 cryptographic signatures
2. **Self-contained tokens** with embedded public keys for verification
3. **Hierarchical scope system** for fine-grained permissions
4. **Built-in constraints** for spending limits, time windows, and content filtering
5. **Stateless design** requiring no central authority or registry

### 1.3 Design Principles

- **Self-Contained**: Delegations include all data needed for verification
- **Stateless**: No central authority or registry required
- **Cryptographically Secure**: Ed25519 signatures per RFC 8037
- **Time-Bounded**: All delegations have explicit expiration
- **Minimal Privilege**: Scoped permissions with explicit constraints

## 2. Core Concepts

### 2.1 Entities

#### 2.1.1 User
- Human or organization granting permissions
- Creates and signs delegations using their private key
- Identity represented as string (email, DID, custom identifier)

#### 2.1.2 Agent
- AI system acting on behalf of users
- Presents delegations to prove authorization
- Identity represented as string

#### 2.1.3 Service
- API or system that agents interact with
- Validates delegation signatures and constraints
- Makes authorization decisions based on delegation content

### 2.2 Key Concepts

#### 2.2.1 Delegation
A cryptographically signed message that grants specific permissions to an agent for a limited time with explicit constraints.

#### 2.2.2 Scope
Hierarchical permission identifiers using colon notation (e.g., `payments:send`, `data:read:profile`) with wildcard support.

#### 2.2.3 Constraints
Limitations on delegations including spending limits, time windows, domain restrictions, and content filtering.

## 3. Delegation Format

### 3.1 Structure

```json
{
  "aaip_version": "1.0",
  "delegation": {
    "id": "del_01H8QK9J2M3N4P5Q6R7S8T9V0W",
    "issuer": {
      "id": "user@example.com",
      "type": "oauth",
      "public_key": "ed25519-public-key-hex"
    },
    "subject": {
      "id": "agent-uuid-123",
      "type": "custom"
    },
    "scope": [
      "payments:send",
      "data:read:*",
      "email:send"
    ],
    "constraints": {
      "max_amount": {"value": 500, "currency": "USD"},
      "time_window": {
        "start": "2025-07-23T10:00:00Z",
        "end": "2025-07-24T10:00:00Z"
      },
      "allowed_domains": ["company.com", "*.partner.com"],
      "blocked_keywords": ["urgent", "limited time"]
    },
    "issued_at": "2025-07-23T10:00:00Z",
    "expires_at": "2025-07-24T10:00:00Z",
    "not_before": "2025-07-23T10:00:00Z"
  },
  "signature": "ed25519-signature-hex"
}
```

### 3.2 Field Definitions

#### 3.2.1 Required Fields
- `aaip_version`: Protocol version (currently "1.0")
- `delegation.id`: Unique delegation identifier (prefixed with `del_`)
- `delegation.issuer`: User granting the delegation
  - `id`: User's identity string (format depends on type)
  - `type`: Identity system type (`oauth`, `did`, `custom`)
  - `public_key`: Ed25519 public key for signature verification (hex format)
- `delegation.subject`: Agent receiving the delegation
  - `id`: Agent's identity string
  - `type`: Identity system type
- `delegation.scope`: Array of permission identifiers with wildcard support
- `delegation.issued_at`: When delegation was created (ISO 8601)
- `delegation.expires_at`: When delegation expires (ISO 8601)
- `delegation.not_before`: When delegation becomes valid (ISO 8601)
- `signature`: Ed25519 signature over canonical JSON (hex format)

#### 3.2.2 Optional Fields
- `delegation.constraints`: Additional limitations (see Section 5)

### 3.3 Canonical Serialization

For signature verification, delegations MUST be serialized using deterministic JSON:

1. Remove all whitespace
2. Sort object keys alphabetically at all levels
3. Use UTF-8 encoding
4. No trailing commas

Example canonical form:
```json
{"aaip_version":"1.0","delegation":{"constraints":{"max_amount":{"currency":"USD","value":500}},"expires_at":"2025-07-24T10:00:00Z","id":"del_01H8QK9J2M3N4P5Q6R7S8T9V0W","issued_at":"2025-07-23T10:00:00Z","issuer":{"id":"user@example.com","public_key":"ed25519-public-key-hex","type":"oauth"},"not_before":"2025-07-23T10:00:00Z","scope":["payments:send","data:read:*"],"subject":{"id":"agent-uuid-123","type":"custom"}}}
```

## 4. Scope System

### 4.1 Scope Format

Scopes use colon notation for hierarchical permissions:

```
service:action:resource
├── payments:send
├── payments:refund  
├── data:read:profile
├── data:write:profile
├── email:send
└── calendar:read
```

### 4.2 Wildcard Support

```json
{
  "scope": [
    "payments:send",        // Exact permission
    "data:read:*",         // All data read permissions
    "email:*",             // All email permissions
    "*"                    // All permissions (use with caution)
  ]
}
```

**Wildcard Rules:**
- `*` at the end matches anything following the prefix
- `data:read:*` matches `data:read:profile`, `data:read:email`, etc.
- `payments:*` matches `payments:send`, `payments:refund`, etc.
- `*` alone matches all possible scopes

### 4.3 Scope Validation

When validating a requested action against delegation scope:
1. Check for exact match first
2. Check for wildcard matches
3. Grant access if any match is found

## 5. Constraint System

### 5.1 Standard Constraints

All AAIP implementations MUST support these standard constraint types:

#### 5.1.1 Financial Constraints
```json
{
  "max_amount": {
    "value": 1000.00,
    "currency": "USD"
  }
}
```

Limits individual transaction amounts. Currency codes MUST follow ISO 4217.

#### 5.1.2 Time Window Constraints
```json
{
  "time_window": {
    "start": "2025-07-23T09:00:00Z",
    "end": "2025-07-23T17:00:00Z"
  }
}
```

Restricts when delegations can be used. Times MUST be in ISO 8601 format.

#### 5.1.3 Domain Constraints
```json
{
  "allowed_domains": ["company.com", "*.partner.com", "api.*"],
  "blocked_domains": ["competitor.com", "*.malicious.com"]
}
```

Controls which domains agents can interact with. Supports wildcard patterns:
- `*.example.com` - matches all subdomains of example.com
- `example.*` - matches example.com, example.org, etc.

#### 5.1.4 Content Constraints
```json
{
  "blocked_keywords": ["urgent", "limited time", "act now"]
}
```

Prevents agents from using specified keywords in content (case-insensitive matching).

### 5.2 Constraint Validation

Services MUST validate constraints before executing agent requests:
1. Standard constraints MUST be enforced
2. Unknown constraints are ignored
3. Constraint violations MUST reject the request

## 6. Identity Format

### 6.1 Identity String Format

AAIP uses simple string identifiers for both users and agents:

- **OAuth/Email**: `"user@example.com"`
- **DID**: `"did:example:123456"`  
- **Custom**: Any string identifier

### 6.2 Self-Contained Verification

AAIP delegations include the issuer's public key directly in the delegation:

```json
{
  "issuer": {
    "id": "user@example.com",
    "type": "oauth", 
    "public_key": "ed25519-public-key-hex"
  }
}
```

This enables verification without external key lookup.

### 6.3 Identity Validation

Identity strings are validated based on their declared type:

- `did` type: Must start with "did:"
- `oauth` type: Must contain "@" character
- `custom` type: Must be non-empty string
- Unknown types: Rejected

## 7. Cryptographic Security

### 7.1 Signature Algorithm

AAIP uses Ed25519 for all signatures:
- **Public Key**: 32 bytes (64 hex characters)
- **Private Key**: 32 bytes (64 hex characters)
- **Signature**: 64 bytes (128 hex characters)
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

### 7.4 Security Considerations

- **Replay attacks**: Prevented by unique delegation IDs and expiration times
- **Man-in-the-middle**: Prevented by cryptographic signatures
- **Privilege escalation**: Prevented by explicit scope validation
- **Data integrity**: Ensured by signature verification

## 8. Protocol Usage

### 8.1 Basic Flow

```
1. User creates delegation with scope and constraints
2. User signs delegation with their private key
3. User provides delegation to agent
4. Agent presents delegation to service
5. Service verifies signature and validates constraints
6. Service grants or denies access based on delegation
```

### 8.2 Verification Steps

Services MUST perform these verification steps in order:

1. **Format Validation**: Check all required fields exist
2. **Version Check**: Ensure `aaip_version` is supported
3. **Time Validation**: Check `expires_at`, `not_before`, and `issued_at`
4. **Signature Verification**: Verify Ed25519 signature using embedded public key
5. **Scope Check**: Validate requested action against delegation scope
6. **Constraint Enforcement**: Apply all standard constraints

## 9. Error Handling

### 9.1 Standard Error Codes

- `INVALID_DELEGATION`: Malformed delegation format
- `MISSING_REQUIRED_FIELD`: Required field missing from delegation
- `INVALID_FIELD_FORMAT`: Field value has incorrect format
- `SIGNATURE_INVALID`: Cryptographic signature verification failed
- `DELEGATION_EXPIRED`: Delegation past expiration time
- `DELEGATION_NOT_YET_VALID`: Delegation before not_before time
- `SCOPE_INSUFFICIENT`: Required permission not granted
- `CONSTRAINT_VIOLATED`: Request violates delegation constraints
- `IDENTITY_VERIFICATION_FAILED`: Agent identity could not be verified

### 9.2 Error Response Format

Services SHOULD return structured error responses:

```json
{
  "error": {
    "code": "CONSTRAINT_VIOLATED",
    "message": "Amount 1500 exceeds maximum 1000 USD",
    "details": {
      "delegation_id": "del_01H8QK9J2M3N4P5Q6R7S8T9V0W",
      "constraint_type": "max_amount",
      "attempted_value": 1500,
      "limit": 1000
    }
  }
}
```

## 10. Implementation Guidelines

### 10.1 For Service Providers

1. **Implement delegation verification** according to Section 8.2
2. **Define clear scope hierarchies** for your service's capabilities
3. **Enforce all standard constraints** as defined in Section 5.1
4. **Return structured errors** following Section 9.2

### 10.2 For Application Developers

1. **Always specify explicit timestamps** for delegation time bounds
2. **Follow principle of least privilege** when defining scopes
3. **Validate ISO 8601 timestamp formats** before creating delegations
4. **Use secure key generation** for Ed25519 keypairs

### 10.3 Library Implementation

AAIP libraries SHOULD provide:
- Delegation creation and signing functions
- Delegation verification and validation
- Constraint enforcement utilities
- Standard error types and handling

## 11. Examples

### 11.1 Simple Payment Authorization

```json
{
  "aaip_version": "1.0",
  "delegation": {
    "id": "del_payment_example_001",
    "issuer": {
      "id": "alice@example.com",
      "type": "oauth",
      "public_key": "b0a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1"
    },
    "subject": {
      "id": "payment_agent_v1",
      "type": "custom"
    },
    "scope": ["payments:authorize"],
    "constraints": {
      "max_amount": {"value": 100, "currency": "USD"},
      "allowed_domains": ["amazon.com", "uber.com"]
    },
    "issued_at": "2025-07-23T10:00:00Z",
    "expires_at": "2025-07-23T18:00:00Z",
    "not_before": "2025-07-23T10:00:00Z"
  },
  "signature": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
}
```

### 11.2 Multi-Service Authorization

```json
{
  "aaip_version": "1.0", 
  "delegation": {
    "id": "del_assistant_001",
    "issuer": {
      "id": "user@company.com",
      "type": "oauth",
      "public_key": "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8e9f0a1b2"
    },
    "subject": {
      "id": "personal_assistant",
      "type": "custom"
    },
    "scope": [
      "email:send",
      "calendar:write", 
      "payments:authorize"
    ],
    "constraints": {
      "max_amount": {"value": 50, "currency": "USD"},
      "time_window": {
        "start": "2025-07-23T09:00:00Z",
        "end": "2025-07-23T17:00:00Z"
      },
      "allowed_domains": ["company.com"],
      "blocked_keywords": ["urgent", "asap"]
    },
    "issued_at": "2025-07-23T08:30:00Z",
    "expires_at": "2025-07-23T18:00:00Z",
    "not_before": "2025-07-23T09:00:00Z"
  },
  "signature": "d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8e9f0a1b2c3d4e5f6a7b8c9d0e1f2"
}
```

## 12. References

### 12.1 Standards

- [RFC 8037: CFRG Elliptic Curve Signatures in JOSE](https://tools.ietf.org/html/rfc8037)
- [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://tools.ietf.org/html/rfc8032)
- [ISO 8601: Date and time format](https://www.iso.org/iso-8601-date-and-time-format.html)
- [ISO 4217: Currency codes](https://www.iso.org/iso-4217-currency-codes.html)

### 12.2 Cryptography

- [Ed25519: high-speed high-security signatures](https://ed25519.cr.yp.to/)

---

*This specification defines AAIP v1.0 - a standard delegation format for AI agent authorization.*