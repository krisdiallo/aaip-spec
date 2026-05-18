# AI Agent Identity Protocol (AAIP) v2.0

> JWT-based delegation chains with JWKS key resolution for AI agent authorization

[![GitHub Stars](https://img.shields.io/github/stars/krisdiallo/aaip-spec)](https://github.com/krisdiallo/aaip-spec/stargazers)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version](https://img.shields.io/badge/AAIP-v2.0-blue)](#specification)

## What is AAIP?

AAIP is a standard protocol for users to grant specific, time-bounded, and constrained permissions to AI agents. It uses JWT tokens signed with EdDSA (Ed25519), UCAN-style delegation chains for sub-delegation and attenuation, and JWKS-based key resolution for verifying signatures.

## Key Features

- **JWT Delegation Format**: EdDSA-signed JWT tokens with standard claims
- **Delegation Chains**: UCAN-style proof chains (`prf` claim) for sub-delegation and attenuation
- **JWKS Key Resolution**: Keys resolved via `kid` and JWKS endpoints
- **Hierarchical Scopes**: Fine-grained permissions with wildcard support (OAuth2-style space-separated format)
- **Standard Constraints**: Built-in spending limits, time windows, and content filtering
- **Protocol-First**: Simple foundation for building agent authorization systems

## Quick Example

```python
from aaip import create_signed_delegation, verify_delegation, generate_keypair, StaticKeyResolver

# Generate keypair for signing
private_key, public_key, kid = generate_keypair()

# Create a signed JWT delegation
token = create_signed_delegation(
    issuer_identity="user@example.com",
    issuer_identity_system="oauth",
    private_key=private_key,
    kid=kid,
    subject_identity="agent_001",
    subject_identity_system="custom",
    scope=["payments:authorize"],
    expires_at="2025-08-26T10:00:00Z",
    not_before="2025-07-26T10:00:00Z",
    constraints={"max_amount": {"value": 500, "currency": "USD"}}
)

# Verify the delegation
resolver = StaticKeyResolver({kid: public_key})
delegation = verify_delegation(token, resolver)
print(f"Delegation valid: {delegation.iss} -> {delegation.aud}")
```

## Delegation Format

AAIP delegations are JWT tokens signed with EdDSA (Ed25519):

### Header
```json
{
  "alg": "EdDSA",
  "typ": "JWT",
  "kid": "key-id-from-jwks"
}
```

### Payload
```json
{
  "iss": "user@example.com",
  "aud": "agent-uuid-123",
  "iat": 1690108800,
  "exp": 1690195200,
  "nbf": 1690108800,
  "jti": "del_01H8QK9J2M3N4P5Q6R7S8T9V0W",
  "scope": "payments:send data:read:*",
  "prf": [],
  "aaip": {
    "version": "2.0",
    "issuer_type": "oauth",
    "subject_type": "custom",
    "constraints": {
      "max_amount": {"value": 500, "currency": "USD"},
      "time_window": {
        "start": "2025-07-23T10:00:00Z",
        "end": "2025-07-24T10:00:00Z"
      }
    }
  }
}
```

## Standard Constraints

AAIP v2.0 defines standard constraint types that all implementations must support:

### Financial Constraints
```json
{
  "max_amount": {
    "value": 1000.0,
    "currency": "USD"
  }
}
```

### Time Windows
```json
{
  "time_window": {
    "start": "2025-07-23T09:00:00Z",
    "end": "2025-07-23T17:00:00Z"
  }
}
```

### Domain Controls
```json
{
  "allowed_domains": ["company.com", "*.partner.com"],
  "blocked_domains": ["competitor.com", "*.malicious.com"]
}
```

### Content Filtering
```json
{
  "blocked_keywords": ["urgent", "limited time", "act now"]
}
```

## Security Features

- **JWT with EdDSA Signatures**: Industry-standard token format with Ed25519 cryptographic security
- **JWKS Key Resolution**: Keys resolved via `kid` from JWKS endpoints, enabling key rotation and centralized management
- **Delegation Chains**: UCAN-style `prf` claim enables verifiable sub-delegation with attenuation
- **Time-Bounded**: Standard JWT `exp` / `nbf` claims prevent replay attacks
- **Minimal Privilege**: Scoped permissions with explicit constraints
- **Scope Attenuation**: Sub-delegations must be a subset of parent scopes

## Installation

```bash
pip install aaip
```

## Examples

### FastAPI Integration
Create REST APIs with AAIP authorization using the standard `Authorization: Bearer` header:

```python
from fastapi import FastAPI, Depends, HTTPException, Request
from aaip import verify_delegation, check_delegation_authorization, JWKSClient

app = FastAPI()

jwks_resolver = JWKSClient("https://auth.example.com/.well-known/jwks.json")

async def get_delegation_from_header(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing Bearer token")
    token = auth.removeprefix("Bearer ")
    return verify_delegation(token, jwks_resolver)

def require_scope(required_scope: str):
    def dependency(delegation=Depends(get_delegation_from_header)):
        if not check_delegation_authorization(delegation, *required_scope.split(":")):
            raise HTTPException(403, f"Insufficient scope: requires {required_scope}")
        return delegation
    return dependency

@app.get("/.well-known/jwks.json")
async def jwks_endpoint():
    """Serve public keys for delegation verification."""
    return {"keys": get_registered_keys()}

@app.post("/payment")
async def process_payment(
    payment_data: PaymentRequest,
    delegation=Depends(require_scope("payments:authorize"))
):
    # Payment processing with delegation authorization
    return {"status": "success"}
```

### LangChain Integration
Add AAIP authorization to LangChain agents using JWT-based delegations:

```python
from langchain.agents import create_openai_functions_agent
from aaip import verify_delegation, check_delegation_authorization, StaticKeyResolver

class AAIPLangChainAgent:
    def __init__(self, agent_identity, resolver):
        self.agent_identity = agent_identity
        self.resolver = resolver
        self.current_delegation = None
        # ... setup LangChain agent
    
    def set_delegation(self, token):
        delegation = verify_delegation(token, self.resolver)
        self.current_delegation = delegation
        return delegation
    
    def execute_task(self, task):
        if not self.current_delegation:
            raise AuthorizationError("No delegation available")
        # ... execute with authorization checks using delegation claims
```

## Use Cases

### Personal Assistants
- **Calendar Management**: Schedule meetings with time constraints
- **Email Communication**: Send emails with domain restrictions  
- **Shopping**: Purchase items with spending limits
- **Travel Booking**: Book flights/hotels within budget constraints

### Enterprise Applications
- **Workflow Automation**: Agents accessing APIs with role-based permissions
- **Customer Service**: Agents handling requests with compliance boundaries
- **Data Processing**: Agents analyzing data with privacy controls
- **DevOps**: Infrastructure management with safety limits

## Verification Process

Services verify delegations in these steps:

1. **JWT Decode**: Decode the JWT token and validate the EdDSA signature
2. **JWKS Key Lookup**: Resolve the signing key via `kid` from a JWKS endpoint or static resolver
3. **Time Validation**: Check `exp` and `nbf` claims for expiration and validity
4. **Chain Verification**: If `prf` claims are present, verify the full delegation chain and confirm scope/constraint attenuation
5. **Scope Check**: Validate requested action against the `scope` claim
6. **Constraint Enforcement**: Apply all constraints from the `aaip` claim

## Error Handling

AAIP defines standard error codes:

- `INVALID_DELEGATION`: Malformed delegation format
- `SIGNATURE_INVALID`: Cryptographic signature verification failed
- `DELEGATION_EXPIRED`: Delegation past expiration time
- `SCOPE_INSUFFICIENT`: Required permission not granted
- `CONSTRAINT_VIOLATED`: Request violates delegation constraints
- `CHAIN_ERROR`: Delegation chain validation failed (e.g., broken proof chain, scope not attenuated)
- `KEY_RESOLUTION_ERROR`: Unable to resolve signing key from JWKS endpoint or static resolver

## Implementation Status

### Core Protocol
- [x] AAIP v2.0 specification complete
- [x] Python reference implementation
- [x] JWT with EdDSA (Ed25519) cryptographic security
- [x] JWKS-based key resolution
- [x] UCAN-style delegation chains
- [x] Standard constraint validation
- [x] Comprehensive test suite

### Examples
- [x] FastAPI integration example (Bearer token + JWKS endpoint)
- [x] LangChain integration example (JWT-based flow)
- [x] Complete documentation

### Language Support
- [x] Python SDK
- [ ] JavaScript SDK
- [ ] Go SDK  
- [ ] Rust SDK

## Getting Started

### 1. Installation
```bash
pip install aaip
```

### 2. Basic Usage
```python
from aaip import create_signed_delegation, verify_delegation, generate_keypair, StaticKeyResolver

# Generate keys
private_key, public_key, kid = generate_keypair()

# Create delegation
token = create_signed_delegation(
    issuer_identity="user@example.com",
    issuer_identity_system="oauth",
    private_key=private_key,
    kid=kid,
    subject_identity="my-agent",
    subject_identity_system="custom",
    scope=["api:read"],
    expires_at="2025-08-26T10:00:00Z",
    not_before="2025-07-26T10:00:00Z"
)

# Verify delegation
resolver = StaticKeyResolver({kid: public_key})
delegation = verify_delegation(token, resolver)
print(f"Delegation valid: {delegation.iss} -> {delegation.aud}")
```

### 3. Run Examples
```bash
# FastAPI example
cd examples/fastapi/basic
python main.py

# LangChain example  
cd examples/langchain/basic
python main.py
```

## Documentation

- [AAIP v2.0 Specification](spec/core/aaip-v2.0.md) - Complete protocol specification
- [Python API Reference](src/aaip/) - Implementation documentation
- [Examples](examples/) - Integration examples and tutorials

## Contributing

We welcome contributions to AAIP:

- **Bug Reports**: File issues for bugs or improvements
- **Feature Requests**: Suggest enhancements to the protocol
- **Implementation**: Contribute SDKs in other languages
- **Examples**: Add integration examples for new frameworks
- **Testing**: Help improve test coverage and edge cases

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

The AAIP specification is released under CC0 (public domain) to ensure maximum adoptability.

## Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/krisdiallo/aaip-spec/issues)
- **Documentation**: Complete guides in the [spec/](spec/) directory
- **Examples**: Working code samples in the [examples/](examples/) directory

---

**AAIP v2.0**: JWT-based delegation chains with JWKS key resolution for AI agent authorization