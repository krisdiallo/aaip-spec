# AI Agent Identity Protocol (AAIP) v1.0

> Standard delegation format for AI agent authorization

[![GitHub Stars](https://img.shields.io/github/stars/krisdiallo/aaip-spec)](https://github.com/krisdiallo/aaip-spec/stargazers)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version](https://img.shields.io/badge/AAIP-v1.0-blue)](#specification)

## What is AAIP?

AAIP is a standard format for users to grant specific, time-bounded, and constrained permissions to AI agents. It provides cryptographically signed delegations that enable secure agent authorization without requiring central infrastructure.

## Key Features

- **Standard Delegation Format**: JSON-based signed delegations with Ed25519 cryptography
- **Self-Contained Verification**: Delegations include all data needed for verification
- **Hierarchical Scopes**: Fine-grained permissions with wildcard support  
- **Standard Constraints**: Built-in spending limits, time windows, and content filtering
- **Stateless Design**: No central authority or registry required
- **Protocol-First**: Simple foundation for building agent authorization systems

## Quick Example

```python
from aaip import create_signed_delegation, verify_delegation, generate_keypair

# Generate keypair for signing
private_key, public_key = generate_keypair()

# Create a signed delegation
delegation = create_signed_delegation(
    issuer_identity="user@example.com",
    issuer_identity_system="oauth",
    issuer_private_key=private_key,
    subject_identity="agent_001", 
    subject_identity_system="custom",
    scope=["payments:authorize"],
    expires_at="2025-08-26T10:00:00Z",
    not_before="2025-07-26T10:00:00Z",
    constraints={
        "max_amount": {"value": 500, "currency": "USD"},
        "allowed_domains": ["amazon.com", "stripe.com"]
    }
)

# Verify the delegation
is_valid = verify_delegation(delegation)
print(f"Delegation valid: {is_valid}")
```

## Delegation Format

AAIP delegations are JSON objects with cryptographic signatures:

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
    "scope": ["payments:send", "data:read:*"],
    "constraints": {
      "max_amount": {"value": 500, "currency": "USD"},
      "time_window": {
        "start": "2025-07-23T10:00:00Z",
        "end": "2025-07-24T10:00:00Z"
      }
    },
    "issued_at": "2025-07-23T10:00:00Z",
    "expires_at": "2025-07-24T10:00:00Z",
    "not_before": "2025-07-23T10:00:00Z"
  },
  "signature": "ed25519-signature-hex"
}
```

## Standard Constraints

AAIP v1.0 defines standard constraint types that all implementations must support:

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

- **Ed25519 Signatures**: Industry-standard cryptographic security
- **Self-Contained**: No external key lookups required
- **Time-Bounded**: Automatic expiration prevents replay attacks
- **Minimal Privilege**: Scoped permissions with explicit constraints
- **Canonical Serialization**: Prevents signature malleability

## Installation

```bash
pip install aaip
```

## Examples

### FastAPI Integration
Create REST APIs with AAIP authorization:

```python
from fastapi import FastAPI, Depends
from aaip import verify_delegation, check_delegation_authorization

app = FastAPI()

def require_scope(required_scope: str):
    def dependency(delegation = Depends(get_delegation_from_header)):
        if not check_delegation_authorization(delegation, *required_scope.split(":")):
            raise HTTPException(403, f"Insufficient scope: requires {required_scope}")
        return delegation
    return dependency

@app.post("/payment")
async def process_payment(
    payment_data: PaymentRequest,
    delegation = Depends(require_scope("payments:authorize"))
):
    # Payment processing with delegation authorization
    return {"status": "success"}
```

### LangChain Integration
Add AAIP authorization to LangChain agents:

```python
from langchain.agents import create_openai_functions_agent
from aaip import verify_delegation, check_delegation_authorization

class AAIPLangChainAgent:
    def __init__(self, agent_identity):
        self.agent_identity = agent_identity
        self.current_delegation = None
        # ... setup LangChain agent
    
    def set_delegation(self, delegation):
        if verify_delegation(delegation):
            self.current_delegation = delegation
            return True
        return False
    
    def execute_task(self, task):
        if not self.current_delegation:
            raise AuthorizationError("No delegation available")
        # ... execute with authorization checks
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

1. **Format Validation**: Check all required fields exist
2. **Version Check**: Ensure `aaip_version` is supported  
3. **Time Validation**: Check expiration and validity times
4. **Signature Verification**: Verify Ed25519 signature using embedded public key
5. **Scope Check**: Validate requested action against delegation scope
6. **Constraint Enforcement**: Apply all standard constraints

## Error Handling

AAIP defines standard error codes:

- `INVALID_DELEGATION`: Malformed delegation format
- `SIGNATURE_INVALID`: Cryptographic signature verification failed
- `DELEGATION_EXPIRED`: Delegation past expiration time
- `SCOPE_INSUFFICIENT`: Required permission not granted
- `CONSTRAINT_VIOLATED`: Request violates delegation constraints

## Implementation Status

### Core Protocol
- [x] AAIP v1.0 specification complete
- [x] Python reference implementation
- [x] Ed25519 cryptographic security
- [x] Standard constraint validation
- [x] Comprehensive test suite

### Examples
- [x] FastAPI integration example
- [x] LangChain integration example
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
from aaip import create_signed_delegation, verify_delegation, generate_keypair

# Generate keys
private_key, public_key = generate_keypair()

# Create delegation
delegation = create_signed_delegation(
    issuer_identity="user@example.com",
    issuer_identity_system="oauth",
    issuer_private_key=private_key,
    subject_identity="my-agent",
    subject_identity_system="custom", 
    scope=["api:read"],
    expires_at="2025-08-26T10:00:00Z",
    not_before="2025-07-26T10:00:00Z"
)

# Verify delegation
if verify_delegation(delegation):
    print("Delegation is valid!")
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

- [AAIP v1.0 Specification](spec/core/aaip-v1.0.md) - Complete protocol specification
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

**AAIP v1.0**: Standard delegation format for AI agent authorization