# AAIP LangChain Integration

This directory demonstrates how to integrate AAIP (AI Agent Identity Protocol) with LangChain agents to provide delegation-based authorization.

## Features

- **Agent Identity Management**: String-based agent identities
- **User Delegations**: Cryptographically signed permission grants using Ed25519  
- **Tool Authorization**: Control agent access to tools and APIs
- **Standard Constraints**: Apply spending limits, time windows, domain restrictions
- **LangChain Integration**: Work with existing LangChain workflows

## Quick Start

### 1. Install Dependencies

```bash
# Install AAIP library
pip install aaip

# Install LangChain dependencies
pip install -r basic/requirements.txt
```

### 2. Run the Basic Example

```bash
cd basic/
python main.py
```

### 3. Optional - Set OpenAI API Key

```bash
# For real LLM usage (otherwise demo uses mock LLM)
export OPENAI_API_KEY="your-key-here"
```

## What's Included

### 📁 `basic/` - Complete Working Example

**Files:**
- `main.py` - Full implementation with 3 demonstration scenarios
- `requirements.txt` - All dependencies needed to run

**Features demonstrated:**
- **Authorization Layer**: Delegation-based permissions with Ed25519 signature verification
- **Standard Constraints**: Spending limits, domain restrictions, keyword filtering  
- **Error Handling**: Basic error handling for authorization failures
- **Multiple Scenarios**: Travel booking, email communication, payment processing

**Code Structure:**
```python
# Create AAIP-enabled agent
agent = AAIPLangChainAgent(
    agent_identity="travel-assistant-v1",
    agent_identity_system="custom"
)

# Set user delegation with constraints
delegation = create_demo_delegation(
    user_identity="alice@example.com",
    scope=["travel:book_flight", "payments:charge"],
    constraints={"max_amount": {"value": 2000.0, "currency": "USD"}},
    expires_at="2025-07-25T10:00:00Z",
    not_before="2025-07-24T10:00:00Z"
)
agent.set_delegation(delegation)

# Execute task with authorization
result = await agent.execute_task("Book a flight to Paris for $800")
```

## Example Scenarios

The basic example includes three scenarios showcasing different AAIP capabilities:

### Scenario 1: Travel Booking with Spending Limits
```python
{
    "scope": ["travel:book_flight", "payments:charge"],
    "constraints": {
        "max_amount": {"value": 2000.0, "currency": "USD"},
        "allowed_domains": ["airline.com", "travel.com"]
    },
    "task": "Book a flight to Paris for next week, budget is $800"
}
```

**What happens:**
- ✅ Agent can book flights up to $2,000 total  
- ✅ Only from allowed domains
- ✅ Flight booking succeeds within limits
- ❌ Would fail if flight costs more than $2,000

### Scenario 2: Email Communication with Domain Restrictions
```python
{
    "scope": ["communication:send_email"], 
    "constraints": {
        "allowed_domains": ["example.com", "company.com"],
        "blocked_keywords": ["spam", "urgent"]
    },
    "task": "Send an email to john@example.com about the meeting tomorrow"
}
```

**What happens:**
- ✅ Can email allowed domains (@example.com, @company.com)
- ✅ Content checked against blocked keywords
- ❌ Cannot email domains not in allowed list
- ❌ Cannot use blocked keywords in content

### Scenario 3: Payment Processing with Amount Limits
```python
{
    "scope": ["payments:charge"],
    "constraints": {
        "max_amount": {"value": 1000.0, "currency": "USD"}
    },
    "task": "Process a payment of $300 to supplier-xyz"
}
```

**What happens:**
- ✅ Payments allowed up to $1,000  
- ❌ Would fail for amounts over $1,000

## Tool Authorization Wrapper

The example shows how tools are wrapped with authorization checks:

```python
def book_flight_wrapper(input_str: str) -> str:
    try:
        params = self._parse_tool_input(input_str)
        # Check delegation authorization
        self._check_tool_authorization("travel:book_flight", params)
        # Execute if authorized
        return self._book_flight_impl(params)
    except AuthorizationError as e:
        return f"Authorization denied: {str(e)}"
```

## Standard Constraints

AAIP v1.0 supports these standard constraint types:

### Financial Constraints
```python
constraints = {
    "max_amount": {
        "value": 1000.0,
        "currency": "USD"
    }
}
```

### Time Window Constraints  
```python
constraints = {
    "time_window": {
        "start": "2025-07-24T09:00:00Z",
        "end": "2025-07-24T17:00:00Z"
    }
}
```

### Domain Constraints
```python
constraints = {
    "allowed_domains": ["company.com", "*.partner.com"],
    "blocked_domains": ["competitor.com", "*.malicious.com"]
}
```

### Content Constraints
```python
constraints = {
    "blocked_keywords": ["urgent", "limited time", "act now"]
}
```

## Security Features

### Cryptographic Security
- **Ed25519 signatures**: Industry-standard elliptic curve cryptography
- **Canonical serialization**: Prevents signature malleability attacks
- **Time-bounded tokens**: Automatic expiration prevents replay attacks
- **Secure key generation**: Cryptographically secure random number generation

### Authorization Security
- **Principle of least privilege**: Agents only get minimal required permissions
- **Explicit delegation**: No implicit permissions, everything must be granted
- **Scope validation**: Hierarchical scope matching with wildcard support
- **Standard constraint enforcement**: Core business rules enforced with delegation signature

## Error Handling

The example demonstrates error handling:

### Authorization Errors
```python
try:
    result = await agent.execute_task("Book expensive flight")
except AuthorizationError as e:
    print(f"Permission denied: {e}")
```

### Constraint Violations
```python
try:
    validate_constraints(delegation["delegation"]["constraints"], request_params)
except ValidationError as e:
    print(f"Constraint violated: {e}")
```

### Delegation Expiration
```python
if not verify_delegation(delegation):
    print("Delegation expired or invalid")
```

## Troubleshooting

### Common Issues

#### "No delegation available" Error
```
❌ No delegation available - agent not authorized
```
**Solution**: Ensure a valid delegation is set before executing tasks:
```python
delegation = create_demo_delegation(...)
agent.set_delegation(delegation)
```

#### "Permission not granted" Error
```
❌ Permission 'travel:book_flight' not granted in delegation
```
**Solution**: Include the required scope in the delegation:
```python
delegation = create_demo_delegation(
    scope=["travel:book_flight"],  # Add missing permission
    ...
)
```

#### Constraint Violation Errors
```
❌ Amount 5000 exceeds maximum 2000
```
**Solution**: Adjust constraints or request parameters:
```python
# Option 1: Increase constraint limit
constraints = {"max_amount": {"value": 6000.0, "currency": "USD"}}

# Option 2: Reduce request amount
"Book a flight to Paris for $1800"  # Instead of $5000
```

#### Mock LLM Warning
```
⚠️  Warning: OPENAI_API_KEY not set. Using mock LLM for demo.
```
**Solution**: Set OpenAI API key for full functionality:
```bash
export OPENAI_API_KEY="your-key-here"
```

## Identity System Support

AAIP v1.0 supports simple string-based identities:

```python
# OAuth-style identities
agent = AAIPLangChainAgent(
    agent_identity="user@example.com",
    agent_identity_system="oauth"
)

# DID-style identities
agent = AAIPLangChainAgent(
    agent_identity="did:example:agent123",
    agent_identity_system="did"
)

# Custom identities
agent = AAIPLangChainAgent(
    agent_identity="agent-uuid-123",
    agent_identity_system="custom"
)
```

Identity verification is handled through self-contained delegations with embedded public keys.

## Testing

Run the example:

```bash
python basic/main.py
```

Example test structure:
```python
import pytest
from basic.main import AAIPLangChainAgent, create_demo_delegation

@pytest.mark.asyncio
async def test_agent_with_delegation():
    # Create agent
    agent = AAIPLangChainAgent("test-agent-v1")
    
    # Create delegation
    delegation = create_demo_delegation(
        user_identity="test@example.com",
        scope=["payments:charge"],
        constraints={"max_amount": {"value": 100.0, "currency": "USD"}}
    )
    
    # Set delegation and test
    assert agent.set_delegation(delegation)
    result = await agent.execute_task("Process a $50 payment")
    assert "Payment" in result
```

## Resources

- 📖 [AAIP Specification](../../spec/core/aaip-v1.0.md)
- 🔧 [AAIP Python API](../../src/aaip/)
- 🧪 [More Examples](../)

This integration provides a foundation for building authorized LangChain agents with AAIP! 🚀