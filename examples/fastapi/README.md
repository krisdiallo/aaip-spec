# AAIP FastAPI Integration Example

This example demonstrates how to integrate AAIP (AI Agent Identity Protocol) with FastAPI to create a secure REST API for AI agent authorization.

## Features

- **Delegation validation** via HTTP headers
- **Scope-based authorization** with decorators
- **Standard constraint enforcement** 
- **RESTful API design**
- **Structured error handling**

## Quick Start

### 1. Install Dependencies

```bash
pip install -r basic/requirements.txt
```

### 2. Run the Server

```bash
cd basic/
python main.py
```

The server will start at `http://localhost:8000`

### 3. View API Documentation

Open your browser to:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## API Endpoints

### `POST /delegations` - Create Delegation

Create a new AAIP delegation for an AI agent:

```bash
curl -X POST "http://localhost:8000/delegations" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_identity": "shopping_assistant_v1",
    "scope": ["payments:authorize"],
    "constraints": {
      "max_amount": {"value": 500.0, "currency": "USD"},
      "allowed_domains": ["amazon.com", "bestbuy.com"]
    },
    "expires_at": "2025-07-25T10:00:00Z",
    "not_before": "2025-07-24T10:00:00Z"
  }'
```

Response:
```json
{
  "delegation": {
    "aaip_version": "1.0",
    "delegation": {
      "id": "del_xyz123...",
      "issuer": {"id": "user@example.com", "type": "oauth", "public_key": "..."},
      "subject": {"id": "shopping_assistant_v1", "type": "custom"},
      "scope": ["payments:authorize"],
      "constraints": {...},
      "expires_at": "2025-07-25T10:00:00Z",
      "not_before": "2025-07-24T10:00:00Z",
      "issued_at": "2025-07-24T10:00:00Z"
    },
    "signature": "ed25519_signature..."
  },
  "usage_instructions": {
    "header": "X-AAIP-Delegation",
    "value": "Base64 encode this delegation JSON"
  }
}
```

### `POST /payment` - Process Payment

Authorize a payment with AAIP delegation:

```bash
# First, base64 encode your delegation JSON
DELEGATION=$(echo '{"aaip_version":"1.0",...}' | base64)

curl -X POST "http://localhost:8000/payment" \
  -H "Content-Type: application/json" \
  -H "X-AAIP-Delegation: $DELEGATION" \
  -d '{
    "amount": 299.99,
    "currency": "USD",
    "merchant": "amazon.com"
  }'
```

Success Response:
```json
{
  "status": "success",
  "transaction_id": "txn_299.99_amazon.com_del_xyz1",
  "amount": 299.99,
  "currency": "USD",
  "merchant": "amazon.com",
  "message": "Payment processed successfully"
}
```

Constraint Violation Response:
```json
{
  "error": "Constraint violation",
  "details": {
    "error": "Amount 750.0 exceeds maximum 500.0 USD"
  }
}
```

### `POST /calendar` - Create Calendar Event

Create a calendar event with delegation authorization:

```bash
curl -X POST "http://localhost:8000/calendar" \
  -H "Content-Type: application/json" \
  -H "X-AAIP-Delegation: $DELEGATION" \
  -d '{
    "title": "Team Meeting",
    "start_time": "2025-07-24T14:00:00Z",
    "duration_hours": 1,
    "attendees": ["alice@company.com", "bob@company.com"]
  }'
```

### `GET /health` - Health Check

Get service health and supported capabilities:

```bash
curl http://localhost:8000/health
```

Response:
```json
{
  "status": "healthy",
  "aaip_version": "1.0",
  "supported_scopes": ["payments:authorize", "calendar:write"],
  "public_key": "ed25519_public_key..."
}
```

## Integration Patterns

### 1. Dependency Injection

The example uses FastAPI's dependency injection for clean authorization:

```python
from fastapi import Depends

def get_delegation_from_header(x_aaip_delegation: Optional[str] = Header(None)):
    """Extract and verify delegation from header."""
    if not x_aaip_delegation:
        raise HTTPException(401, "Missing X-AAIP-Delegation header")
    
    try:
        delegation_json = base64.b64decode(x_aaip_delegation).decode('utf-8')
        delegation = json.loads(delegation_json)
    except Exception:
        raise HTTPException(400, "Invalid delegation format")
    
    if not verify_delegation(delegation):
        raise HTTPException(401, "Invalid delegation")
    
    return delegation

def require_scope(required_scope: str):
    """Decorator factory for requiring specific scopes."""
    def dependency(delegation = Depends(get_delegation_from_header)):
        if not check_delegation_authorization(delegation, *required_scope.split(":")):
            raise HTTPException(403, f"Insufficient scope: requires {required_scope}")
        return delegation
    return dependency

@app.post("/protected-endpoint")
async def protected_route(
    delegation = Depends(require_scope("payments:authorize"))
):
    # Your protected logic here
    pass
```

### 2. Constraint Enforcement

Real-time constraint validation:

```python
from aaip import validate_constraints

try:
    validate_constraints(delegation["delegation"]["constraints"], request_data)
except ValidationError as e:
    raise HTTPException(403, detail={
        "error": "Constraint violation",
        "details": {"error": str(e)}
    })
```

## Standard Constraints

The API supports AAIP v1.0 standard constraints:

### Financial Constraints
```json
{
  "max_amount": {
    "value": 1000.0,
    "currency": "USD"  
  }
}
```

### Time Window Constraints  
```json
{
  "time_window": {
    "start": "2025-07-24T09:00:00Z",
    "end": "2025-07-24T17:00:00Z"
  }
}
```

### Domain Constraints
```json
{
  "allowed_domains": ["company.com", "*.partner.com"],
  "blocked_domains": ["competitor.com", "*.malicious.com"]
}
```

### Content Constraints
```json
{
  "blocked_keywords": ["urgent", "limited time", "act now"]
}
```

## Testing

Run the example:

```bash
python basic/main.py
```

Example test:

```python
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_payment_with_valid_delegation():
    # Create delegation
    delegation_response = client.post("/delegations", json={
        "agent_identity": "test_agent",
        "scope": ["payments:authorize"],
        "constraints": {"max_amount": {"value": 100.0, "currency": "USD"}},
        "expires_at": "2025-07-25T10:00:00Z",
        "not_before": "2025-07-24T10:00:00Z"
    })
    
    delegation = delegation_response.json()["delegation"]
    
    # Test payment
    response = client.post("/payment", 
        json={
            "amount": 50.0,
            "currency": "USD", 
            "merchant": "test.com"
        },
        headers={
            "X-AAIP-Delegation": base64.b64encode(
                json.dumps(delegation).encode()
            ).decode()
        }
    )
    
    assert response.status_code == 200
    assert response.json()["status"] == "success"
```

## Security Features

### Cryptographic Security
- **Ed25519 signatures**: Industry-standard elliptic curve cryptography
- **Canonical serialization**: Prevents signature malleability attacks
- **Time-bounded tokens**: Automatic expiration prevents replay attacks
- **Self-contained verification**: No external key lookup required

### API Security  
- **Header-based delegation**: Secure delegation transmission
- **Signature verification**: Cryptographic validation of all delegations
- **Scope enforcement**: Exact permission matching with wildcard support
- **Constraint validation**: Standard constraints enforced before action execution

## Production Considerations

### Security

1. **HTTPS Only**: Always use HTTPS in production
2. **Rate Limiting**: Implement API rate limiting
3. **Input Validation**: Validate all request data
4. **Key Management**: Use secure key storage for signing keys

### Performance

1. **Delegation Caching**: Cache verification results to avoid repeated crypto operations
2. **Connection Pooling**: Use database connection pooling if storing audit logs
3. **Async Operations**: Leverage FastAPI's async capabilities
4. **Health Monitoring**: Add metrics and health checks

### Deployment

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

## Error Handling

The API returns structured errors following standard HTTP conventions:

### 400 Bad Request - Invalid Input
```json
{
  "error": "Invalid delegation format"
}
```

### 401 Unauthorized - Missing/Invalid Delegation
```json
{
  "error": "Missing X-AAIP-Delegation header"
}
```

### 403 Forbidden - Insufficient Permissions  
```json
{
  "error": "Insufficient scope: requires payments:authorize"
}
```

### 403 Forbidden - Constraint Violation
```json
{
  "error": "Constraint violation",
  "details": {
    "error": "Amount 1500 exceeds maximum 1000 USD"
  }
}
```

## Resources

- 📖 [AAIP Specification](../../spec/core/aaip-v1.0.md)
- 🔧 [AAIP Python API](../../src/aaip/)
- 🧪 [More Examples](../)

This example provides a foundation for building production AAIP-enabled APIs with FastAPI! 🚀