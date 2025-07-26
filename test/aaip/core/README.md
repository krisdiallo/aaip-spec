# AAIP Core Tests

This directory contains comprehensive tests for the AAIP v1.0 core functionality, organized into focused test files covering the essential protocol components.

## Test Structure

The tests are split into separate files based on functionality:

### `test_delegation.py`
Tests for core delegation functionality:
- Delegation object creation and verification
- Authorization checking with scope validation
- Wildcard scope matching
- Time-based validation (expires_at, not_before)
- Delegation object serialization/deserialization

### `test_crypto.py`
Tests for cryptographic functionality:
- Ed25519 keypair generation
- Delegation signing and signature verification
- Canonical JSON serialization
- Public key extraction from private keys
- Cryptographic error handling

### `test_constraints.py`
Tests for standard constraint validation:
- Financial constraints (max_amount with currency)
- Time window constraints (start/end times)
- Domain constraints (allowed_domains, blocked_domains with wildcards)
- Content constraints (blocked_keywords)
- Combined constraint validation scenarios

### `test_integration.py`
Tests for end-to-end scenarios:
- Complete delegation lifecycle (create → verify → authorize)
- Real-world usage scenarios with multiple constraints
- Cross-module integration testing
- JSON serialization roundtrip testing

### `test_errors.py`
Tests for error handling:
- AAIP error codes and exception types
- Error creation convenience functions
- Proper error propagation through the system
- Validation error scenarios

## Running Tests

```bash
# Install dev dependencies first
pip install -e ".[dev]"

# Run all AAIP tests
pytest test/

# Run specific test file
pytest test/aaip/core/test_delegation.py

# Run specific test class
pytest test/aaip/core/test_delegation.py::TestDelegationCreation

# Run with verbose output and coverage
pytest test/ -v --cov=aaip --cov-report=term-missing
```

## Test Coverage

The test suite covers:

### Core Protocol Features ✅
- Ed25519 cryptographic operations
- Delegation creation and verification
- Standard constraint validation
- Scope-based authorization checking
- Time-based validity checking

### Error Handling ✅
- Invalid delegation formats
- Expired delegations
- Insufficient scopes
- Constraint violations
- Cryptographic failures

### Real-World Scenarios ✅
- Payment authorization with spending limits
- Multi-scope delegations
- Domain-restricted operations
- Time-bounded delegations

## Test Organization

### Unit Tests
- `test_crypto.py` - Cryptographic primitives
- `test_delegation.py` - Core delegation logic
- `test_constraints.py` - Constraint validation
- `test_errors.py` - Error handling

### Integration Tests
- `test_integration.py` - End-to-end scenarios

## Adding New Tests

When adding new functionality:

1. **Identify the appropriate test file** based on functionality:
   - Crypto operations → `test_crypto.py`
   - Delegation logic → `test_delegation.py`
   - Constraint validation → `test_constraints.py`
   - Error handling → `test_errors.py`
   - End-to-end scenarios → `test_integration.py`

2. **Add tests to the existing file** if it's related functionality
3. **Create a new test file** only for major new modules
4. **Update this README** to document new test files

## Quick Validation

To quickly verify everything works:

```bash
# Run a basic smoke test
python -c "
from aaip import generate_keypair, create_signed_delegation, verify_delegation
pk, pubk = generate_keypair()
d = create_signed_delegation('u@ex.com', 'oauth', pk, 'agent', 'custom', ['test:action'], '2025-12-31T23:59:59Z', '2025-01-01T00:00:00Z')
print('✅ AAIP working!' if verify_delegation(d) else '❌ Failed')
"
```

## Best Practices

- Each test file focuses on one core module
- Tests include both positive and negative cases
- Error conditions are properly tested
- Tests use descriptive names
- Integration tests cover realistic scenarios
- Tests are independent and can run in any order

## Debugging Failed Tests

1. **Run the specific test file** to isolate the issue:
   ```bash
   pytest test/aaip/core/test_delegation.py -v
   ```

2. **Run individual test methods** for detailed debugging:
   ```bash
   pytest test/aaip/core/test_delegation.py::TestDelegationCreation::test_delegation_authorization_check -v -s
   ```

3. **Check import issues** by running Python directly:
   ```bash
   python test/aaip/core/test_delegation.py
   ```

This test organization ensures the AAIP v1.0 core protocol is thoroughly validated and ready for production use.