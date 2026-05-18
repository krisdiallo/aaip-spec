# Changelog

All notable changes to the AI Agent Identity Protocol (AAIP) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-04-22

### Breaking Changes

- **JWT format (EdDSA) replaces custom JSON envelope with hex Ed25519 signatures**
  Delegations are now standard JWT tokens signed with EdDSA (Ed25519) instead of custom JSON objects with hex-encoded signatures.

- **UCAN-style delegation chains via `prf` claim for sub-delegation and attenuation**
  Agents can now sub-delegate authority using proof chains. The `prf` claim references parent delegation tokens, enabling verifiable attenuation of permissions across a chain.

- **JWKS-based key resolution (`kid` + JWKS endpoint) replaces embedded public keys**
  Public keys are no longer embedded in delegations. Verifiers resolve keys by `kid` from a JWKS endpoint or static resolver.

- **OAuth2-style space-separated `scope` claim replaces JSON array**
  Scopes are now encoded as a single space-separated string in the JWT `scope` claim, following OAuth2 conventions.

- **`Authorization: Bearer <jwt>` header replaces `X-AAIP-Delegation`**
  HTTP integrations now use the standard `Authorization: Bearer` header instead of the custom `X-AAIP-Delegation` header.

- **AAIP-specific metadata in nested `aaip` custom claim (constraints, identity types)**
  Constraint definitions, identity system types, and other AAIP-specific metadata are grouped under a single `aaip` claim in the JWT payload.

- **`generate_keypair()` now returns `(Ed25519PrivateKey, Ed25519PublicKey, kid)` instead of hex strings**
  Keys are returned as native cryptographic objects with an associated key ID, rather than hex-encoded strings.

- **`verify_delegation()` returns `Delegation` object instead of `bool`**
  Verification now returns a rich `Delegation` object containing parsed claims, instead of a simple boolean.

- **`create_signed_delegation()` returns JWT string instead of dict; takes `private_key` (native key object) and `kid` instead of `issuer_private_key` (hex string)**
  The signing function now produces a compact JWT string and accepts native key objects with key IDs.

- **Identity `public_key` field removed (keys now in JWKS)**
  The `public_key` field has been removed from identity objects. Key material is resolved via JWKS.

### Added

- **New `StaticKeyResolver`, `JWKSClient` for key resolution**
  `StaticKeyResolver` maps `kid` values to local keys for testing and offline use. `JWKSClient` fetches keys from remote JWKS endpoints.

- **New `ChainError`, `KeyResolutionError` exception types**
  Dedicated exception types for delegation chain validation failures and key resolution failures.

- **New `is_scope_subset()`, `are_constraints_attenuated()` utilities**
  Helper functions for verifying that sub-delegated scopes and constraints are properly attenuated relative to their parent.

- **PyJWT added as dependency**
  JWT encoding and decoding is handled by the PyJWT library.

## [1.0.0] - 2025-07-26

### Added
- **AAIP v1.0 Core Protocol Specification**
  - Standard delegation format with Ed25519 cryptographic signatures
  - Self-contained verification with embedded public keys
  - Hierarchical scope system with wildcard support
  - Standard constraints: financial limits, time windows, domain controls, content filtering
  - Stateless design requiring no central authority

- **Python Reference Implementation**
  - Core delegation creation and verification functions
  - Cryptographic operations using Ed25519
  - Standard constraint validation
  - Identity management with multiple identity system support
  - Comprehensive error handling with standard error codes

- **Integration Examples**
  - FastAPI REST API integration with AAIP authorization
  - LangChain agent integration with delegation-based tool access
  - Complete working examples with constraint enforcement

- **Documentation**
  - Complete AAIP v1.0 specification document
  - Getting started guide with working examples
  - Comprehensive API reference

- **Development Infrastructure**
  - Full test suite for core functionality
  - Development dependencies and tooling configuration
  - CI/CD ready project structure

### Technical Details
- **Cryptography**: Ed25519 signatures per RFC 8037
- **Identity Systems**: Support for OAuth, DID, and custom identity types
- **Constraints**: Max amount, time windows, domain allowlists/blocklists, keyword filtering
- **Error Handling**: Standard error codes aligned with RFC 7807 problem details
- **Python Support**: Python 3.9+ compatibility

### Architecture
- **Protocol-First Design**: Minimal core implementation
- **Stateless Operation**: No external dependencies for basic verification
- **Extensible**: Clean interfaces for adding custom constraints and identity adapters
- **Standards Compliant**: Follows established cryptographic and web standards

---

**Note**: This project follows the protocol-first approach similar to foundational internet protocols (SMTP, HTTP). The core specification remains stable while implementations and extensions can evolve independently.