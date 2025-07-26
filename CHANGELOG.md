# Changelog

All notable changes to the AI Agent Identity Protocol (AAIP) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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