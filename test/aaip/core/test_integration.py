"""
Integration tests for AAIP v2.0 core functionality.
"""


import pytest

from aaip.core import (
    ConstraintError,
    StaticKeyResolver,
    check_delegation_authorization,
    create_signed_delegation,
    generate_keypair,
    validate_constraints,
    verify_delegation,
)


class TestEndToEndScenarios:
    def test_simple_delegation_scenario(self):
        priv, pub, kid = generate_keypair()
        resolver = StaticKeyResolver({kid: pub})

        token = create_signed_delegation(
            issuer_identity="user@example.com",
            issuer_identity_system="oauth",
            private_key=priv,
            kid=kid,
            subject_identity="simple_agent",
            subject_identity_system="custom",
            scope=["email:send", "payments:authorize"],
            expires_at="2027-08-26T10:00:00Z",
            not_before="2025-07-26T10:00:00Z",
            constraints={"max_amount": {"value": 1000, "currency": "USD"}},
        )

        delegation = verify_delegation(token, resolver)

        assert delegation.iss == "user@example.com"
        assert delegation.aud == "simple_agent"
        assert "email:send" in delegation.scope
        assert "payments:authorize" in delegation.scope
        assert delegation.constraints["max_amount"]["value"] == 1000

        assert check_delegation_authorization(delegation, "email", "send") is True
        assert check_delegation_authorization(delegation, "payments", "authorize") is True

        valid_request = {"amount": 500, "currency": "USD"}
        assert validate_constraints(delegation.constraints, valid_request) is True

        invalid_request = {"amount": 1500, "currency": "USD"}
        with pytest.raises(ConstraintError):
            validate_constraints(delegation.constraints, invalid_request)

    def test_constraint_creation_integration(self):
        constraints = {
            "max_amount": {"value": 500.0, "currency": "USD"},
            "allowed_domains": ["amazon.com", "stripe.com"],
        }

        valid_request = {"amount": 100.0, "currency": "USD", "domain": "amazon.com"}
        assert validate_constraints(constraints, valid_request) is True

        invalid_request = {"amount": 600.0, "currency": "USD", "domain": "amazon.com"}
        with pytest.raises(ConstraintError):
            validate_constraints(constraints, invalid_request)

    def test_delegation_with_constraints(self):
        priv, pub, kid = generate_keypair()
        resolver = StaticKeyResolver({kid: pub})

        token = create_signed_delegation(
            issuer_identity="user@example.com",
            issuer_identity_system="oauth",
            private_key=priv,
            kid=kid,
            subject_identity="complex_agent",
            subject_identity_system="custom",
            scope=["email:send", "payments:authorize"],
            expires_at="2027-08-26T10:00:00Z",
            not_before="2025-07-26T10:00:00Z",
            constraints={
                "max_amount": {"value": 2000, "currency": "USD"},
                "blocked_domains": ["competitor.com", "spam.com"],
            },
        )

        delegation = verify_delegation(token, resolver)
        constraints = delegation.constraints

        assert constraints["max_amount"]["value"] == 2000
        assert "competitor.com" in constraints["blocked_domains"]

        valid_request = {"amount": 500, "currency": "USD", "email": "prospect@goodcompany.com"}
        assert validate_constraints(constraints, valid_request) is True

        invalid_request = {"amount": 500, "currency": "USD", "domain": "competitor.com"}
        with pytest.raises(ConstraintError):
            validate_constraints(constraints, invalid_request)

    def test_direct_public_key_verification(self):
        """Verify delegation using a direct public key instead of a resolver."""
        priv, pub, kid = generate_keypair()

        token = create_signed_delegation(
            issuer_identity="user@example.com",
            issuer_identity_system="oauth",
            private_key=priv,
            kid=kid,
            subject_identity="agent",
            subject_identity_system="custom",
            scope=["test:action"],
            expires_at="2027-01-01T00:00:00Z",
            not_before="2025-01-01T00:00:00Z",
        )

        delegation = verify_delegation(token, pub)
        assert delegation.iss == "user@example.com"

    def test_allowed_issuers_filter(self):
        priv, pub, kid = generate_keypair()
        resolver = StaticKeyResolver({kid: pub})

        token = create_signed_delegation(
            issuer_identity="user@example.com",
            issuer_identity_system="oauth",
            private_key=priv,
            kid=kid,
            subject_identity="agent",
            subject_identity_system="custom",
            scope=["test:action"],
            expires_at="2027-01-01T00:00:00Z",
            not_before="2025-01-01T00:00:00Z",
        )

        delegation = verify_delegation(token, resolver, allowed_issuers=["user@example.com"])
        assert delegation.iss == "user@example.com"

        from aaip.core import DelegationError
        with pytest.raises(DelegationError):
            verify_delegation(token, resolver, allowed_issuers=["other@example.com"])
