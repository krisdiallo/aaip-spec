"""
Tests for AAIP v2.0 delegation chain (UCAN-style) functionality.
"""


import pytest

from aaip.core import (
    ChainError,
    StaticKeyResolver,
    are_constraints_attenuated,
    create_signed_delegation,
    generate_keypair,
    is_scope_subset,
    verify_delegation,
)


class TestScopeSubset:
    def test_exact_match(self):
        assert is_scope_subset(["payments:authorize"], ["payments:authorize"]) is True

    def test_subset(self):
        assert is_scope_subset(
            ["payments:authorize"],
            ["payments:authorize", "email:send"],
        ) is True

    def test_not_subset(self):
        assert is_scope_subset(
            ["payments:authorize", "email:send"],
            ["payments:authorize"],
        ) is False

    def test_wildcard_parent(self):
        assert is_scope_subset(["payments:authorize"], ["payments:*"]) is True
        assert is_scope_subset(["data:read:profile"], ["data:*"]) is True

    def test_full_wildcard(self):
        assert is_scope_subset(["anything:here"], ["*"]) is True

    def test_empty_child(self):
        assert is_scope_subset([], ["payments:authorize"]) is True

    def test_wildcard_not_covered(self):
        assert is_scope_subset(["email:send"], ["payments:*"]) is False


class TestConstraintAttenuation:
    def test_stricter_max_amount(self):
        parent = {"max_amount": {"value": 500, "currency": "USD"}}
        child = {"max_amount": {"value": 200, "currency": "USD"}}
        assert are_constraints_attenuated(child, parent) is True

    def test_wider_max_amount_rejected(self):
        parent = {"max_amount": {"value": 200, "currency": "USD"}}
        child = {"max_amount": {"value": 500, "currency": "USD"}}
        assert are_constraints_attenuated(child, parent) is False

    def test_currency_mismatch_rejected(self):
        parent = {"max_amount": {"value": 500, "currency": "USD"}}
        child = {"max_amount": {"value": 200, "currency": "EUR"}}
        assert are_constraints_attenuated(child, parent) is False

    def test_missing_parent_constraint_in_child(self):
        parent = {"max_amount": {"value": 500, "currency": "USD"}}
        child = {}
        assert are_constraints_attenuated(child, parent) is False

    def test_allowed_domains_subset(self):
        parent = {"allowed_domains": ["a.com", "b.com", "c.com"]}
        child = {"allowed_domains": ["a.com", "b.com"]}
        assert are_constraints_attenuated(child, parent) is True

    def test_allowed_domains_superset_rejected(self):
        parent = {"allowed_domains": ["a.com"]}
        child = {"allowed_domains": ["a.com", "b.com"]}
        assert are_constraints_attenuated(child, parent) is False

    def test_blocked_domains_superset(self):
        parent = {"blocked_domains": ["bad.com"]}
        child = {"blocked_domains": ["bad.com", "worse.com"]}
        assert are_constraints_attenuated(child, parent) is True

    def test_blocked_domains_subset_rejected(self):
        parent = {"blocked_domains": ["bad.com", "worse.com"]}
        child = {"blocked_domains": ["bad.com"]}
        assert are_constraints_attenuated(child, parent) is False

    def test_blocked_keywords_superset(self):
        parent = {"blocked_keywords": ["urgent"]}
        child = {"blocked_keywords": ["urgent", "asap"]}
        assert are_constraints_attenuated(child, parent) is True

    def test_equal_constraints(self):
        constraints = {
            "max_amount": {"value": 500, "currency": "USD"},
            "blocked_keywords": ["spam"],
        }
        assert are_constraints_attenuated(constraints, constraints) is True

    def test_child_can_add_extra_constraints(self):
        parent = {"max_amount": {"value": 500, "currency": "USD"}}
        child = {
            "max_amount": {"value": 200, "currency": "USD"},
            "blocked_keywords": ["spam"],
        }
        assert are_constraints_attenuated(child, parent) is True


class TestDelegationChain:
    def test_root_delegation_no_proofs(self):
        priv, pub, kid = generate_keypair()
        resolver = StaticKeyResolver({kid: pub})

        token = create_signed_delegation(
            issuer_identity="user@example.com",
            issuer_identity_system="oauth",
            private_key=priv,
            kid=kid,
            subject_identity="agent_a",
            subject_identity_system="custom",
            scope=["payments:authorize"],
            expires_at="2027-01-01T00:00:00Z",
            not_before="2025-01-01T00:00:00Z",
        )

        delegation = verify_delegation(token, resolver)
        assert delegation.proofs == []
        assert delegation.iss == "user@example.com"

    def test_single_level_delegation(self):
        priv_user, pub_user, kid_user = generate_keypair()
        priv_agent, pub_agent, kid_agent = generate_keypair()

        root_token = create_signed_delegation(
            issuer_identity="user@example.com",
            issuer_identity_system="oauth",
            private_key=priv_user,
            kid=kid_user,
            subject_identity="agent_a",
            subject_identity_system="custom",
            scope=["payments:authorize", "email:send"],
            expires_at="2027-01-01T00:00:00Z",
            not_before="2025-01-01T00:00:00Z",
            constraints={"max_amount": {"value": 500, "currency": "USD"}},
        )

        child_token = create_signed_delegation(
            issuer_identity="agent_a",
            issuer_identity_system="custom",
            private_key=priv_agent,
            kid=kid_agent,
            subject_identity="sub_agent",
            subject_identity_system="custom",
            scope=["payments:authorize"],
            expires_at="2027-01-01T00:00:00Z",
            not_before="2025-01-01T00:00:00Z",
            constraints={"max_amount": {"value": 200, "currency": "USD"}},
            proofs=[root_token],
        )

        resolver = StaticKeyResolver({kid_user: pub_user, kid_agent: pub_agent})
        child = verify_delegation(child_token, resolver)

        assert child.iss == "agent_a"
        assert child.aud == "sub_agent"
        assert child.scope == ["payments:authorize"]
        assert child.constraints["max_amount"]["value"] == 200

    def test_multi_level_chain(self):
        priv1, pub1, kid1 = generate_keypair()
        priv2, pub2, kid2 = generate_keypair()
        priv3, pub3, kid3 = generate_keypair()

        token1 = create_signed_delegation(
            issuer_identity="user@example.com",
            issuer_identity_system="oauth",
            private_key=priv1, kid=kid1,
            subject_identity="agent_a",
            subject_identity_system="custom",
            scope=["payments:authorize", "email:send"],
            expires_at="2027-01-01T00:00:00Z",
            not_before="2025-01-01T00:00:00Z",
            constraints={"max_amount": {"value": 1000, "currency": "USD"}},
        )

        token2 = create_signed_delegation(
            issuer_identity="agent_a",
            issuer_identity_system="custom",
            private_key=priv2, kid=kid2,
            subject_identity="agent_b",
            subject_identity_system="custom",
            scope=["payments:authorize"],
            expires_at="2027-01-01T00:00:00Z",
            not_before="2025-01-01T00:00:00Z",
            constraints={"max_amount": {"value": 500, "currency": "USD"}},
            proofs=[token1],
        )

        token3 = create_signed_delegation(
            issuer_identity="agent_b",
            issuer_identity_system="custom",
            private_key=priv3, kid=kid3,
            subject_identity="agent_c",
            subject_identity_system="custom",
            scope=["payments:authorize"],
            expires_at="2027-01-01T00:00:00Z",
            not_before="2025-01-01T00:00:00Z",
            constraints={"max_amount": {"value": 100, "currency": "USD"}},
            proofs=[token2],
        )

        resolver = StaticKeyResolver({kid1: pub1, kid2: pub2, kid3: pub3})
        leaf = verify_delegation(token3, resolver)

        assert leaf.iss == "agent_b"
        assert leaf.aud == "agent_c"
        assert leaf.constraints["max_amount"]["value"] == 100

    def test_wider_scope_rejected(self):
        priv_user, pub_user, kid_user = generate_keypair()
        priv_agent, pub_agent, kid_agent = generate_keypair()

        root_token = create_signed_delegation(
            issuer_identity="user@example.com",
            issuer_identity_system="oauth",
            private_key=priv_user, kid=kid_user,
            subject_identity="agent_a",
            subject_identity_system="custom",
            scope=["payments:authorize"],
            expires_at="2027-01-01T00:00:00Z",
            not_before="2025-01-01T00:00:00Z",
        )

        child_token = create_signed_delegation(
            issuer_identity="agent_a",
            issuer_identity_system="custom",
            private_key=priv_agent, kid=kid_agent,
            subject_identity="sub_agent",
            subject_identity_system="custom",
            scope=["payments:authorize", "email:send"],
            expires_at="2027-01-01T00:00:00Z",
            not_before="2025-01-01T00:00:00Z",
            proofs=[root_token],
        )

        resolver = StaticKeyResolver({kid_user: pub_user, kid_agent: pub_agent})
        with pytest.raises(ChainError) as exc_info:
            verify_delegation(child_token, resolver)
        assert exc_info.value.code.value == "ATTENUATION_VIOLATED"

    def test_weaker_constraints_rejected(self):
        priv_user, pub_user, kid_user = generate_keypair()
        priv_agent, pub_agent, kid_agent = generate_keypair()

        root_token = create_signed_delegation(
            issuer_identity="user@example.com",
            issuer_identity_system="oauth",
            private_key=priv_user, kid=kid_user,
            subject_identity="agent_a",
            subject_identity_system="custom",
            scope=["payments:authorize"],
            expires_at="2027-01-01T00:00:00Z",
            not_before="2025-01-01T00:00:00Z",
            constraints={"max_amount": {"value": 100, "currency": "USD"}},
        )

        child_token = create_signed_delegation(
            issuer_identity="agent_a",
            issuer_identity_system="custom",
            private_key=priv_agent, kid=kid_agent,
            subject_identity="sub_agent",
            subject_identity_system="custom",
            scope=["payments:authorize"],
            expires_at="2027-01-01T00:00:00Z",
            not_before="2025-01-01T00:00:00Z",
            constraints={"max_amount": {"value": 500, "currency": "USD"}},
            proofs=[root_token],
        )

        resolver = StaticKeyResolver({kid_user: pub_user, kid_agent: pub_agent})
        with pytest.raises(ChainError) as exc_info:
            verify_delegation(child_token, resolver)
        assert exc_info.value.code.value == "ATTENUATION_VIOLATED"

    def test_child_expires_after_parent_rejected(self):
        priv_user, pub_user, kid_user = generate_keypair()
        priv_agent, pub_agent, kid_agent = generate_keypair()

        root_token = create_signed_delegation(
            issuer_identity="user@example.com",
            issuer_identity_system="oauth",
            private_key=priv_user, kid=kid_user,
            subject_identity="agent_a",
            subject_identity_system="custom",
            scope=["payments:authorize"],
            expires_at="2027-01-01T00:00:00Z",
            not_before="2025-01-01T00:00:00Z",
        )

        child_token = create_signed_delegation(
            issuer_identity="agent_a",
            issuer_identity_system="custom",
            private_key=priv_agent, kid=kid_agent,
            subject_identity="sub_agent",
            subject_identity_system="custom",
            scope=["payments:authorize"],
            expires_at="2028-01-01T00:00:00Z",
            not_before="2025-01-01T00:00:00Z",
            proofs=[root_token],
        )

        resolver = StaticKeyResolver({kid_user: pub_user, kid_agent: pub_agent})
        with pytest.raises(ChainError) as exc_info:
            verify_delegation(child_token, resolver)
        assert exc_info.value.code.value == "ATTENUATION_VIOLATED"

    def test_max_chain_depth(self):
        keys = []
        for _ in range(4):
            keys.append(generate_keypair())

        resolver_dict = {kid: pub for _, pub, kid in keys}
        resolver = StaticKeyResolver(resolver_dict)

        token = create_signed_delegation(
            issuer_identity="level_0",
            issuer_identity_system="custom",
            private_key=keys[0][0], kid=keys[0][2],
            subject_identity="level_1",
            subject_identity_system="custom",
            scope=["test:action"],
            expires_at="2027-01-01T00:00:00Z",
            not_before="2025-01-01T00:00:00Z",
        )

        for i in range(1, len(keys)):
            token = create_signed_delegation(
                issuer_identity=f"level_{i}",
                issuer_identity_system="custom",
                private_key=keys[i][0], kid=keys[i][2],
                subject_identity=f"level_{i + 1}",
                subject_identity_system="custom",
                scope=["test:action"],
                expires_at="2027-01-01T00:00:00Z",
                not_before="2025-01-01T00:00:00Z",
                proofs=[token],
            )

        # Should succeed with default depth 5
        verify_delegation(token, resolver)

        # Should fail with depth limit of 2
        with pytest.raises(ChainError):
            verify_delegation(token, resolver, max_chain_depth=2)
