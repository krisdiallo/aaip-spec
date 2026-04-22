"""
Tests for AAIP v2.0 delegation functionality.
"""

import os
import sys

import pytest

from aaip.core import (
    check_delegation_authorization,
)

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from utils import create_test_delegation, create_test_delegation_token


class TestDelegationCreation:
    def test_delegation_authorization_check(self):
        delegation = create_test_delegation(
            issuer_identity="user@example.com",
            issuer_identity_system="oauth",
            subject_identity="test_agent",
            subject_identity_system="custom",
            scope=["payments:authorize"],
            constraints={"max_amount": {"value": 500.0, "currency": "USD"}},
        )

        assert check_delegation_authorization(delegation, "payments", "authorize") is True
        assert check_delegation_authorization(delegation, "email", "send") is False

    def test_wildcard_scope(self):
        delegation = create_test_delegation(scope=["data:*"])

        assert check_delegation_authorization(delegation, "data", "read") is True
        assert check_delegation_authorization(delegation, "data", "write") is True
        assert check_delegation_authorization(delegation, "payments", "send") is False

    def test_full_wildcard_scope(self):
        delegation = create_test_delegation(scope=["*"])

        assert check_delegation_authorization(delegation, "anything", "goes") is True

    def test_delegation_fields(self):
        delegation = create_test_delegation(
            issuer_identity="alice@example.com",
            issuer_identity_system="oauth",
            subject_identity="my_agent",
            subject_identity_system="custom",
            scope=["email:send", "calendar:write"],
        )

        assert delegation.iss == "alice@example.com"
        assert delegation.aud == "my_agent"
        assert delegation.issuer_type == "oauth"
        assert delegation.subject_type == "custom"
        assert delegation.scope == ["email:send", "calendar:write"]
        assert delegation.aaip_version == "2.0"
        assert delegation.jti.startswith("del_")

    def test_delegation_to_dict(self):
        delegation = create_test_delegation(scope=["test:action"])
        d = delegation.to_dict()

        assert d["iss"] == delegation.iss
        assert d["aud"] == delegation.aud
        assert d["scope"] == "test:action"
        assert d["aaip"]["version"] == "2.0"


class TestDelegationErrorHandling:
    def test_empty_scope(self):
        with pytest.raises(ValueError):
            create_test_delegation_token(scope=[])

    def test_empty_issuer_identity(self):
        with pytest.raises(ValueError):
            create_test_delegation_token(issuer_identity="")

    def test_empty_subject_identity(self):
        with pytest.raises(ValueError):
            create_test_delegation_token(subject_identity="")
