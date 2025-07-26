"""
Tests for AAIP constraint validation functionality.

Run with: python -m pytest test_constraints.py
"""

from datetime import datetime, timezone

import pytest

# Import AAIP core modules
from aaip.core import ConstraintError, validate_constraints


class TestConstraintValidation:
    """Test constraint validation."""

    def test_max_amount_constraint(self):
        """Test max_amount constraint validation."""
        constraints = {"max_amount": {"value": 100.0, "currency": "USD"}}

        # Valid request
        valid_request = {"amount": 50.0, "currency": "USD"}

        assert validate_constraints(constraints, valid_request) is True

        # Amount too high
        high_amount_request = {"amount": 150.0, "currency": "USD"}

        with pytest.raises(ConstraintError) as exc_info:
            validate_constraints(constraints, high_amount_request)
        assert "max_amount" in str(exc_info.value) or "Amount" in str(exc_info.value)

    def test_time_window_constraint(self):
        """Test time_window constraint validation."""
        # Create time window constraint (current time should be valid)
        now = datetime.now(timezone.utc)
        start_time = datetime.fromtimestamp(
            now.timestamp() - 1800, tz=timezone.utc
        )  # 30 min ago
        future_time = datetime.fromtimestamp(
            now.timestamp() + 3600, tz=timezone.utc
        )  # 1 hour from now

        constraints = {
            "time_window": {
                "start": start_time.isoformat().replace("+00:00", "Z"),
                "end": future_time.isoformat().replace("+00:00", "Z"),
            }
        }

        # Current time should be valid
        request = {"action": "test"}
        assert validate_constraints(constraints, request) is True

        # Test with past end time (should fail)
        past_constraints = {
            "time_window": {
                "start": start_time.isoformat().replace("+00:00", "Z"),
                "end": start_time.isoformat().replace("+00:00", "Z"),  # Already past
            }
        }

        with pytest.raises(ConstraintError):
            validate_constraints(past_constraints, request)

    def test_domain_constraints(self):
        """Test domain constraint validation."""
        constraints = {
            "allowed_domains": ["company.com", "*.partner.com"],
            "blocked_domains": ["competitor.com", "spam.com"],
        }

        # Valid domain (allowed)
        valid_request = {"domain": "company.com"}

        assert validate_constraints(constraints, valid_request) is True

        # Valid wildcard domain
        wildcard_request = {"domain": "api.partner.com"}

        assert validate_constraints(constraints, wildcard_request) is True

        # Blocked domain
        blocked_request = {"domain": "competitor.com"}

        with pytest.raises(ConstraintError) as exc_info:
            validate_constraints(constraints, blocked_request)
        assert "not in allowed" in str(exc_info.value).lower()

        # Domain not in allowed list
        disallowed_request = {"domain": "unknown.com"}

        with pytest.raises(ConstraintError) as exc_info:
            validate_constraints(constraints, disallowed_request)
        assert "not in allowed" in str(exc_info.value).lower()

    def test_combined_constraints(self):
        """Test multiple constraints working together."""
        constraints = {
            "max_amount": {"value": 500, "currency": "USD"},
            "blocked_domains": ["competitor.com"],
            "blocked_keywords": ["urgent", "limited time"],
        }

        # Valid request that satisfies all constraints
        valid_request = {
            "amount": 100.0,
            "currency": "USD",
            "domain": "goodcompany.com",
            "content": "This is a normal message",
        }

        assert validate_constraints(constraints, valid_request) is True

        # Request that violates max_amount
        invalid_amount_request = {
            "amount": 600.0,  # Exceeds max_amount
            "currency": "USD",
            "domain": "goodcompany.com",
            "content": "This is a normal message",
        }

        with pytest.raises(ConstraintError):
            validate_constraints(constraints, invalid_amount_request)

        # Request that violates blocked domain
        invalid_domain_request = {
            "amount": 100.0,
            "currency": "USD",
            "domain": "competitor.com",  # Blocked domain
            "content": "This is a normal message",
        }

        with pytest.raises(ConstraintError):
            validate_constraints(constraints, invalid_domain_request)

        # Request that violates blocked keywords
        invalid_content_request = {
            "amount": 100.0,
            "currency": "USD",
            "domain": "goodcompany.com",
            "content": "This is an urgent message with limited time offer!",
        }

        with pytest.raises(ConstraintError):
            validate_constraints(constraints, invalid_content_request)


class TestBlockedKeywordsConstraint:
    """Test blocked_keywords constraint."""

    def test_blocked_keywords_constraint(self):
        """Test blocked_keywords constraint validation."""
        constraints = {"blocked_keywords": ["urgent", "limited time", "act now"]}

        # Valid content without blocked keywords
        valid_request = {"content": "This is a normal business message"}

        assert validate_constraints(constraints, valid_request) is True

        # Invalid content with blocked keyword
        invalid_request = {
            "content": "This is an URGENT message that requires immediate action!"
        }

        with pytest.raises(ConstraintError) as exc_info:
            validate_constraints(constraints, invalid_request)
        assert "blocked keyword" in str(exc_info.value).lower()

        # Test case insensitive matching
        case_insensitive_request = {"content": "Limited Time offer available now!"}

        with pytest.raises(ConstraintError):
            validate_constraints(constraints, case_insensitive_request)


if __name__ == "__main__":
    # Run a simple smoke test
    print("Running AAIP constraints smoke test...")

    try:
        # Test constraint validation
        constraints = {"max_amount": {"value": 100.0, "currency": "USD"}}
        print("✓ Created basic constraints")

        # Test constraint validation
        valid_request = {"amount": 50.0, "currency": "USD"}
        validate_constraints(constraints, valid_request)
        print("✓ Constraint validation works")

        print("\033[92mConstraints smoke tests passed!\033[0m")

    except Exception as e:
        print(f"\033[91mConstraints smoke test failed: {e}\033[0m")
        raise
