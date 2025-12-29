"""Tests for core modules."""

import pytest
from pathlib import Path
import tempfile

from reconductor.core.config import Settings, ScopeConfig
from reconductor.core.scope import ScopeValidator
from reconductor.core.rate_limiter import AdaptiveRateLimiter
from reconductor.utils.validator import LLMOutputValidator, HostnameValidator
from reconductor.utils.deduplicator import Deduplicator


class TestSettings:
    """Tests for Settings configuration."""

    def test_default_settings(self):
        """Test default settings are valid."""
        settings = Settings()
        assert settings.app_name == "ReconDuctor"
        assert settings.max_workers == 20
        assert settings.min_workers == 3

    def test_ipv6_prefix_validation(self):
        """Test IPv6 prefix validation."""
        settings = Settings(ipv6_prefix=64)
        assert settings.ipv6_prefix == 64

        with pytest.raises(ValueError):
            Settings(ipv6_prefix=32)


class TestScopeValidator:
    """Tests for scope validation."""

    def test_domain_in_scope(self):
        """Test domain scope validation."""
        config = ScopeConfig(allowed_domains=["example.com"])
        validator = ScopeValidator(config)

        assert validator.is_in_scope("example.com")
        assert validator.is_in_scope("api.example.com")
        assert validator.is_in_scope("dev.api.example.com")
        assert not validator.is_in_scope("example.org")

    def test_blocked_patterns(self):
        """Test blocked pattern matching."""
        config = ScopeConfig(
            allowed_domains=["example.com"],
            blocked_patterns=[r".*\.internal\..*"],
        )
        validator = ScopeValidator(config)

        assert validator.is_in_scope("api.example.com")
        assert not validator.is_in_scope("api.internal.example.com")

    def test_batch_validation(self):
        """Test batch validation."""
        config = ScopeConfig(allowed_domains=["example.com"])
        validator = ScopeValidator(config)

        targets = [
            "api.example.com",
            "dev.example.com",
            "api.other.com",
        ]

        valid, rejected = validator.validate_batch(targets)
        assert len(valid) == 2
        assert len(rejected) == 1
        assert "api.other.com" in rejected


class TestAdaptiveRateLimiter:
    """Tests for adaptive rate limiting."""

    def test_initial_rate(self):
        """Test initial rate configuration."""
        limiter = AdaptiveRateLimiter(initial_rate=30.0)
        assert limiter.get_rate("1.2.3.4") == 30.0

    def test_backoff_on_waf(self):
        """Test rate backoff on WAF detection."""
        limiter = AdaptiveRateLimiter(initial_rate=30.0)

        # Record WAF response
        limiter.record_response("1.2.3.4", 429)

        # Rate should be halved
        assert limiter.get_rate("1.2.3.4") == 15.0

    def test_recovery_after_success(self):
        """Test rate recovery after successful requests."""
        limiter = AdaptiveRateLimiter(initial_rate=30.0)

        # First backoff
        limiter.record_response("1.2.3.4", 429)
        assert limiter.get_rate("1.2.3.4") == 15.0

        # Multiple successes
        for _ in range(10):
            limiter.record_response("1.2.3.4", 200)

        # Rate should recover (but not exceed initial)
        assert limiter.get_rate("1.2.3.4") <= 30.0

    def test_waf_body_detection(self):
        """Test WAF detection in response body."""
        limiter = AdaptiveRateLimiter(initial_rate=30.0)

        # Record response with WAF body
        detected = limiter.record_response(
            "1.2.3.4",
            200,
            body="Access Denied by Cloudflare",
        )

        assert detected is True
        assert limiter.get_rate("1.2.3.4") < 30.0


class TestLLMOutputValidator:
    """Tests for LLM output validation."""

    def test_valid_subdomain(self):
        """Test valid subdomain validation."""
        validator = LLMOutputValidator("example.com")

        result = validator.validate_single("api")
        assert result == "api.example.com"

    def test_invalid_underscore(self):
        """Test underscore rejection."""
        validator = LLMOutputValidator("example.com")

        result = validator.validate_single("api_v2")
        assert result is None  # Underscores invalid in DNS

    def test_full_subdomain_handling(self):
        """Test handling of full subdomain input."""
        validator = LLMOutputValidator("example.com")

        result = validator.validate_single("api.example.com")
        assert result == "api.example.com"

    def test_batch_validation(self):
        """Test batch validation and deduplication."""
        validator = LLMOutputValidator("example.com")

        raw_output = """
        api
        dev
        api
        staging
        invalid_name
        test
        """

        results = validator.validate_and_clean(raw_output)

        assert "api.example.com" in results
        assert "dev.example.com" in results
        assert "staging.example.com" in results
        # Duplicates and invalid should be removed
        assert len(results) == 4  # api, dev, staging, test


class TestHostnameValidator:
    """Tests for hostname validation."""

    def test_valid_hostname(self):
        """Test valid hostname detection."""
        assert HostnameValidator.is_valid_hostname("example.com")
        assert HostnameValidator.is_valid_hostname("api.example.com")
        assert HostnameValidator.is_valid_hostname("dev-api.example.com")

    def test_invalid_hostname(self):
        """Test invalid hostname detection."""
        assert not HostnameValidator.is_valid_hostname("")
        assert not HostnameValidator.is_valid_hostname("-example.com")
        assert not HostnameValidator.is_valid_hostname("example-.com")

    def test_valid_domain(self):
        """Test domain validation."""
        assert HostnameValidator.is_valid_domain("example.com")
        assert not HostnameValidator.is_valid_domain("example")  # No TLD


class TestDeduplicator:
    """Tests for deduplication."""

    def test_simple_dedup(self):
        """Test simple deduplication."""
        dedup = Deduplicator()

        items = ["api.example.com", "dev.example.com", "api.example.com"]
        unique = dedup.deduplicate(items)

        assert len(unique) == 2
        assert "api.example.com" in unique
        assert "dev.example.com" in unique

    def test_case_insensitive(self):
        """Test case-insensitive deduplication."""
        dedup = Deduplicator(case_sensitive=False)

        items = ["API.example.com", "api.example.com"]
        unique = dedup.deduplicate(items)

        assert len(unique) == 1

    def test_with_master_file(self):
        """Test deduplication with master file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("existing.example.com\n")
            master_path = Path(f.name)

        dedup = Deduplicator(master_file=master_path)

        items = ["new.example.com", "existing.example.com"]
        unique = dedup.deduplicate(items)

        assert len(unique) == 1
        assert "new.example.com" in unique

        # Cleanup
        master_path.unlink()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
