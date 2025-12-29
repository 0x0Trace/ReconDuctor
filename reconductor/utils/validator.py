"""Validation utilities for LLM outputs and subdomain names."""

from __future__ import annotations

import re
from typing import Optional

from reconductor.core.logger import get_logger

logger = get_logger(__name__)


class LLMOutputValidator:
    """
    Validates and sanitizes LLM-generated subdomain predictions.

    Ensures all generated subdomains are RFC 1035 compliant
    and properly formatted.
    """

    # RFC 1035: hostname label rules
    LABEL_REGEX = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
    MAX_LABEL_LENGTH = 63
    MAX_HOSTNAME_LENGTH = 253

    def __init__(self, base_domain: str):
        """
        Initialize validator for a specific base domain.

        Args:
            base_domain: The base domain for subdomain validation
        """
        self.base_domain = base_domain.lower().strip()
        self.seen: set[str] = set()

    def validate_and_clean(self, raw_output: str) -> list[str]:
        """
        Parse, validate, and deduplicate LLM output.

        Args:
            raw_output: Raw LLM output text

        Returns:
            List of valid, unique subdomain names
        """
        valid_subdomains = []

        for line in raw_output.strip().split("\n"):
            candidate = line.strip().lower()

            # Skip empty lines
            if not candidate:
                continue

            # Remove common LLM artifacts
            candidate = self._clean_artifacts(candidate)

            if not candidate:
                continue

            # Handle if LLM returned full domain
            if candidate.endswith(f".{self.base_domain}"):
                candidate = candidate[: -len(self.base_domain) - 1]
            elif candidate == self.base_domain:
                continue

            # Validate as subdomain prefix
            if not self._is_valid_subdomain(candidate):
                logger.debug(f"Invalid subdomain rejected: {candidate}")
                continue

            # Build full subdomain
            full_subdomain = f"{candidate}.{self.base_domain}"

            # Check total length
            if len(full_subdomain) > self.MAX_HOSTNAME_LENGTH:
                continue

            # Deduplicate
            if full_subdomain in self.seen:
                continue

            self.seen.add(full_subdomain)
            valid_subdomains.append(full_subdomain)

        return valid_subdomains

    def _clean_artifacts(self, candidate: str) -> str:
        """
        Remove common LLM output artifacts.

        Args:
            candidate: Raw candidate string

        Returns:
            Cleaned candidate
        """
        # Remove numbering (e.g., "1. ", "- ")
        candidate = re.sub(r"^[\d]+[.\)]\s*", "", candidate)
        candidate = re.sub(r"^[-*]\s*", "", candidate)

        # Remove quotes
        candidate = candidate.strip("'\"")

        # Remove protocol
        candidate = re.sub(r"^https?://", "", candidate)

        # Remove trailing paths
        if "/" in candidate:
            candidate = candidate.split("/")[0]

        # Remove port
        if ":" in candidate:
            candidate = candidate.split(":")[0]

        return candidate.strip()

    def _is_valid_subdomain(self, subdomain: str) -> bool:
        """
        Check if subdomain is valid per RFC 1035.

        Args:
            subdomain: Subdomain prefix to validate

        Returns:
            True if valid, False otherwise
        """
        if not subdomain:
            return False

        # RFC 1035 Section 2.3.1: Labels must not contain underscores
        if "_" in subdomain:
            return False

        # Handle multi-level subdomains (e.g., "dev.api")
        for label in subdomain.split("."):
            if not self._is_valid_label(label):
                return False

        return True

    def _is_valid_label(self, label: str) -> bool:
        """
        Check if a single DNS label is valid.

        Args:
            label: DNS label to validate

        Returns:
            True if valid, False otherwise
        """
        if not label:
            return False

        if len(label) > self.MAX_LABEL_LENGTH:
            return False

        # Must match RFC 1035 pattern
        if not self.LABEL_REGEX.match(label):
            return False

        # Cannot start or end with hyphen
        if label.startswith("-") or label.endswith("-"):
            return False

        return True

    def validate_single(self, subdomain: str) -> Optional[str]:
        """
        Validate a single subdomain.

        Args:
            subdomain: Subdomain to validate

        Returns:
            Validated full subdomain or None if invalid
        """
        subdomain = subdomain.lower().strip()

        # Clean artifacts
        subdomain = self._clean_artifacts(subdomain)

        if not subdomain:
            return None

        # Handle if full domain provided
        if subdomain.endswith(f".{self.base_domain}"):
            prefix = subdomain[: -len(self.base_domain) - 1]
        else:
            prefix = subdomain

        if not self._is_valid_subdomain(prefix):
            return None

        full = f"{prefix}.{self.base_domain}"

        if len(full) > self.MAX_HOSTNAME_LENGTH:
            return None

        return full

    def reset(self) -> None:
        """Reset seen set for new validation batch."""
        self.seen.clear()


class HostnameValidator:
    """
    General hostname validation utility.
    """

    HOSTNAME_REGEX = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$"
    )

    @classmethod
    def is_valid_hostname(cls, hostname: str) -> bool:
        """
        Check if a string is a valid hostname.

        Args:
            hostname: Hostname to validate

        Returns:
            True if valid, False otherwise
        """
        if not hostname or len(hostname) > 253:
            return False

        # Remove trailing dot if present
        if hostname.endswith("."):
            hostname = hostname[:-1]

        # Check each label
        for label in hostname.split("."):
            if not cls.HOSTNAME_REGEX.match(label):
                return False

        return True

    @classmethod
    def is_valid_domain(cls, domain: str) -> bool:
        """
        Check if a string is a valid domain name.

        Args:
            domain: Domain to validate

        Returns:
            True if valid, False otherwise
        """
        if not cls.is_valid_hostname(domain):
            return False

        # Domain must have at least one dot
        if "." not in domain:
            return False

        # TLD must be at least 2 characters
        tld = domain.split(".")[-1]
        if len(tld) < 2:
            return False

        return True

    @classmethod
    def extract_base_domain(cls, subdomain: str) -> Optional[str]:
        """
        Extract the base domain from a subdomain.

        Simple implementation - assumes last two parts are base domain.
        For more accurate results, use a proper public suffix library.

        Args:
            subdomain: Full subdomain

        Returns:
            Base domain or None if invalid
        """
        if not cls.is_valid_hostname(subdomain):
            return None

        parts = subdomain.lower().split(".")

        if len(parts) < 2:
            return None

        # Simple heuristic: last two parts are base domain
        # This doesn't handle .co.uk, .com.au, etc. properly
        return ".".join(parts[-2:])
