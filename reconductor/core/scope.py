"""Scope validation for authorized targets only."""

from __future__ import annotations

import ipaddress
import re
from typing import Optional

from pydantic import BaseModel, Field

from reconductor.core.logger import get_logger

logger = get_logger(__name__)


class ScopeConfig(BaseModel):
    """Scope validation configuration."""
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_patterns: list[str] = Field(default_factory=list)
    blocked_patterns: list[str] = Field(default_factory=list)
    allowed_asns: list[int] = Field(default_factory=list)
    allowed_ip_ranges: list[str] = Field(default_factory=list)


class ScopeValidator:
    """
    Validates all targets are within authorized scope.

    Prevents out-of-scope scanning which could have legal implications.
    Supports domain validation, ASN-based IP scope, and IP range enforcement.
    """

    def __init__(self, config: ScopeConfig):
        """
        Initialize scope validator.

        Args:
            config: Scope configuration with allowed/blocked patterns
        """
        self.allowed_domains = {d.lower() for d in config.allowed_domains}
        self.allowed_patterns = [
            re.compile(p, re.IGNORECASE) for p in config.allowed_patterns
        ]
        self.blocked_patterns = [
            re.compile(p, re.IGNORECASE) for p in config.blocked_patterns
        ]
        self.allowed_asns = set(config.allowed_asns)
        self.allowed_ip_ranges = [
            ipaddress.ip_network(r, strict=False)
            for r in config.allowed_ip_ranges
        ]

        # Cache for ASN lookups
        self._asn_cache: dict[str, Optional[int]] = {}

    def is_in_scope(self, target: str) -> bool:
        """
        Check if a domain target is within authorized scope.

        Args:
            target: Domain or subdomain to validate

        Returns:
            True if target is in scope, False otherwise
        """
        target = target.lower().strip()

        # Remove protocol if present
        if "://" in target:
            target = target.split("://", 1)[1]

        # Remove path if present
        if "/" in target:
            target = target.split("/", 1)[0]

        # Remove port if present
        if ":" in target:
            target = target.split(":", 1)[0]

        # Check blocked patterns first (deny takes precedence)
        for pattern in self.blocked_patterns:
            if pattern.search(target):
                logger.warning(
                    "Target blocked by pattern",
                    target=target,
                    pattern=pattern.pattern,
                )
                return False

        # Check if target is a subdomain of an allowed domain
        for allowed in self.allowed_domains:
            if target == allowed or target.endswith(f".{allowed}"):
                return True

        # Check allowed patterns
        for pattern in self.allowed_patterns:
            if pattern.match(target):
                return True

        logger.warning("Target rejected - not in scope", target=target)
        return False

    def is_ip_in_scope(self, ip: str) -> bool:
        """
        Validate an IP address against allowed ASN and IP ranges.

        Args:
            ip: IP address to validate

        Returns:
            True if IP is in scope, False otherwise
        """
        # If no IP restrictions configured, allow all
        if not self.allowed_asns and not self.allowed_ip_ranges:
            return True

        try:
            ip_obj = ipaddress.ip_address(ip)

            # Check explicit IP ranges first
            for network in self.allowed_ip_ranges:
                if ip_obj in network:
                    return True

            # Check ASN if configured
            if self.allowed_asns:
                ip_asn = self._lookup_asn(ip)
                if ip_asn and ip_asn in self.allowed_asns:
                    return True

            logger.warning(
                "IP outside authorized scope",
                ip=ip,
                allowed_asns=list(self.allowed_asns) if self.allowed_asns else None,
                allowed_ranges=[str(r) for r in self.allowed_ip_ranges] if self.allowed_ip_ranges else None,
            )
            return False

        except ValueError as e:
            logger.error("Invalid IP address", ip=ip, error=str(e))
            return False

    def _lookup_asn(self, ip: str) -> Optional[int]:
        """
        Look up ASN for an IP address.

        Uses Team Cymru DNS-based ASN lookup.

        Args:
            ip: IP address to look up

        Returns:
            ASN number if found, None otherwise
        """
        if ip in self._asn_cache:
            return self._asn_cache[ip]

        try:
            import socket

            # Reverse the IP for DNS lookup
            ip_obj = ipaddress.ip_address(ip)

            if isinstance(ip_obj, ipaddress.IPv4Address):
                # IPv4: reverse octets and query origin.asn.cymru.com
                reversed_ip = ".".join(reversed(ip.split(".")))
                query = f"{reversed_ip}.origin.asn.cymru.com"
            else:
                # IPv6: reverse nibbles and query origin6.asn.cymru.com
                expanded = ip_obj.exploded.replace(":", "")
                reversed_ip = ".".join(reversed(expanded))
                query = f"{reversed_ip}.origin6.asn.cymru.com"

            try:
                answers = socket.gethostbyname_ex(query)
                if answers and answers[2]:
                    # Response format: "ASN | IP Range | Country | RIR | Date"
                    txt = answers[2][0]
                    asn = int(txt.split("|")[0].strip().replace("AS", ""))
                    self._asn_cache[ip] = asn
                    return asn
            except (socket.gaierror, socket.herror):
                pass

        except Exception as e:
            logger.debug("ASN lookup failed", ip=ip, error=str(e))

        self._asn_cache[ip] = None
        return None

    def validate_batch(
        self,
        targets: list[str],
    ) -> tuple[list[str], list[str]]:
        """
        Validate a batch of targets.

        Args:
            targets: List of targets to validate

        Returns:
            Tuple of (valid_targets, rejected_targets)
        """
        valid = []
        rejected = []

        for target in targets:
            if self.is_in_scope(target):
                valid.append(target)
            else:
                rejected.append(target)

        if rejected:
            logger.warning(
                "Rejected out-of-scope targets",
                count=len(rejected),
                samples=rejected[:5],
            )

        return valid, rejected

    def validate_ips_batch(
        self,
        ips: list[str],
    ) -> tuple[list[str], list[str]]:
        """
        Validate a batch of IP addresses.

        Args:
            ips: List of IP addresses to validate

        Returns:
            Tuple of (valid_ips, rejected_ips)
        """
        valid = []
        rejected = []

        for ip in ips:
            if self.is_ip_in_scope(ip):
                valid.append(ip)
            else:
                rejected.append(ip)

        if rejected:
            logger.warning(
                "Rejected out-of-scope IPs",
                count=len(rejected),
                samples=rejected[:5],
            )

        return valid, rejected

    def add_domain(self, domain: str) -> None:
        """
        Add a domain to the allowed list dynamically.

        Args:
            domain: Domain to add
        """
        self.allowed_domains.add(domain.lower())
        logger.info("Domain added to scope", domain=domain)

    def add_ip_range(self, cidr: str) -> None:
        """
        Add an IP range to the allowed list dynamically.

        Args:
            cidr: CIDR notation IP range
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            self.allowed_ip_ranges.append(network)
            logger.info("IP range added to scope", cidr=cidr)
        except ValueError as e:
            logger.error("Invalid CIDR notation", cidr=cidr, error=str(e))

    def add_asn(self, asn: int) -> None:
        """
        Add an ASN to the allowed list dynamically.

        Args:
            asn: ASN number to add
        """
        self.allowed_asns.add(asn)
        logger.info("ASN added to scope", asn=asn)


def create_scope_validator(
    domains: list[str],
    patterns: Optional[list[str]] = None,
    blocked: Optional[list[str]] = None,
    asns: Optional[list[int]] = None,
    ip_ranges: Optional[list[str]] = None,
) -> ScopeValidator:
    """
    Convenience function to create a scope validator.

    Args:
        domains: List of allowed base domains
        patterns: Optional list of allowed regex patterns
        blocked: Optional list of blocked regex patterns
        asns: Optional list of allowed ASNs
        ip_ranges: Optional list of allowed IP ranges in CIDR notation

    Returns:
        Configured ScopeValidator instance
    """
    config = ScopeConfig(
        allowed_domains=domains,
        allowed_patterns=patterns or [],
        blocked_patterns=blocked or [],
        allowed_asns=asns or [],
        allowed_ip_ranges=ip_ranges or [],
    )
    return ScopeValidator(config)
