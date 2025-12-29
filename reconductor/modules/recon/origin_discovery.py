"""
Comprehensive Origin IP Discovery module for CDN/WAF bypass.

Combines multiple techniques to find origin servers behind Cloudflare, Akamai, Fastly, etc.

Techniques implemented:
1. DNS-based discovery (SPF, MX, AAAA records)
2. Subdomain IP analysis (non-CDN IPs from enumeration)
3. Shodan SSL/Favicon matching (existing)
4. SecurityTrails historical DNS (finds pre-CDN IPs)
5. check-host.net CDN validation (free, no API key)
6. HTTP response validation (active confirmation)

References:
- https://blog.christophetd.fr/bypassing-cloudflare-using-internet-wide-scan-data/
- https://github.com/mrh0wl/Cloudmare
- https://github.com/gwen001/cloudflare-origin-ip
- https://docs.securitytrails.com/reference/dns-history-by-record-type-old-1
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from collections import defaultdict
import hashlib

import httpx

from reconductor.core.logger import get_logger
from reconductor.modules.recon.shodan_recon import (
    ShodanClient,
    ShodanOriginFinder,
    FaviconHasher,
    OriginIPResult,
    AKAMAI_RANGES,
    FASTLY_RANGES,
)

# Expanded Cloudflare ranges (more complete list)
CLOUDFLARE_RANGES = [
    "103.21.244.", "103.22.200.", "103.31.4.", "104.16.", "104.17.",
    "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.",
    "104.24.", "104.25.", "104.26.", "104.27.", "108.162.", "131.0.72.",
    "141.101.", "162.158.", "162.159.",  # Added 162.159
    "172.64.", "172.65.", "172.66.", "172.67.",
    "173.245.", "188.114.", "190.93.", "197.234.", "198.41.",
]

logger = get_logger(__name__)

# Extended CDN IP ranges
CLOUDFRONT_RANGES = ["13.32.", "13.33.", "13.35.", "52.84.", "52.85.", "54.182.", "54.192.", "54.230.", "54.239.", "99.84.", "143.204.", "204.246."]
INCAPSULA_RANGES = ["199.83.", "198.143.", "149.126.", "185.11.", "192.230."]
SUCURI_RANGES = ["192.88.", "185.93."]

ALL_CDN_RANGES = CLOUDFLARE_RANGES + AKAMAI_RANGES + FASTLY_RANGES + CLOUDFRONT_RANGES + INCAPSULA_RANGES + SUCURI_RANGES

# Known CDN/WAF provider names for check-host.net validation
CDN_PROVIDER_NAMES = [
    "cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "imperva",
    "sucuri", "stackpath", "maxcdn", "keycdn", "bunnycdn", "cdn77",
    "leaseweb", "ovh", "google", "microsoft", "amazon", "azure",
]


class SecurityTrailsClient:
    """
    SecurityTrails API client for historical DNS lookups.

    Used to find origin IPs from before CDN was added.
    Free tier: 50 queries/month.

    API Reference: https://docs.securitytrails.com/reference/dns-history-by-record-type-old-1
    """

    BASE_URL = "https://api.securitytrails.com/v1"

    def __init__(self, api_key: str, timeout: int = 30):
        self.api_key = api_key
        self.timeout = timeout

    async def get_historical_dns(self, domain: str, record_type: str = "a") -> list[dict]:
        """
        Get historical DNS records for a domain.

        Args:
            domain: Target domain
            record_type: DNS record type (a, aaaa, mx, ns, txt, soa)

        Returns:
            List of historical records with IPs and dates

        Response format:
            {
                "records": [
                    {
                        "first_seen": "2018-06-08",
                        "last_seen": null,  # null means still active
                        "organizations": ["Some ISP"],
                        "values": [{"ip": "1.2.3.4", "ip_count": 1}]
                    }
                ]
            }
        """
        if record_type.lower() not in ["a", "aaaa", "mx", "ns", "txt", "soa"]:
            raise ValueError(f"Invalid record type: {record_type}")

        url = f"{self.BASE_URL}/history/{domain}/dns/{record_type.lower()}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    url,
                    headers={
                        "APIKEY": self.api_key,
                        "Accept": "application/json",
                    },
                )

                if response.status_code == 200:
                    data = response.json()
                    return data.get("records", [])
                elif response.status_code == 429:
                    logger.warning("SecurityTrails rate limit exceeded")
                    return []
                elif response.status_code == 403:
                    logger.warning("SecurityTrails API key invalid or quota exceeded")
                    return []
                else:
                    logger.debug(f"SecurityTrails API error: {response.status_code}")
                    return []

        except Exception as e:
            logger.debug(f"SecurityTrails request failed: {e}")
            return []

    async def find_historical_ips(self, domain: str) -> list[tuple[str, str, str]]:
        """
        Find historical A record IPs for origin discovery.

        Returns:
            List of (ip, first_seen, last_seen) tuples
            last_seen is None if the record is still active
        """
        records = await self.get_historical_dns(domain, "a")
        results = []

        for record in records:
            first_seen = record.get("first_seen", "unknown")
            last_seen = record.get("last_seen")  # None if still active
            values = record.get("values", [])

            for value in values:
                ip = value.get("ip")
                if ip:
                    results.append((ip, first_seen, last_seen))

        return results


class CheckHostValidator:
    """
    Validates IPs using check-host.net to identify CDN/hosting providers.

    Free service, no API key required.
    Parses organization information from IP info page.
    """

    BASE_URL = "https://check-host.net/ip-info"

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self._cache: dict[str, tuple[bool, str]] = {}

    async def is_cdn_ip(self, ip: str) -> tuple[bool, Optional[str]]:
        """
        Check if an IP belongs to a CDN/WAF provider.

        Args:
            ip: IP address to check

        Returns:
            (is_cdn, provider_name) tuple
        """
        # Check cache first
        if ip in self._cache:
            return self._cache[ip]

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.BASE_URL}?host={ip}",
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                    },
                )

                if response.status_code != 200:
                    return (False, None)

                html = response.text.lower()

                # Look for CDN provider names in the page
                for provider in CDN_PROVIDER_NAMES:
                    if provider in html:
                        # Extract more specific provider info
                        provider_name = provider.capitalize()
                        self._cache[ip] = (True, provider_name)
                        return (True, provider_name)

                # Check for ASN numbers associated with CDNs
                cdn_asns = {
                    "as13335": "Cloudflare",
                    "as20940": "Akamai",
                    "as54113": "Fastly",
                    "as16509": "Amazon/CloudFront",
                    "as8075": "Microsoft/Azure",
                    "as15169": "Google",
                }

                for asn, name in cdn_asns.items():
                    if asn in html:
                        self._cache[ip] = (True, name)
                        return (True, name)

                self._cache[ip] = (False, None)
                return (False, None)

        except Exception as e:
            logger.debug(f"check-host.net validation failed for {ip}: {e}")
            return (False, None)

    async def validate_batch(self, ips: list[str]) -> dict[str, tuple[bool, Optional[str]]]:
        """
        Validate multiple IPs in parallel.

        Args:
            ips: List of IPs to check

        Returns:
            Dict mapping IP -> (is_cdn, provider)
        """
        results = {}
        semaphore = asyncio.Semaphore(3)  # Be nice to the free service

        async def check_one(ip: str):
            async with semaphore:
                is_cdn, provider = await self.is_cdn_ip(ip)
                results[ip] = (is_cdn, provider)
                # Small delay between requests
                await asyncio.sleep(0.5)

        await asyncio.gather(*[check_one(ip) for ip in ips])
        return results


@dataclass
class OriginCandidate:
    """A candidate origin IP with evidence tracking."""
    ip: str
    sources: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    port: int = 443
    confidence: float = 0.0
    is_validated: bool = False
    validation_score: float = 0.0
    evidence: dict[str, Any] = field(default_factory=dict)
    # Reverse IP lookup data
    reverse_dns_hostnames: list[str] = field(default_factory=list)
    co_hosted_domains: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)

    def add_source(self, source: str, hostname: str = None, evidence: str = None):
        """Add a discovery source."""
        if source not in self.sources:
            self.sources.append(source)
        if hostname and hostname not in self.hostnames:
            self.hostnames.append(hostname)
        if evidence:
            self.evidence[source] = evidence
        self._update_confidence()

    def _update_confidence(self):
        """Update confidence based on number of sources."""
        # Base confidence from source count
        source_weights = {
            "spf_record": 0.25,
            "mx_record": 0.20,
            "subdomain": 0.15,
            "shodan_ssl": 0.20,
            "shodan_favicon": 0.25,
            "historical_dns": 0.15,
            "aaaa_record": 0.10,
        }

        total = sum(source_weights.get(s, 0.10) for s in self.sources)
        self.confidence = min(total, 0.95)  # Cap at 95% before validation

    @property
    def confidence_level(self) -> str:
        """Get human-readable confidence level."""
        if self.is_validated and self.validation_score > 0.8:
            return "confirmed"
        elif self.confidence >= 0.5 or len(self.sources) >= 3:
            return "high"
        elif self.confidence >= 0.25 or len(self.sources) >= 2:
            return "medium"
        return "low"


@dataclass
class OriginDiscoveryResult:
    """Complete result of origin IP discovery."""
    domain: str
    is_behind_cdn: bool = False
    cdn_provider: Optional[str] = None
    cdn_ips: list[str] = field(default_factory=list)
    candidates: list[OriginCandidate] = field(default_factory=list)
    confirmed_origins: list[OriginCandidate] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "domain": self.domain,
            "is_behind_cdn": self.is_behind_cdn,
            "cdn_provider": self.cdn_provider,
            "cdn_ips": self.cdn_ips,
            "confirmed_origins": [
                {
                    "ip": c.ip,
                    "confidence": c.confidence_level,
                    "validation_score": c.validation_score,
                    "sources": c.sources,
                    "hostnames": c.hostnames,
                    "evidence": c.evidence,
                    "reverse_dns": c.reverse_dns_hostnames,
                    "co_hosted_domains": c.co_hosted_domains,
                    "open_ports": c.open_ports,
                }
                for c in self.confirmed_origins
            ],
            "candidates": [
                {
                    "ip": c.ip,
                    "confidence": c.confidence_level,
                    "sources": c.sources,
                    "hostnames": c.hostnames,
                    "reverse_dns": c.reverse_dns_hostnames,
                    "co_hosted_domains": c.co_hosted_domains,
                    "open_ports": c.open_ports,
                }
                for c in self.candidates
                if c not in self.confirmed_origins
            ],
        }


class OriginDiscovery:
    """
    Comprehensive origin IP discovery combining multiple techniques.

    Usage:
        discovery = OriginDiscovery(shodan_api_key="...", securitytrails_api_key="...")
        result = await discovery.discover(
            domain="example.com",
            subdomains=["mail.example.com", "ftp.example.com"],
            resolved_ips={"mail.example.com": "192.168.1.50"},
            target_url="https://example.com"
        )
    """

    def __init__(
        self,
        shodan_api_key: Optional[str] = None,
        securitytrails_api_key: Optional[str] = None,
        timeout: int = 30,
        validate_candidates: bool = True,
        max_validation_candidates: int = 10,
        use_checkhost: bool = True,
    ):
        """
        Initialize origin discovery.

        Args:
            shodan_api_key: Shodan API key for SSL/favicon searches
            securitytrails_api_key: SecurityTrails API key for historical DNS
            timeout: HTTP request timeout
            validate_candidates: Whether to perform HTTP validation
            max_validation_candidates: Max candidates to validate (reduces noise)
            use_checkhost: Use check-host.net for additional CDN validation
        """
        self.shodan_api_key = shodan_api_key
        self.securitytrails_api_key = securitytrails_api_key
        self.timeout = timeout
        self.validate_candidates = validate_candidates
        self.max_validation_candidates = max_validation_candidates
        self.use_checkhost = use_checkhost

        # Initialize Shodan components if key available
        self.shodan_finder = None
        self.shodan_client = None
        self.favicon_hasher = None
        if shodan_api_key:
            self.shodan_finder = ShodanOriginFinder(api_key=shodan_api_key, timeout=timeout)
            self.shodan_client = ShodanClient(api_key=shodan_api_key, timeout=timeout)
            self.favicon_hasher = FaviconHasher(timeout=timeout)

        # Initialize SecurityTrails client if key available
        self.securitytrails_client = None
        if securitytrails_api_key:
            self.securitytrails_client = SecurityTrailsClient(
                api_key=securitytrails_api_key,
                timeout=timeout
            )

        # Initialize check-host.net validator (always available, no key needed)
        self.checkhost_validator = CheckHostValidator(timeout=timeout) if use_checkhost else None

    async def discover(
        self,
        domain: str,
        subdomains: list[str] = None,
        resolved_ips: dict[str, str] = None,
        target_url: str = None,
    ) -> OriginDiscoveryResult:
        """
        Discover origin IPs using all available techniques.

        Args:
            domain: Target domain
            subdomains: List of discovered subdomains (from Phase 1)
            resolved_ips: Dict of subdomain -> IP mappings
            target_url: URL for favicon/baseline fetching

        Returns:
            OriginDiscoveryResult with candidates and confirmed origins
        """
        result = OriginDiscoveryResult(domain=domain)
        candidates: dict[str, OriginCandidate] = {}

        # Step 1: Check if domain is behind CDN
        cdn_check = await self._check_cdn_status(domain)
        result.is_behind_cdn = cdn_check["is_cdn"]
        result.cdn_provider = cdn_check.get("provider")
        result.cdn_ips = cdn_check.get("ips", [])

        if not result.is_behind_cdn:
            logger.info(f"{domain} is not behind CDN, skipping origin discovery")
            return result

        logger.info(f"{domain} is behind {result.cdn_provider or 'CDN'}, starting origin discovery")

        # Step 2: DNS-based discovery (SPF, MX, AAAA)
        dns_candidates = await self._discover_from_dns(domain)
        for ip, info in dns_candidates.items():
            if ip not in candidates:
                candidates[ip] = OriginCandidate(ip=ip)
            for source, hostname in info:
                candidates[ip].add_source(source, hostname, f"DNS {source}")

        # Step 3: Subdomain IP analysis
        if subdomains and resolved_ips:
            subdomain_candidates = self._analyze_subdomain_ips(subdomains, resolved_ips)
            for ip, hostnames in subdomain_candidates.items():
                if ip not in candidates:
                    candidates[ip] = OriginCandidate(ip=ip)
                for hostname in hostnames:
                    candidates[ip].add_source("subdomain", hostname, f"Subdomain {hostname}")

        # Step 4: Shodan-based discovery
        if self.shodan_finder:
            shodan_candidates = await self._discover_from_shodan(domain, target_url)
            for origin in shodan_candidates:
                if origin.ip not in candidates:
                    candidates[origin.ip] = OriginCandidate(ip=origin.ip, port=origin.port)
                candidates[origin.ip].add_source(
                    f"shodan_{origin.source.replace('shodan_', '')}",
                    origin.hostname,
                    origin.evidence
                )

        # Step 5: SecurityTrails historical DNS (finds pre-CDN IPs)
        if self.securitytrails_client:
            historical_candidates = await self._discover_from_securitytrails(domain)
            for ip, first_seen, last_seen in historical_candidates:
                if ip not in candidates:
                    candidates[ip] = OriginCandidate(ip=ip)
                # Historical IPs that are no longer active are high-value
                evidence = f"First seen: {first_seen}"
                if last_seen:
                    evidence += f", Last seen: {last_seen} (pre-CDN)"
                    # Boost confidence for IPs no longer in use (likely pre-CDN)
                    candidates[ip].evidence["pre_cdn"] = True
                candidates[ip].add_source("historical_dns", domain, evidence)
                logger.debug(f"SecurityTrails historical IP: {ip} ({evidence})")

        # Step 6: Filter CDN IPs using static ranges
        valid_candidates = [c for ip, c in candidates.items() if not self._is_cdn_ip(ip)]

        # Step 7: Additional CDN validation via check-host.net (for uncertain IPs)
        if self.checkhost_validator and valid_candidates:
            # Only validate IPs we're uncertain about (single source, low confidence)
            uncertain_ips = [
                c.ip for c in valid_candidates
                if len(c.sources) == 1 and c.confidence < 0.3
            ][:5]  # Limit to 5 to avoid too many requests

            if uncertain_ips:
                logger.debug(f"Validating {len(uncertain_ips)} uncertain IPs via check-host.net")
                checkhost_results = await self.checkhost_validator.validate_batch(uncertain_ips)

                # Remove IPs confirmed as CDN
                for ip, (is_cdn, provider) in checkhost_results.items():
                    if is_cdn:
                        logger.debug(f"check-host.net confirmed {ip} is CDN ({provider})")
                        valid_candidates = [c for c in valid_candidates if c.ip != ip]
                    else:
                        # Add evidence that it's NOT a CDN
                        for c in valid_candidates:
                            if c.ip == ip:
                                c.add_source("checkhost_validated", domain, "Not CDN (check-host.net)")

        valid_candidates.sort(key=lambda c: (-len(c.sources), -c.confidence))

        # Step 8: HTTP validation of top candidates
        if self.validate_candidates and valid_candidates and target_url:
            baseline = await self._get_baseline_response(target_url)
            if baseline:
                top_candidates = valid_candidates[:self.max_validation_candidates]
                await self._validate_candidates(top_candidates, domain, baseline)

        # Step 9: Shodan reverse IP lookup for co-hosted domains
        if self.shodan_client and valid_candidates:
            await self._enrich_with_reverse_ip(valid_candidates[:10], domain)

        # Separate confirmed and candidates
        for candidate in valid_candidates:
            if candidate.is_validated and candidate.validation_score > 0.7:
                result.confirmed_origins.append(candidate)
            else:
                result.candidates.append(candidate)

        # Sort by confidence
        result.confirmed_origins.sort(key=lambda c: -c.validation_score)
        result.candidates.sort(key=lambda c: (-len(c.sources), -c.confidence))

        logger.info(
            f"Origin discovery complete for {domain}",
            confirmed=len(result.confirmed_origins),
            candidates=len(result.candidates),
        )

        return result

    async def _check_cdn_status(self, domain: str) -> dict:
        """Check if domain is behind CDN and identify provider."""
        import socket

        result = {"is_cdn": False, "provider": None, "ips": []}

        try:
            # Resolve domain
            ips = socket.gethostbyname_ex(domain)[2]
            result["ips"] = ips

            for ip in ips:
                provider = self._identify_cdn(ip)
                if provider:
                    result["is_cdn"] = True
                    result["provider"] = provider
                    break

        except socket.gaierror:
            logger.debug(f"Could not resolve {domain}")

        return result

    async def _discover_from_dns(self, domain: str) -> dict[str, list[tuple[str, str]]]:
        """
        Discover origin IPs from DNS records (SPF, MX, AAAA).

        Returns:
            Dict mapping IP -> list of (source, hostname) tuples
        """
        import subprocess

        candidates = defaultdict(list)

        # SPF Record
        try:
            spf_ips = await self._extract_spf_ips(domain)
            for ip in spf_ips:
                if not self._is_cdn_ip(ip):
                    candidates[ip].append(("spf_record", domain))
                    logger.debug(f"SPF record contains IP: {ip}")
        except Exception as e:
            logger.debug(f"SPF lookup failed: {e}")

        # MX Records
        try:
            mx_ips = await self._extract_mx_ips(domain)
            for ip, hostname in mx_ips:
                if not self._is_cdn_ip(ip):
                    candidates[ip].append(("mx_record", hostname))
                    logger.debug(f"MX record {hostname} resolves to: {ip}")
        except Exception as e:
            logger.debug(f"MX lookup failed: {e}")

        # AAAA Records (IPv6 often not behind CDN)
        try:
            aaaa_ips = await self._extract_aaaa_records(domain)
            for ip in aaaa_ips:
                # IPv6 - check if it's a CDN IPv6
                if not self._is_cdn_ipv6(ip):
                    candidates[ip].append(("aaaa_record", domain))
                    logger.debug(f"AAAA record: {ip}")
        except Exception as e:
            logger.debug(f"AAAA lookup failed: {e}")

        return dict(candidates)

    async def _extract_spf_ips(self, domain: str) -> list[str]:
        """Extract IP addresses from SPF record."""
        import subprocess

        ips = []

        try:
            # Query TXT records
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "TXT", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            txt_records = stdout.decode().strip()

            # Find SPF record
            for line in txt_records.split("\n"):
                if "v=spf1" in line.lower():
                    # Extract ip4: entries
                    ip4_matches = re.findall(r'ip4:([0-9./]+)', line, re.IGNORECASE)
                    for match in ip4_matches:
                        # Handle CIDR notation
                        ip = match.split("/")[0]
                        ips.append(ip)

                    # Extract ip6: entries
                    ip6_matches = re.findall(r'ip6:([0-9a-fA-F:./]+)', line, re.IGNORECASE)
                    for match in ip6_matches:
                        ip = match.split("/")[0]
                        ips.append(ip)

        except Exception as e:
            logger.debug(f"SPF extraction failed: {e}")

        return ips

    async def _extract_mx_ips(self, domain: str) -> list[tuple[str, str]]:
        """Extract IPs from MX records."""
        import subprocess
        import socket

        results = []

        # Skip common third-party mail providers (not origin servers)
        third_party_mail = [
            "google.com", "googlemail.com", "outlook.com", "office365",
            "protection.outlook", "mimecast", "proofpoint", "barracuda",
            "messagelabs", "pphosted", "mailgun", "sendgrid", "amazonaws",
            "zoho.com", "zohomail", "fastmail", "mailchimp",
        ]

        try:
            # Query MX records
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "MX", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            mx_records = stdout.decode().strip()

            for line in mx_records.split("\n"):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        mx_host = parts[-1].rstrip(".").lower()

                        # Skip third-party mail providers
                        if any(provider in mx_host for provider in third_party_mail):
                            logger.debug(f"Skipping third-party MX: {mx_host}")
                            continue

                        # Resolve MX hostname to IP
                        try:
                            ip = socket.gethostbyname(mx_host)
                            results.append((ip, mx_host))
                        except socket.gaierror:
                            pass

        except Exception as e:
            logger.debug(f"MX extraction failed: {e}")

        return results

    async def _extract_aaaa_records(self, domain: str) -> list[str]:
        """Extract IPv6 addresses."""
        ips = []

        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "AAAA", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)

            for line in stdout.decode().strip().split("\n"):
                line = line.strip()
                if line and ":" in line:  # Basic IPv6 check
                    ips.append(line)

        except Exception as e:
            logger.debug(f"AAAA extraction failed: {e}")

        return ips

    def _analyze_subdomain_ips(
        self,
        subdomains: list[str],
        resolved_ips: dict[str, str],
    ) -> dict[str, list[str]]:
        """
        Analyze subdomain IPs to find non-CDN origins.

        Args:
            subdomains: List of subdomains
            resolved_ips: Dict of subdomain -> IP

        Returns:
            Dict mapping non-CDN IP -> list of subdomains
        """
        candidates = defaultdict(list)

        # Common subdomains that often bypass CDN
        high_value_prefixes = {
            "mail", "smtp", "pop", "imap", "email",  # Mail
            "ftp", "sftp", "files",  # File transfer
            "direct", "origin", "backend", "server",  # Direct access
            "cpanel", "whm", "plesk", "webmail",  # Control panels
            "dev", "staging", "test", "beta",  # Non-prod
            "vpn", "remote", "ssh",  # Remote access
            "api", "ws", "websocket",  # APIs (sometimes direct)
        }

        for subdomain in subdomains:
            ip = resolved_ips.get(subdomain)
            if not ip:
                continue

            # Skip CDN IPs
            if self._is_cdn_ip(ip):
                continue

            # Check if it's a high-value subdomain
            prefix = subdomain.split(".")[0].lower()
            is_high_value = prefix in high_value_prefixes

            candidates[ip].append(subdomain)

            if is_high_value:
                logger.debug(f"High-value subdomain {subdomain} -> {ip}")

        return dict(candidates)

    async def _discover_from_shodan(
        self,
        domain: str,
        target_url: str = None,
    ) -> list[OriginIPResult]:
        """Use existing Shodan discovery."""
        if not self.shodan_finder:
            return []

        try:
            origins = await self.shodan_finder.find_origin_ips(
                domain=domain,
                target_url=target_url,
            )
            return [o for o in origins if not o.is_cdn]
        except Exception as e:
            logger.warning(f"Shodan discovery failed: {e}")
            return []

    async def _discover_from_securitytrails(
        self,
        domain: str,
    ) -> list[tuple[str, str, Optional[str]]]:
        """
        Discover origin IPs from SecurityTrails historical DNS.

        This is highly effective because it can find IPs that were used
        BEFORE the domain moved behind a CDN.

        Args:
            domain: Target domain

        Returns:
            List of (ip, first_seen, last_seen) tuples
            last_seen is None if record is still active
        """
        if not self.securitytrails_client:
            return []

        try:
            logger.debug(f"Querying SecurityTrails historical DNS for {domain}")
            historical_ips = await self.securitytrails_client.find_historical_ips(domain)

            # Filter out CDN IPs from historical data
            non_cdn_ips = []
            for ip, first_seen, last_seen in historical_ips:
                if not self._is_cdn_ip(ip):
                    non_cdn_ips.append((ip, first_seen, last_seen))
                else:
                    logger.debug(f"Filtering historical CDN IP: {ip}")

            if non_cdn_ips:
                logger.info(f"SecurityTrails found {len(non_cdn_ips)} historical non-CDN IPs")

            return non_cdn_ips

        except Exception as e:
            logger.warning(f"SecurityTrails discovery failed: {e}")
            return []

    async def _enrich_with_reverse_ip(
        self,
        candidates: list[OriginCandidate],
        target_domain: str,
    ) -> None:
        """
        Enrich candidates with Shodan reverse IP lookup data.

        Retrieves:
        - All hostnames associated with the IP
        - Open ports
        - Co-hosted domains (other domains on same server)

        This is valuable for:
        1. Confirming the IP serves the target domain
        2. Finding additional attack surface (shared hosting)
        3. Identifying the server's purpose

        Args:
            candidates: List of origin candidates to enrich
            target_domain: The target domain we're investigating
        """
        if not self.shodan_client:
            return

        logger.debug(f"Performing Shodan reverse IP lookup for {len(candidates)} candidates")

        semaphore = asyncio.Semaphore(3)  # Limit concurrent Shodan requests

        async def enrich_one(candidate: OriginCandidate):
            async with semaphore:
                try:
                    host_info = await self.shodan_client.host_info(candidate.ip)

                    if not host_info:
                        return

                    # Extract hostnames (reverse DNS)
                    hostnames = host_info.get("hostnames", [])
                    candidate.reverse_dns_hostnames = hostnames

                    # Extract open ports
                    ports = host_info.get("ports", [])
                    candidate.open_ports = sorted(ports)

                    # Identify co-hosted domains (domains on same IP that aren't target)
                    co_hosted = []
                    target_base = target_domain.lower()
                    for hostname in hostnames:
                        hostname_lower = hostname.lower()
                        # Skip if it's the target domain or subdomain of target
                        if hostname_lower == target_base or hostname_lower.endswith(f".{target_base}"):
                            continue
                        # Extract domain from hostname
                        parts = hostname_lower.split(".")
                        if len(parts) >= 2:
                            domain = ".".join(parts[-2:])
                            if domain not in co_hosted and domain != target_base:
                                co_hosted.append(domain)

                    candidate.co_hosted_domains = co_hosted[:20]  # Limit to 20

                    # If target domain found in hostnames, boost confidence
                    target_found = any(
                        target_base in h.lower()
                        for h in hostnames
                    )
                    if target_found:
                        candidate.add_source("shodan_reverse_dns", target_domain, f"Reverse DNS confirms {target_domain}")
                        logger.debug(f"Reverse DNS confirms {candidate.ip} serves {target_domain}")

                    if co_hosted:
                        logger.debug(f"{candidate.ip} co-hosts {len(co_hosted)} other domains: {co_hosted[:5]}")

                    if ports:
                        logger.debug(f"{candidate.ip} has {len(ports)} open ports: {ports[:10]}")

                except Exception as e:
                    logger.debug(f"Reverse IP lookup failed for {candidate.ip}: {e}")

        await asyncio.gather(*[enrich_one(c) for c in candidates])

        # Log summary
        enriched = sum(1 for c in candidates if c.reverse_dns_hostnames or c.open_ports)
        logger.info(f"Shodan reverse IP enriched {enriched}/{len(candidates)} candidates")

    async def _get_baseline_response(self, url: str) -> Optional[dict]:
        """Get baseline response from CDN-protected URL for comparison."""
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,
            ) as client:
                response = await client.get(url)

                return {
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "content_hash": hashlib.md5(response.content).hexdigest(),
                    "title": self._extract_title(response.text),
                    "headers": dict(response.headers),
                    "content_sample": response.text[:5000] if response.text else "",
                }

        except Exception as e:
            logger.warning(f"Failed to get baseline response: {e}")
            return None

    async def _validate_candidates(
        self,
        candidates: list[OriginCandidate],
        domain: str,
        baseline: dict,
    ) -> None:
        """
        Validate candidates by comparing HTTP responses.

        Makes requests directly to candidate IPs with Host header set to domain.
        Compares response to baseline from CDN.
        """
        logger.info(f"Validating {len(candidates)} origin candidates...")

        semaphore = asyncio.Semaphore(5)  # Limit concurrent validations

        async def validate_one(candidate: OriginCandidate):
            async with semaphore:
                score = await self._check_candidate_response(candidate, domain, baseline)
                candidate.validation_score = score
                candidate.is_validated = True

                if score > 0.7:
                    logger.info(f"Confirmed origin: {candidate.ip} (score: {score:.2f})")

        await asyncio.gather(*[validate_one(c) for c in candidates])

    async def _check_candidate_response(
        self,
        candidate: OriginCandidate,
        domain: str,
        baseline: dict,
    ) -> float:
        """
        Check if candidate IP returns similar content to baseline.

        Returns:
            Similarity score 0.0-1.0
        """
        # Try both HTTP and HTTPS
        for scheme in ["https", "http"]:
            try:
                url = f"{scheme}://{candidate.ip}"

                async with httpx.AsyncClient(
                    timeout=10,
                    follow_redirects=True,
                    verify=False,
                ) as client:
                    response = await client.get(
                        url,
                        headers={"Host": domain},
                    )

                    # Calculate similarity score
                    score = self._calculate_similarity(response, baseline)

                    if score > 0:
                        candidate.evidence["http_validation"] = {
                            "url": url,
                            "status_code": response.status_code,
                            "similarity": score,
                        }
                        return score

            except Exception as e:
                logger.debug(f"Validation failed for {candidate.ip}: {e}")
                continue

        return 0.0

    def _calculate_similarity(self, response: httpx.Response, baseline: dict) -> float:
        """
        Calculate similarity between response and baseline.

        Scoring:
        - Status code match: 0.2
        - Content length similar (±20%): 0.2
        - Title match: 0.3
        - Content hash match: 0.3
        """
        score = 0.0

        # Status code match
        if response.status_code == baseline["status_code"]:
            score += 0.2
        elif abs(response.status_code - baseline["status_code"]) < 100:
            score += 0.1

        # Content length similarity
        content_length = len(response.content)
        baseline_length = baseline["content_length"]
        if baseline_length > 0:
            ratio = min(content_length, baseline_length) / max(content_length, baseline_length)
            if ratio > 0.8:
                score += 0.2
            elif ratio > 0.5:
                score += 0.1

        # Title match
        response_title = self._extract_title(response.text)
        if response_title and baseline["title"]:
            if response_title.lower() == baseline["title"].lower():
                score += 0.3
            elif response_title.lower() in baseline["title"].lower() or baseline["title"].lower() in response_title.lower():
                score += 0.15

        # Content hash match (exact match)
        response_hash = hashlib.md5(response.content).hexdigest()
        if response_hash == baseline["content_hash"]:
            score += 0.3
        else:
            # Partial content similarity using simple comparison
            if baseline["content_sample"] and response.text:
                common = self._text_similarity(response.text[:5000], baseline["content_sample"])
                score += 0.3 * common

        return min(score, 1.0)

    def _text_similarity(self, text1: str, text2: str) -> float:
        """Simple text similarity using common subsequences."""
        if not text1 or not text2:
            return 0.0

        # Simple word-based Jaccard similarity
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())

        if not words1 or not words2:
            return 0.0

        intersection = len(words1 & words2)
        union = len(words1 | words2)

        return intersection / union if union > 0 else 0.0

    def _extract_title(self, html: str) -> Optional[str]:
        """Extract title from HTML."""
        if not html:
            return None

        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else None

    def _is_cdn_ip(self, ip: str) -> bool:
        """Check if IP belongs to known CDN (IPv4 or IPv6)."""
        # Check IPv6
        if ":" in ip:
            return self._is_cdn_ipv6(ip)
        # Check IPv4
        for prefix in ALL_CDN_RANGES:
            if ip.startswith(prefix):
                return True
        return False

    def _is_cdn_ipv6(self, ip: str) -> bool:
        """Check if IPv6 belongs to known CDN."""
        ip_lower = ip.lower()
        # Cloudflare IPv6 prefixes
        cf_ipv6_prefixes = [
            "2606:4700:", "2803:f800:", "2405:b500:", "2405:8100:",
            "2a06:98c0:", "2a06:98c1:",  # Cloudflare
        ]
        # Fastly IPv6
        fastly_ipv6_prefixes = ["2a04:4e40:", "2a04:4e41:"]
        # Akamai IPv6
        akamai_ipv6_prefixes = ["2600:1400:", "2600:1401:"]

        all_prefixes = cf_ipv6_prefixes + fastly_ipv6_prefixes + akamai_ipv6_prefixes
        for prefix in all_prefixes:
            if ip_lower.startswith(prefix.lower()):
                return True
        return False

    def _identify_cdn(self, ip: str) -> Optional[str]:
        """Identify CDN provider from IP."""
        for prefix in CLOUDFLARE_RANGES:
            if ip.startswith(prefix):
                return "Cloudflare"
        for prefix in AKAMAI_RANGES:
            if ip.startswith(prefix):
                return "Akamai"
        for prefix in FASTLY_RANGES:
            if ip.startswith(prefix):
                return "Fastly"
        for prefix in CLOUDFRONT_RANGES:
            if ip.startswith(prefix):
                return "CloudFront"
        for prefix in INCAPSULA_RANGES:
            if ip.startswith(prefix):
                return "Incapsula"
        for prefix in SUCURI_RANGES:
            if ip.startswith(prefix):
                return "Sucuri"
        return None


async def discover_origin_ips(
    domain: str,
    shodan_api_key: str = None,
    securitytrails_api_key: str = None,
    subdomains: list[str] = None,
    resolved_ips: dict[str, str] = None,
    target_url: str = None,
    use_checkhost: bool = True,
) -> OriginDiscoveryResult:
    """
    Convenience function for origin IP discovery.

    Args:
        domain: Target domain
        shodan_api_key: Shodan API key
        securitytrails_api_key: SecurityTrails API key for historical DNS
        subdomains: Discovered subdomains
        resolved_ips: Subdomain to IP mappings
        target_url: URL for baseline comparison
        use_checkhost: Use check-host.net for CDN validation (free, no API key)

    Returns:
        OriginDiscoveryResult
    """
    discovery = OriginDiscovery(
        shodan_api_key=shodan_api_key,
        securitytrails_api_key=securitytrails_api_key,
        use_checkhost=use_checkhost,
    )
    return await discovery.discover(
        domain=domain,
        subdomains=subdomains,
        resolved_ips=resolved_ips,
        target_url=target_url,
    )
