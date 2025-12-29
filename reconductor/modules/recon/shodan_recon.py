"""
Shodan reconnaissance module for subdomain enumeration and origin IP discovery.

Implements techniques from:
- SSL Certificate CN/O searches for subdomain discovery
- Favicon hash lookups for origin IP detection (Cloudflare bypass)
- HTTP title/header correlation
- Historical data analysis

References:
- https://blog.christophetd.fr/bypassing-cloudflare-using-internet-wide-scan-data/
- https://blog.detectify.com/industry-insights/bypassing-cloudflare-waf-with-the-origin-server-ip-address/
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from reconductor.core.config import Settings
from reconductor.core.logger import get_logger
from reconductor.models.subdomain import Subdomain, SubdomainSource

logger = get_logger(__name__)

# Known CDN/WAF IP ranges (partial list for detection)
CLOUDFLARE_RANGES = [
    "103.21.244.", "103.22.200.", "103.31.4.", "104.16.", "104.17.",
    "104.18.", "104.19.", "104.20.", "104.21.", "104.22.", "104.23.",
    "104.24.", "104.25.", "104.26.", "104.27.", "108.162.", "131.0.72.",
    "141.101.", "162.158.", "172.64.", "172.65.", "172.66.", "172.67.",
    "173.245.", "188.114.", "190.93.", "197.234.", "198.41.",
]

AKAMAI_RANGES = ["23.32.", "23.33.", "23.34.", "23.35.", "23.36."]
FASTLY_RANGES = ["151.101.", "199.232."]


@dataclass
class OriginIPResult:
    """Result of origin IP discovery."""
    ip: str
    hostname: Optional[str] = None
    port: int = 443
    source: str = "shodan"
    confidence: str = "medium"  # low, medium, high
    evidence: str = ""
    is_cdn: bool = False
    cdn_provider: Optional[str] = None


@dataclass
class ShodanSearchResult:
    """Result from Shodan search."""
    ip: str
    port: int
    hostnames: list[str] = field(default_factory=list)
    org: Optional[str] = None
    asn: Optional[str] = None
    ssl_cn: Optional[str] = None
    ssl_org: Optional[str] = None
    http_title: Optional[str] = None
    http_server: Optional[str] = None
    favicon_hash: Optional[int] = None
    data: dict = field(default_factory=dict)


class ShodanClient:
    """
    Async Shodan API client.

    Supports both API and InternetDB (free, no key required) for basic lookups.
    """

    API_BASE = "https://api.shodan.io"
    INTERNETDB_BASE = "https://internetdb.shodan.io"

    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        """
        Initialize Shodan client.

        Args:
            api_key: Shodan API key (optional for InternetDB)
            timeout: Request timeout in seconds
        """
        self.api_key = api_key
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self):
        self._client = httpx.AsyncClient(timeout=self.timeout)
        return self

    async def __aexit__(self, *args):
        if self._client:
            await self._client.aclose()

    @property
    def has_api_key(self) -> bool:
        return bool(self.api_key)

    async def search(
        self,
        query: str,
        page: int = 1,
        limit: int = 100,
    ) -> list[ShodanSearchResult]:
        """
        Search Shodan with a query.

        Args:
            query: Shodan search query
            page: Page number
            limit: Max results to return

        Returns:
            List of search results
        """
        if not self.api_key:
            logger.warning("Shodan API key not configured, skipping search")
            return []

        try:
            url = f"{self.API_BASE}/shodan/host/search"
            params = {
                "key": self.api_key,
                "query": query,
                "page": page,
            }

            # Use existing client or create new one
            if self._client:
                response = await self._client.get(url, params=params)
            else:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(url, params=params)

            if response.status_code == 401:
                logger.error("Invalid Shodan API key")
                return []
            elif response.status_code == 402:
                logger.warning("Shodan query credits exhausted")
                return []
            elif response.status_code != 200:
                logger.warning(f"Shodan search failed: {response.status_code}")
                return []

            data = response.json()
            results = []

            for match in data.get("matches", [])[:limit]:
                result = ShodanSearchResult(
                    ip=match.get("ip_str", ""),
                    port=match.get("port", 0),
                    hostnames=match.get("hostnames", []),
                    org=match.get("org"),
                    asn=match.get("asn"),
                    data=match,
                )

                # Extract SSL info
                ssl = match.get("ssl", {})
                if ssl:
                    cert = ssl.get("cert", {})
                    subject = cert.get("subject", {})
                    result.ssl_cn = subject.get("CN")
                    result.ssl_org = subject.get("O")

                # Extract HTTP info
                http = match.get("http", {})
                if http:
                    result.http_title = http.get("title")
                    result.http_server = http.get("server")
                    result.favicon_hash = http.get("favicon", {}).get("hash")

                results.append(result)

            logger.info(f"Shodan search returned {len(results)} results", query=query)
            return results

        except Exception as e:
            logger.error(f"Shodan search error: {e}")
            return []

    async def host_info(self, ip: str) -> Optional[dict]:
        """
        Get information about a specific IP.

        Args:
            ip: IP address to lookup

        Returns:
            Host information dict or None
        """
        if not self.api_key:
            # Fall back to InternetDB (free)
            return await self._internetdb_lookup(ip)

        try:
            url = f"{self.API_BASE}/shodan/host/{ip}"
            params = {"key": self.api_key}

            # Use existing client or create new one
            if self._client:
                response = await self._client.get(url, params=params)
            else:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(url, params=params)

            if response.status_code == 200:
                return response.json()

        except Exception as e:
            logger.error(f"Shodan host lookup error: {e}")

        return None

    async def _internetdb_lookup(self, ip: str) -> Optional[dict]:
        """
        Free IP lookup via InternetDB (no API key required).

        Args:
            ip: IP address

        Returns:
            Basic host info
        """
        try:
            url = f"{self.INTERNETDB_BASE}/{ip}"

            # Use existing client or create new one
            if self._client:
                response = await self._client.get(url)
            else:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(url)

            if response.status_code == 200:
                return response.json()

        except Exception as e:
            logger.debug(f"InternetDB lookup failed: {e}")

        return None

    async def search_ssl_cn(self, domain: str) -> list[ShodanSearchResult]:
        """Search by SSL certificate Common Name."""
        query = f'ssl.cert.subject.CN:"{domain}"'
        return await self.search(query)

    async def search_ssl_org(self, org: str) -> list[ShodanSearchResult]:
        """Search by SSL certificate Organization."""
        query = f'ssl.cert.subject.O:"{org}"'
        return await self.search(query)

    async def search_favicon_hash(self, favicon_hash: int) -> list[ShodanSearchResult]:
        """Search by favicon hash (MurmurHash3)."""
        query = f"http.favicon.hash:{favicon_hash}"
        return await self.search(query)

    async def search_http_title(self, title: str) -> list[ShodanSearchResult]:
        """Search by HTTP title."""
        query = f'http.title:"{title}"'
        return await self.search(query)


class FaviconHasher:
    """
    Calculate favicon hashes for Shodan lookups.

    Shodan uses MurmurHash3 of base64-encoded favicon content.
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    async def get_favicon_hash(self, url: str) -> Optional[int]:
        """
        Fetch favicon and calculate its Shodan-compatible hash.

        Args:
            url: Target URL (will try /favicon.ico)

        Returns:
            MurmurHash3 of favicon or None
        """
        try:
            import mmh3  # MurmurHash3 library
        except ImportError:
            logger.warning("mmh3 not installed, favicon hashing disabled")
            return None

        # Parse URL and construct favicon URL
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        favicon_urls = [
            f"{base_url}/favicon.ico",
            f"{base_url}/favicon.png",
        ]

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,  # Some targets have invalid certs
        ) as client:
            for favicon_url in favicon_urls:
                try:
                    response = await client.get(favicon_url)

                    if response.status_code == 200 and len(response.content) > 0:
                        # Shodan hashes base64-encoded content
                        favicon_b64 = base64.b64encode(response.content)
                        favicon_hash = mmh3.hash(favicon_b64)

                        logger.debug(f"Favicon hash: {favicon_hash}", url=favicon_url)
                        return favicon_hash

                except Exception:
                    continue

        return None

    async def get_favicon_hashes_batch(
        self,
        urls: list[str],
        concurrency: int = 10,
    ) -> dict[str, int]:
        """
        Get favicon hashes for multiple URLs.

        Args:
            urls: List of URLs
            concurrency: Max concurrent requests

        Returns:
            Dict mapping URL to hash
        """
        semaphore = asyncio.Semaphore(concurrency)
        results = {}

        async def fetch_one(url: str):
            async with semaphore:
                hash_val = await self.get_favicon_hash(url)
                if hash_val:
                    results[url] = hash_val

        await asyncio.gather(*[fetch_one(url) for url in urls])
        return results


class ShodanEnumerator:
    """
    Subdomain enumeration using Shodan SSL certificate data.

    Searches for:
    - SSL certificates with matching CN (Common Name)
    - SSL certificates with matching O (Organization)
    - Reverse DNS hostnames
    """

    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        """
        Initialize Shodan enumerator.

        Args:
            api_key: Shodan API key
            timeout: Request timeout
        """
        self.api_key = api_key or self._load_api_key()
        self.timeout = timeout

    def _load_api_key(self) -> Optional[str]:
        """Try to load API key from environment or config."""
        import os

        # Check environment
        key = os.environ.get("SHODAN_API_KEY")
        if key:
            return key

        # Check common config locations
        config_paths = [
            Path.home() / ".shodan" / "api_key",
            Path.home() / ".config" / "shodan" / "api_key",
        ]

        for path in config_paths:
            if path.exists():
                return path.read_text().strip()

        return None

    async def enumerate(self, domain: str) -> list[Subdomain]:
        """
        Enumerate subdomains via Shodan SSL certificate search.

        Args:
            domain: Target domain

        Returns:
            List of discovered subdomains
        """
        if not self.api_key:
            logger.warning("Shodan API key not configured, skipping enumeration")
            return []

        subdomains = []
        seen = set()

        async with ShodanClient(self.api_key, self.timeout) as client:
            # Search by SSL CN
            results = await client.search_ssl_cn(domain)

            for result in results:
                # Extract from SSL CN
                if result.ssl_cn:
                    cn = result.ssl_cn.lower()
                    # Skip wildcard entries
                    if cn.startswith("*."):
                        cn = cn[2:]
                    if cn.endswith(f".{domain}") or cn == domain:
                        if cn not in seen:
                            seen.add(cn)
                            sub = Subdomain.from_name(cn, source=SubdomainSource.SHODAN)
                            if result.ip:
                                sub.a_records.append(result.ip)
                            subdomains.append(sub)

                # Extract from hostnames
                for hostname in result.hostnames:
                    hostname = hostname.lower()
                    if hostname.endswith(f".{domain}") or hostname == domain:
                        if hostname not in seen:
                            seen.add(hostname)
                            sub = Subdomain.from_name(hostname, source=SubdomainSource.SHODAN)
                            if result.ip:
                                sub.a_records.append(result.ip)
                            subdomains.append(sub)

        logger.info(f"Shodan found {len(subdomains)} subdomains", domain=domain)
        return subdomains


class ShodanOriginFinder:
    """
    Find origin IPs behind CDN/WAF using Shodan.

    Techniques:
    1. SSL Certificate matching - Find servers with same SSL cert
    2. Favicon hash matching - Find servers with same favicon
    3. HTTP title/content matching - Find servers with same content
    4. Historical DNS records - Check for pre-CDN records
    """

    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        """
        Initialize origin finder.

        Args:
            api_key: Shodan API key (auto-detects from env or ~/.shodan/api_key)
            timeout: Request timeout
        """
        self.api_key = api_key or self._load_api_key()
        self.timeout = timeout
        self.favicon_hasher = FaviconHasher(timeout)

    def _load_api_key(self) -> Optional[str]:
        """Try to load API key from environment or native Shodan config."""
        import os

        # Check environment
        key = os.environ.get("SHODAN_API_KEY")
        if key:
            return key

        # Check native Shodan config (~/.shodan/api_key from `shodan init`)
        config_paths = [
            Path.home() / ".shodan" / "api_key",
            Path.home() / ".config" / "shodan" / "api_key",
        ]

        for path in config_paths:
            if path.exists():
                return path.read_text().strip()

        return None

    async def find_origin_ips(
        self,
        domain: str,
        target_url: Optional[str] = None,
        ssl_org: Optional[str] = None,
    ) -> list[OriginIPResult]:
        """
        Attempt to find origin IPs behind CDN/WAF.

        Args:
            domain: Target domain
            target_url: URL to fetch favicon from (optional)
            ssl_org: SSL certificate organization to search (optional)

        Returns:
            List of potential origin IPs
        """
        if not self.api_key:
            logger.warning("Shodan API key required for origin discovery")
            return []

        origins = []

        async with ShodanClient(self.api_key, self.timeout) as client:
            # Method 1: SSL Certificate CN match
            logger.info("Searching by SSL certificate CN...")
            ssl_results = await client.search_ssl_cn(domain)

            for result in ssl_results:
                if not self._is_cdn_ip(result.ip):
                    origins.append(OriginIPResult(
                        ip=result.ip,
                        hostname=result.ssl_cn,
                        port=result.port,
                        source="shodan_ssl_cn",
                        confidence="high",
                        evidence=f"SSL CN matches: {result.ssl_cn}",
                    ))
                else:
                    # Track CDN IPs for reference
                    cdn = self._identify_cdn(result.ip)
                    origins.append(OriginIPResult(
                        ip=result.ip,
                        hostname=result.ssl_cn,
                        port=result.port,
                        source="shodan_ssl_cn",
                        confidence="low",
                        evidence=f"CDN IP detected",
                        is_cdn=True,
                        cdn_provider=cdn,
                    ))

            # Method 2: SSL Organization match (if provided)
            if ssl_org:
                logger.info(f"Searching by SSL organization: {ssl_org}")
                org_results = await client.search_ssl_org(ssl_org)

                for result in org_results:
                    if not self._is_cdn_ip(result.ip):
                        # Check if this IP has hostnames related to our domain
                        related = any(
                            domain in h.lower()
                            for h in result.hostnames
                        )

                        origins.append(OriginIPResult(
                            ip=result.ip,
                            hostname=result.hostnames[0] if result.hostnames else None,
                            port=result.port,
                            source="shodan_ssl_org",
                            confidence="medium" if related else "low",
                            evidence=f"SSL Org matches: {ssl_org}",
                        ))

            # Method 3: Favicon hash match
            if target_url:
                logger.info("Calculating favicon hash...")
                favicon_hash = await self.favicon_hasher.get_favicon_hash(target_url)

                if favicon_hash:
                    logger.info(f"Searching by favicon hash: {favicon_hash}")
                    favicon_results = await client.search_favicon_hash(favicon_hash)

                    for result in favicon_results:
                        if not self._is_cdn_ip(result.ip):
                            origins.append(OriginIPResult(
                                ip=result.ip,
                                hostname=result.hostnames[0] if result.hostnames else None,
                                port=result.port,
                                source="shodan_favicon",
                                confidence="high",
                                evidence=f"Favicon hash matches: {favicon_hash}",
                            ))

        # Deduplicate by IP
        seen_ips = set()
        unique_origins = []
        for origin in origins:
            if origin.ip not in seen_ips:
                seen_ips.add(origin.ip)
                unique_origins.append(origin)

        # Sort by confidence
        confidence_order = {"high": 0, "medium": 1, "low": 2}
        unique_origins.sort(key=lambda x: confidence_order.get(x.confidence, 3))

        logger.info(
            f"Origin discovery found {len(unique_origins)} potential IPs",
            domain=domain,
            non_cdn=sum(1 for o in unique_origins if not o.is_cdn),
        )

        return unique_origins

    def _is_cdn_ip(self, ip: str) -> bool:
        """Check if IP belongs to known CDN/WAF provider."""
        for prefix in CLOUDFLARE_RANGES + AKAMAI_RANGES + FASTLY_RANGES:
            if ip.startswith(prefix):
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
        return None


class SecurityTrailsClient:
    """
    SecurityTrails API client for historical DNS lookups.

    Can reveal origin IPs from before CDN was implemented.
    """

    API_BASE = "https://api.securitytrails.com/v1"

    def __init__(self, api_key: Optional[str] = None, timeout: int = 30):
        self.api_key = api_key or self._load_api_key()
        self.timeout = timeout

    def _load_api_key(self) -> Optional[str]:
        import os
        return os.environ.get("SECURITYTRAILS_API_KEY")

    async def get_dns_history(self, domain: str, record_type: str = "a") -> list[dict]:
        """
        Get historical DNS records.

        Args:
            domain: Target domain
            record_type: DNS record type (a, aaaa, mx, ns, etc.)

        Returns:
            List of historical records
        """
        if not self.api_key:
            logger.debug("SecurityTrails API key not configured")
            return []

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                url = f"{self.API_BASE}/history/{domain}/dns/{record_type}"
                headers = {"APIKEY": self.api_key}

                response = await client.get(url, headers=headers)

                if response.status_code == 200:
                    data = response.json()
                    return data.get("records", [])

        except Exception as e:
            logger.error(f"SecurityTrails lookup failed: {e}")

        return []


# Import Path for api key loading
from pathlib import Path
