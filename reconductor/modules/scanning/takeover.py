"""Subdomain takeover detection with dynamic fingerprints."""

from __future__ import annotations

import json
import re
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from reconductor.core.logger import get_logger
from reconductor.models.finding import Finding, Severity, TakeoverFinding
from reconductor.models.subdomain import Subdomain
from reconductor.utils.executor import get_executor

logger = get_logger(__name__)


@dataclass
class TakeoverService:
    """Fingerprint for a vulnerable service."""
    name: str
    cname_patterns: list[re.Pattern] = field(default_factory=list)
    response_patterns: list[re.Pattern] = field(default_factory=list)
    status: str = "unknown"
    vulnerable: bool = False
    documentation: str = ""


@dataclass
class CNAMEHop:
    """A single hop in a CNAME chain."""
    source: str
    target: str
    takeover_candidate: bool = False
    service: Optional[str] = None


@dataclass
class CNAMEChain:
    """Complete CNAME resolution chain."""
    original: str
    hops: list[CNAMEHop] = field(default_factory=list)
    final_target: str = ""
    is_potential_takeover: bool = False


class TakeoverFingerprints:
    """
    Dynamic fingerprint management from can-i-take-over-xyz.

    Fetches and caches fingerprints for takeover-vulnerable services.
    """

    FINGERPRINTS_URL = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json"
    CACHE_TTL = 86400  # 24 hours

    def __init__(
        self,
        cache_path: Optional[Path] = None,
    ):
        """
        Initialize fingerprints manager.

        Args:
            cache_path: Path to cache fingerprints
        """
        self.cache_path = cache_path or Path(".cache/takeover_fingerprints.json")
        self.fingerprints: dict[str, TakeoverService] = {}
        self._last_update: Optional[datetime] = None

    def _is_cache_valid(self) -> bool:
        """Check if cached fingerprints are still valid."""
        if not self.cache_path.exists():
            return False

        try:
            mtime = datetime.fromtimestamp(self.cache_path.stat().st_mtime)
            return (datetime.now() - mtime) < timedelta(seconds=self.CACHE_TTL)
        except Exception:
            return False

    def _load_cache(self) -> dict[str, TakeoverService]:
        """Load fingerprints from cache."""
        try:
            data = json.loads(self.cache_path.read_text())
            return self._parse_fingerprints(data)
        except Exception as e:
            logger.warning(f"Failed to load fingerprint cache: {e}")
            return {}

    def _save_cache(self, data: list[dict]) -> None:
        """Save fingerprints to cache."""
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.warning(f"Failed to save fingerprint cache: {e}")

    async def load_fingerprints(self) -> None:
        """Fetch or load cached fingerprints."""
        if self._is_cache_valid():
            self.fingerprints = self._load_cache()
            logger.info(f"Loaded {len(self.fingerprints)} fingerprints from cache")
            return

        import httpx

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(self.FINGERPRINTS_URL)
                if response.status_code == 200:
                    data = response.json()
                    self.fingerprints = self._parse_fingerprints(data)
                    self._save_cache(data)
                    self._last_update = datetime.now()
                    logger.info(f"Fetched {len(self.fingerprints)} takeover fingerprints")
        except Exception as e:
            logger.error(f"Failed to fetch fingerprints: {e}")
            # Fall back to cache even if expired
            if self.cache_path.exists():
                self.fingerprints = self._load_cache()

    def _parse_fingerprints(self, data: list[dict]) -> dict[str, TakeoverService]:
        """Parse fingerprints into usable format."""
        fingerprints = {}

        for entry in data:
            service = entry.get("service", "unknown")

            # Parse CNAME patterns
            cname_patterns = []
            for pattern in entry.get("cname", []):
                try:
                    # Escape dots and create regex
                    regex = pattern.replace(".", r"\.")
                    cname_patterns.append(re.compile(regex, re.IGNORECASE))
                except re.error:
                    continue

            # Parse response patterns
            response_patterns = []
            for pattern in entry.get("fingerprint", []):
                try:
                    response_patterns.append(re.compile(pattern, re.IGNORECASE))
                except re.error:
                    continue

            fingerprints[service] = TakeoverService(
                name=service,
                cname_patterns=cname_patterns,
                response_patterns=response_patterns,
                status=entry.get("status", "unknown"),
                vulnerable=entry.get("vulnerable", False),
                documentation=entry.get("documentation", ""),
            )

        return fingerprints

    def check_cname(self, cname: str) -> Optional[TakeoverService]:
        """
        Check if a CNAME matches any vulnerable service.

        Args:
            cname: CNAME target to check

        Returns:
            TakeoverService if match found
        """
        for service in self.fingerprints.values():
            for pattern in service.cname_patterns:
                if pattern.search(cname):
                    return service
        return None

    def check_response(self, body: str) -> Optional[TakeoverService]:
        """
        Check if response body matches any takeover fingerprint.

        Args:
            body: HTTP response body

        Returns:
            TakeoverService if match found
        """
        for service in self.fingerprints.values():
            if not service.vulnerable:
                continue
            for pattern in service.response_patterns:
                if pattern.search(body):
                    return service
        return None


class TakeoverDetector:
    """
    Subdomain takeover detection.

    Combines CNAME chain analysis with dynamic fingerprints
    to detect potential takeover vulnerabilities.
    """

    def __init__(
        self,
        fingerprints: Optional[TakeoverFingerprints] = None,
    ):
        """
        Initialize takeover detector.

        Args:
            fingerprints: Fingerprints manager
        """
        self.fingerprints = fingerprints or TakeoverFingerprints()

    async def initialize(self) -> None:
        """Initialize fingerprints (load from cache or fetch)."""
        await self.fingerprints.load_fingerprints()

    async def check_subdomain(
        self,
        subdomain: Subdomain,
    ) -> Optional[TakeoverFinding]:
        """
        Check a subdomain for takeover potential.

        Args:
            subdomain: Subdomain to check

        Returns:
            TakeoverFinding if vulnerable
        """
        # Check CNAME chain
        for cname in subdomain.cname_chain:
            service = self.fingerprints.check_cname(cname)
            if service and service.vulnerable:
                return TakeoverFinding(
                    title=f"Potential Subdomain Takeover ({service.name})",
                    target=subdomain.name,
                    subdomain=subdomain.name,
                    cname_chain=subdomain.cname_chain,
                    vulnerable_service=service.name,
                    takeover_documentation=service.documentation,
                    confidence=0.7,
                    severity=Severity.HIGH,
                    description=f"CNAME {cname} points to {service.name} which may be vulnerable to takeover",
                    evidence=f"CNAME chain: {' -> '.join([subdomain.name] + subdomain.cname_chain)}",
                )

        return None

    async def check_subdomains(
        self,
        subdomains: list[Subdomain],
    ) -> list[TakeoverFinding]:
        """
        Check multiple subdomains for takeover potential.

        Args:
            subdomains: List of subdomains to check

        Returns:
            List of TakeoverFinding objects
        """
        findings = []

        for subdomain in subdomains:
            finding = await self.check_subdomain(subdomain)
            if finding:
                findings.append(finding)

        if findings:
            logger.warning(
                f"Found {len(findings)} potential takeovers",
                subdomains=len(subdomains),
            )

        return findings

    async def check_with_http(
        self,
        url: str,
        body: str,
    ) -> Optional[TakeoverFinding]:
        """
        Check HTTP response for takeover indicators.

        Args:
            url: Target URL
            body: HTTP response body

        Returns:
            TakeoverFinding if vulnerable
        """
        service = self.fingerprints.check_response(body)
        if service:
            return TakeoverFinding(
                title=f"Subdomain Takeover Confirmed ({service.name})",
                target=url,
                subdomain=url.split("/")[2] if "/" in url else url,
                vulnerable_service=service.name,
                takeover_documentation=service.documentation,
                confidence=0.9,
                severity=Severity.HIGH,
                description=f"Response matches {service.name} takeover fingerprint",
                evidence=body[:500],
            )

        return None


# Built-in fingerprints as fallback
BUILTIN_FINGERPRINTS = [
    {
        "service": "AWS S3",
        "cname": [r"\.s3\.amazonaws\.com$", r"\.s3-website.*\.amazonaws\.com$"],
        "fingerprint": ["NoSuchBucket", "The specified bucket does not exist"],
        "vulnerable": True,
    },
    {
        "service": "GitHub Pages",
        "cname": [r"\.github\.io$"],
        "fingerprint": ["There isn't a GitHub Pages site here"],
        "vulnerable": True,
    },
    {
        "service": "Heroku",
        "cname": [r"\.herokuapp\.com$", r"\.herokudns\.com$"],
        "fingerprint": ["No such app", "herokucdn.com/error-pages"],
        "vulnerable": True,
    },
    {
        "service": "Azure",
        "cname": [r"\.azurewebsites\.net$", r"\.cloudapp\.azure\.com$"],
        "fingerprint": ["404 Web Site not found", "azure-dns.com"],
        "vulnerable": True,
    },
    {
        "service": "Netlify",
        "cname": [r"\.netlify\.app$", r"\.netlify\.com$"],
        "fingerprint": ["Not Found - Request ID"],
        "vulnerable": True,
    },
    {
        "service": "Vercel",
        "cname": [r"\.vercel\.app$", r"\.now\.sh$"],
        "fingerprint": ["The deployment could not be found"],
        "vulnerable": True,
    },
    {
        "service": "Shopify",
        "cname": [r"\.myshopify\.com$"],
        "fingerprint": ["Sorry, this shop is currently unavailable"],
        "vulnerable": True,
    },
    {
        "service": "Tumblr",
        "cname": [r"\.tumblr\.com$"],
        "fingerprint": ["There's nothing here", "Whatever you were looking for doesn't currently exist"],
        "vulnerable": True,
    },
    {
        "service": "WordPress.com",
        "cname": [r"\.wordpress\.com$"],
        "fingerprint": ["Do you want to register"],
        "vulnerable": True,
    },
    {
        "service": "Surge.sh",
        "cname": [r"\.surge\.sh$"],
        "fingerprint": ["project not found"],
        "vulnerable": True,
    },
]
