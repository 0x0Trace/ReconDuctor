"""Intelligence gathering for AI-powered wordlist generation.

Collects data from multiple sources to provide context for intelligent
subdomain wordlist generation.

Security Notes:
    - All external API responses are validated before processing
    - String lengths are checked before regex operations (ReDoS prevention)
    - Memory usage is bounded with max result limits
    - Domain names are URL-encoded in API requests
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import quote

import httpx

from reconductor.core.logger import get_logger

logger = get_logger(__name__)

# Compiled regex patterns for performance
RE_DIGIT = re.compile(r'\d+')
RE_CAMEL_CASE = re.compile(r'[a-z][A-Z]')
RE_SEPARATOR = re.compile(r'[-.]')
RE_VALID_PREFIX = re.compile(r'^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$', re.IGNORECASE)

# Limits for security
MAX_SUBDOMAIN_LENGTH = 63
MAX_STRING_FOR_REGEX = 1000
MAX_SUBDOMAINS_IN_SET = 10000


@dataclass
class DomainIntelligence:
    """Aggregated intelligence about a target domain."""

    domain: str

    # Certificate Transparency data
    ct_subdomains: list[str] = field(default_factory=list)

    # Wayback Machine data
    wayback_urls: list[str] = field(default_factory=list)
    wayback_subdomains: list[str] = field(default_factory=list)

    # Pattern analysis
    detected_patterns: list[str] = field(default_factory=list)
    naming_conventions: dict[str, int] = field(default_factory=dict)
    common_prefixes: list[str] = field(default_factory=list)
    separators: list[str] = field(default_factory=list)

    # Technology hints
    technologies: list[str] = field(default_factory=list)

    # Company/industry info
    industry_hints: list[str] = field(default_factory=list)

    # Statistics
    source_stats: dict[str, int] = field(default_factory=dict)

    def to_prompt_context(self) -> str:
        """
        Convert intelligence to structured prompt context.

        Uses clear delimiters to prevent prompt injection.
        """
        sections = []

        sections.append(f"=== TARGET DOMAIN ===")
        sections.append(f"{self.domain}")

        if self.ct_subdomains:
            sections.append(f"\n=== HISTORICAL SUBDOMAINS (CT logs: {len(self.ct_subdomains)}) ===")
            # Sanitize subdomain names - only allow safe characters
            safe_subs = [s for s in self.ct_subdomains[:50] if self._is_safe_for_prompt(s)]
            sections.append(", ".join(safe_subs))

        if self.wayback_subdomains:
            sections.append(f"\n=== ARCHIVED SUBDOMAINS (Wayback: {len(self.wayback_subdomains)}) ===")
            safe_subs = [s for s in self.wayback_subdomains[:30] if self._is_safe_for_prompt(s)]
            sections.append(", ".join(safe_subs))

        if self.detected_patterns:
            sections.append(f"\n=== DETECTED PATTERNS ===")
            for pattern in self.detected_patterns[:10]:
                # Patterns are generated internally, but still sanitize
                safe_pattern = pattern[:200].replace("\n", " ")
                sections.append(f"  - {safe_pattern}")

        if self.common_prefixes:
            sections.append(f"\n=== COMMON PREFIXES ===")
            safe_prefixes = [p for p in self.common_prefixes[:20] if self._is_safe_for_prompt(p)]
            sections.append(", ".join(safe_prefixes))

        if self.separators:
            sections.append(f"\n=== SEPARATORS USED ===")
            sections.append(", ".join(self.separators[:5]))

        if self.technologies:
            sections.append(f"\n=== TECHNOLOGIES DETECTED ===")
            sections.append(", ".join(self.technologies[:15]))

        if self.industry_hints:
            sections.append(f"\n=== INDUSTRY HINTS ===")
            sections.append(", ".join(self.industry_hints[:10]))

        sections.append("\n=== END INTELLIGENCE ===")

        return "\n".join(sections)

    @staticmethod
    def _is_safe_for_prompt(s: str) -> bool:
        """Check if string is safe to include in prompt (no injection risk)."""
        if not s or len(s) > 100:
            return False
        # Only allow alphanumeric, hyphens, dots
        return bool(re.match(r'^[a-zA-Z0-9.-]+$', s))


class IntelligenceGatherer:
    """
    Gathers intelligence from multiple sources for subdomain enumeration.

    Sources:
    - Certificate Transparency logs (crt.sh)
    - Wayback Machine (web.archive.org)
    - Pattern analysis from existing subdomains
    - Technology detection hints

    Security:
    - API responses are validated for type and structure
    - String lengths are bounded before regex operations
    - Memory growth is limited with max result caps
    """

    # User agent for API requests
    USER_AGENT = "ReconDuctor/2.0 (Security Research Tool)"

    def __init__(
        self,
        timeout: int = 60,  # Increased from 30 for slower connections
        max_ct_results: int = 500,
        max_wayback_results: int = 200,
    ):
        """
        Initialize intelligence gatherer.

        Args:
            timeout: HTTP request timeout in seconds
            max_ct_results: Maximum CT log results to fetch
            max_wayback_results: Maximum Wayback results to fetch

        Raises:
            ValueError: If parameters are out of valid range
        """
        if timeout < 1 or timeout > 120:
            raise ValueError("timeout must be between 1 and 120 seconds")
        if max_ct_results < 1 or max_ct_results > 5000:
            raise ValueError("max_ct_results must be between 1 and 5000")
        if max_wayback_results < 1 or max_wayback_results > 1000:
            raise ValueError("max_wayback_results must be between 1 and 1000")

        self.timeout = httpx.Timeout(connect=10.0, read=float(timeout), write=10.0, pool=5.0)
        self.max_ct_results = max_ct_results
        self.max_wayback_results = max_wayback_results

    async def gather(
        self,
        domain: str,
        existing_subdomains: Optional[list[str]] = None,
    ) -> DomainIntelligence:
        """
        Gather intelligence from all sources.

        Args:
            domain: Target domain (must be valid domain name)
            existing_subdomains: Already discovered subdomains

        Returns:
            Aggregated domain intelligence
        """
        # Validate domain
        if not domain or not self._is_valid_domain(domain):
            logger.error(f"Invalid domain: {domain}")
            return DomainIntelligence(domain=domain or "invalid")

        intel = DomainIntelligence(domain=domain)
        existing = existing_subdomains or []

        # Run all gathering tasks concurrently
        tasks = [
            self._gather_ct_logs(domain),
            self._gather_wayback(domain),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process CT logs
        if isinstance(results[0], list):
            intel.ct_subdomains = results[0]
            intel.source_stats["ct_logs"] = len(intel.ct_subdomains)
            logger.info(f"CT logs: found {len(intel.ct_subdomains)} subdomains")
        elif isinstance(results[0], Exception):
            intel.source_stats["ct_logs"] = 0
            logger.warning(f"CT logs failed: {type(results[0]).__name__}: {results[0]}")

        # Process Wayback
        if isinstance(results[1], tuple) and len(results[1]) == 2:
            intel.wayback_urls, intel.wayback_subdomains = results[1]
            intel.source_stats["wayback"] = len(intel.wayback_subdomains)
            logger.info(f"Wayback: found {len(intel.wayback_subdomains)} subdomains")
        elif isinstance(results[1], Exception):
            intel.source_stats["wayback"] = 0
            logger.warning(f"Wayback failed: {type(results[1]).__name__}: {results[1]}")

        # Combine all known subdomains for pattern analysis (with limit)
        all_subdomains = list(set(
            existing[:MAX_SUBDOMAINS_IN_SET] +
            intel.ct_subdomains[:MAX_SUBDOMAINS_IN_SET] +
            intel.wayback_subdomains[:MAX_SUBDOMAINS_IN_SET]
        ))[:MAX_SUBDOMAINS_IN_SET]

        # Analyze patterns
        if all_subdomains:
            intel.detected_patterns = self._detect_patterns(all_subdomains)
            intel.naming_conventions = self._analyze_naming(all_subdomains)
            intel.common_prefixes = self._extract_prefixes(all_subdomains)
            intel.separators = self._detect_separators(all_subdomains)

        # Detect technologies from subdomain names
        intel.technologies = self._detect_technologies(all_subdomains)

        # Infer industry hints
        intel.industry_hints = self._infer_industry(domain, all_subdomains)

        intel.source_stats["total_unique"] = len(all_subdomains)

        logger.info(
            f"Intelligence gathered for {domain}",
            total_subdomains=len(all_subdomains),
            patterns=len(intel.detected_patterns),
            technologies=len(intel.technologies),
        )

        return intel

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain name format."""
        if not domain or len(domain) > 253:
            return False
        # Basic domain validation
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))

    async def _gather_ct_logs(self, domain: str) -> list[str]:
        """Fetch subdomains from Certificate Transparency logs via crt.sh."""
        subdomains: set[str] = set()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # URL-encode the domain to prevent injection
                encoded_domain = quote(domain, safe='')
                response = await client.get(
                    f"https://crt.sh/?q=%.{encoded_domain}&output=json",
                    headers={"User-Agent": self.USER_AGENT},
                )

                if response.status_code != 200:
                    logger.debug(f"crt.sh returned status {response.status_code}")
                    return []

                # Validate response is JSON array
                try:
                    data = response.json()
                except Exception:
                    logger.debug("crt.sh returned invalid JSON")
                    return []

                if not isinstance(data, list):
                    logger.debug("crt.sh returned non-list JSON")
                    return []

                for entry in data[:self.max_ct_results]:
                    # Validate entry structure
                    if not isinstance(entry, dict):
                        continue

                    name = entry.get("name_value")
                    if not isinstance(name, str):
                        continue

                    # Limit string length before processing (ReDoS prevention)
                    if len(name) > MAX_STRING_FOR_REGEX:
                        continue

                    # Handle wildcard and multi-line entries (limit splits)
                    for line in name.split("\n")[:100]:
                        line = line.strip().lower()
                        if len(line) > MAX_SUBDOMAIN_LENGTH + len(domain) + 10:
                            continue

                        if line.startswith("*."):
                            line = line[2:]

                        if line.endswith(f".{domain}") or line == domain:
                            if line != domain:
                                prefix = line.replace(f".{domain}", "")
                                if self._is_valid_subdomain(prefix):
                                    subdomains.add(prefix)
                                    # Bound set size
                                    if len(subdomains) >= self.max_ct_results:
                                        break

                    if len(subdomains) >= self.max_ct_results:
                        break

        except httpx.TimeoutException:
            logger.debug("crt.sh request timed out")
            return list(subdomains)
        except Exception as e:
            logger.debug(f"CT log fetch error: {type(e).__name__}: {e}")
            return list(subdomains)

        return sorted(subdomains)[:self.max_ct_results]

    async def _gather_wayback(self, domain: str) -> tuple[list[str], list[str]]:
        """Fetch URLs and subdomains from Wayback Machine."""
        urls: list[str] = []
        subdomains: set[str] = set()

        # Pre-compile regex for this domain (with length limit in pattern)
        domain_escaped = re.escape(domain)
        url_pattern = re.compile(
            rf"https?://([a-zA-Z0-9.-]{{1,100}}\.{domain_escaped})",
            re.IGNORECASE
        )

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    "https://web.archive.org/cdx/search/cdx",
                    params={
                        "url": f"*.{domain}/*",
                        "output": "json",
                        "fl": "original",
                        "collapse": "urlkey",
                        "limit": self.max_wayback_results,
                    },
                    headers={"User-Agent": self.USER_AGENT},
                )

                if response.status_code != 200:
                    logger.debug(f"Wayback returned status {response.status_code}")
                    return urls, []

                # Validate response
                try:
                    data = response.json()
                except Exception:
                    logger.debug("Wayback returned invalid JSON")
                    return urls, []

                if not isinstance(data, list) or len(data) < 2:
                    return urls, []

                # Skip header row
                for row in data[1:self.max_wayback_results + 1]:
                    if not isinstance(row, list) or not row:
                        continue

                    url = row[0]
                    if not isinstance(url, str):
                        continue

                    # Length check before regex (ReDoS prevention)
                    if len(url) > MAX_STRING_FOR_REGEX:
                        continue

                    urls.append(url[:500])  # Truncate stored URLs

                    # Extract subdomain from URL
                    match = url_pattern.search(url)
                    if match:
                        full_host = match.group(1).lower()
                        prefix = full_host.replace(f".{domain}", "")
                        if prefix and self._is_valid_subdomain(prefix):
                            subdomains.add(prefix)
                            if len(subdomains) >= self.max_wayback_results:
                                break

        except httpx.TimeoutException:
            logger.debug("Wayback request timed out")
            return urls, list(subdomains)
        except Exception as e:
            logger.debug(f"Wayback fetch error: {type(e).__name__}: {e}")
            return urls, list(subdomains)

        return urls, sorted(subdomains)

    def _detect_patterns(self, subdomains: list[str]) -> list[str]:
        """Detect naming patterns in subdomains."""
        patterns = []

        # Environment patterns
        env_keywords = {"dev", "staging", "prod", "test", "uat", "qa", "beta", "alpha"}
        env_found = sum(1 for s in subdomains if any(e in s.lower() for e in env_keywords))
        if env_found:
            patterns.append(f"Environment-based naming ({env_found} found): dev, staging, prod, etc.")

        # Numbered patterns
        numbered = sum(1 for s in subdomains if len(s) <= MAX_SUBDOMAIN_LENGTH and RE_DIGIT.search(s))
        if numbered:
            patterns.append(f"Numbered instances ({numbered} found): app1, server01, node-2, etc.")

        # Regional patterns
        regions = {"us", "eu", "asia", "east", "west", "north", "south", "uk", "de", "fr", "jp"}
        regional = sum(1 for s in subdomains if any(r in s.lower().split("-") for r in regions))
        if regional:
            patterns.append(f"Regional naming ({regional} found): us-east, eu-west, etc.")

        # Service patterns
        services = {"api", "auth", "mail", "smtp", "ftp", "vpn", "cdn", "static", "assets"}
        service_found = sum(1 for s in subdomains if any(svc in s.lower() for svc in services))
        if service_found:
            patterns.append(f"Service-based naming ({service_found} found): api, auth, mail, etc.")

        # Internal patterns
        internal = {"internal", "intranet", "corp", "private", "admin"}
        internal_found = sum(1 for s in subdomains if any(i in s.lower() for i in internal))
        if internal_found:
            patterns.append(f"Internal resources ({internal_found} found): internal, corp, admin, etc.")

        return patterns

    def _analyze_naming(self, subdomains: list[str]) -> dict[str, int]:
        """Analyze naming conventions."""
        conventions = {
            "hyphen_separated": 0,
            "dot_separated": 0,
            "camelCase": 0,
            "numbered": 0,
            "abbreviated": 0,
        }

        for sub in subdomains:
            if len(sub) > MAX_SUBDOMAIN_LENGTH:
                continue
            if "-" in sub:
                conventions["hyphen_separated"] += 1
            if "." in sub:
                conventions["dot_separated"] += 1
            if RE_CAMEL_CASE.search(sub):
                conventions["camelCase"] += 1
            if RE_DIGIT.search(sub):
                conventions["numbered"] += 1
            if len(sub) <= 4 and sub.isalpha():
                conventions["abbreviated"] += 1

        return {k: v for k, v in conventions.items() if v > 0}

    def _extract_prefixes(self, subdomains: list[str]) -> list[str]:
        """Extract common prefixes from subdomains."""
        prefix_counts: dict[str, int] = {}

        for sub in subdomains:
            if len(sub) > MAX_SUBDOMAIN_LENGTH:
                continue
            parts = RE_SEPARATOR.split(sub)
            if parts:
                prefix = parts[0].lower()
                if 2 <= len(prefix) <= 20:
                    prefix_counts[prefix] = prefix_counts.get(prefix, 0) + 1

        sorted_prefixes = sorted(
            prefix_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )

        return [p[0] for p in sorted_prefixes[:30]]

    def _detect_separators(self, subdomains: list[str]) -> list[str]:
        """Detect separators used in subdomain names."""
        separators: set[str] = set()

        for sub in subdomains[:1000]:  # Limit iteration
            if "-" in sub:
                separators.add("-")
            if "." in sub:
                separators.add(".")

        return list(separators) or ["-"]

    def _detect_technologies(self, subdomains: list[str]) -> list[str]:
        """Detect technologies from subdomain naming."""
        tech_keywords = {
            "kubernetes": ["k8s", "kube", "kubernetes"],
            "docker": ["docker", "container"],
            "aws": ["aws", "s3", "ec2", "lambda", "cloudfront"],
            "azure": ["azure", "blob", "cosmos"],
            "gcp": ["gcp", "gke", "cloud"],
            "jenkins": ["jenkins", "ci", "build"],
            "gitlab": ["gitlab", "git"],
            "grafana": ["grafana", "metrics", "monitor"],
            "elasticsearch": ["elastic", "kibana", "logstash"],
            "redis": ["redis", "cache"],
            "mongodb": ["mongo", "mongodb"],
            "postgresql": ["postgres", "pg", "psql"],
            "mysql": ["mysql", "mariadb"],
            "kafka": ["kafka", "zookeeper"],
            "nginx": ["nginx", "proxy"],
            "wordpress": ["wp", "wordpress", "blog"],
            "jira": ["jira", "confluence", "atlassian"],
        }

        detected: set[str] = set()
        # Limit total text size
        sub_text = " ".join(s[:50] for s in subdomains[:500]).lower()

        for tech, keywords in tech_keywords.items():
            if any(kw in sub_text for kw in keywords):
                detected.add(tech)

        return sorted(detected)

    def _infer_industry(self, domain: str, subdomains: list[str]) -> list[str]:
        """Infer industry hints from domain and subdomains."""
        hints: list[str] = []
        # Limit combined text size
        combined = f"{domain} {' '.join(s[:30] for s in subdomains[:200])}".lower()

        industry_keywords = {
            "e-commerce": ["shop", "store", "cart", "checkout", "payment", "order"],
            "fintech": ["bank", "pay", "wallet", "finance", "trade", "invest"],
            "healthcare": ["health", "medical", "patient", "doctor", "clinic"],
            "education": ["edu", "learn", "course", "student", "teacher", "school"],
            "gaming": ["game", "play", "server", "match", "lobby"],
            "media": ["video", "stream", "media", "content", "cdn"],
            "saas": ["app", "api", "dashboard", "portal", "admin", "console"],
            "social": ["social", "profile", "feed", "message", "chat"],
        }

        for industry, keywords in industry_keywords.items():
            if any(kw in combined for kw in keywords):
                hints.append(industry)

        return hints

    def _is_valid_subdomain(self, prefix: str) -> bool:
        """Check if a subdomain prefix is valid DNS name component."""
        if not prefix or len(prefix) > MAX_SUBDOMAIN_LENGTH:
            return False

        # Must start and end with alphanumeric
        if not prefix[0].isalnum() or not prefix[-1].isalnum():
            return False

        # Use pre-compiled regex
        return bool(RE_VALID_PREFIX.match(prefix))
