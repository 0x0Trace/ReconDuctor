"""GAU (GetAllUrls) wrapper for historical URL mining."""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs

from reconductor.core.logger import get_logger
from reconductor.utils.executor import ToolExecutor, get_executor
from reconductor.utils.tempfiles import secure_temp_file

logger = get_logger(__name__)


# Fast providers (when Wayback/CommonCrawl are slow or down)
FAST_PROVIDERS = ["otx", "urlscan"]
# All providers (when all services are working)
ALL_PROVIDERS = ["wayback", "commoncrawl", "otx", "urlscan"]

# Extensions to blacklist (static files, images, fonts, etc.)
DEFAULT_BLACKLIST = [
    # Images
    "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "bmp", "tiff",
    # Fonts
    "woff", "woff2", "ttf", "eot", "otf",
    # Static assets
    "css", "less", "scss",
    # Media
    "mp4", "mp3", "avi", "mov", "wmv", "flv", "webm", "wav", "ogg",
    # Documents (usually not interesting for web attacks)
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    # Archives
    "zip", "rar", "gz", "tar", "7z",
    # Other
    "map", "swf",
]

# Patterns that indicate potentially interesting URLs
INTERESTING_PATTERNS = {
    "param_urls": re.compile(r'\?[^=]+='),  # URLs with query params
    "api_endpoints": re.compile(r'/(api|v[0-9]+|graphql|rest|ws)/'),
    "auth_endpoints": re.compile(r'/(auth|login|logout|signin|signout|register|password|reset|token|oauth|callback)'),
    "file_operations": re.compile(r'/(upload|download|export|import|file|document|attachment)'),
    "admin_paths": re.compile(r'/(admin|dashboard|manage|control|panel|config|settings)'),
    "debug_paths": re.compile(r'/(debug|test|dev|staging|internal|phpinfo|trace)'),
    "ssrf_candidates": re.compile(r'[?&](url|uri|path|dest|redirect|return|next|target|link|goto|src|source|ref|img|image|domain|host|site|callback|data|load|fetch)='),
    "lfi_candidates": re.compile(r'[?&](file|path|template|page|include|dir|document|folder|root|pg|read|cat|doc|view)='),
    "sqli_candidates": re.compile(r'[?&](id|user|uid|pid|page|sort|order|category|search|query|filter|limit|offset|count|type|name|key|select|from|where)='),
    "xss_candidates": re.compile(r'[?&](q|s|search|query|keyword|term|message|text|content|body|title|name|value|input|data|param|output|echo|print|error|msg|callback|jsonp)='),
    "open_redirect": re.compile(r'[?&](url|uri|redirect|return|next|target|redir|destination|go|link|out|ref|to|continue|forward)='),
    "rce_candidates": re.compile(r'[?&](cmd|exec|command|execute|run|system|shell|code|eval|ping|query|process)='),
}


@dataclass
class GauUrl:
    """Parsed GAU URL with metadata."""
    url: str
    domain: str
    path: str
    params: dict[str, list[str]] = field(default_factory=dict)
    categories: list[str] = field(default_factory=list)
    validation_status: Optional[int] = None  # HTTP status if validated

    @property
    def has_params(self) -> bool:
        return bool(self.params)

    @property
    def param_count(self) -> int:
        return len(self.params)


@dataclass
class GauResult:
    """GAU scan result."""
    domain: str
    total_urls: int = 0
    unique_urls: int = 0
    urls_with_params: int = 0
    categorized_urls: dict[str, list[GauUrl]] = field(default_factory=dict)
    all_urls: list[GauUrl] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class GauWrapper:
    """
    GAU (GetAllUrls) wrapper for historical URL discovery.

    Mines URLs from:
    - Wayback Machine
    - Common Crawl
    - Open Threat Exchange (OTX)
    - URLScan
    """

    def __init__(
        self,
        executor: Optional[ToolExecutor] = None,
        blacklist: Optional[list[str]] = None,
    ):
        """
        Initialize GAU wrapper.

        Args:
            executor: Tool executor instance
            blacklist: Extensions to skip (defaults to DEFAULT_BLACKLIST)
        """
        self.executor = executor or get_executor()
        self.blacklist = blacklist or DEFAULT_BLACKLIST

    async def fetch_urls(
        self,
        domain: str,
        include_subs: bool = True,
        providers: Optional[list[str]] = None,
        threads: int = 5,
        timeout: int = 90,
        output_file: Optional[Path] = None,
        dedupe_params: bool = True,
    ) -> GauResult:
        """
        Fetch historical URLs for a domain.

        Args:
            domain: Target domain
            include_subs: Include subdomains
            providers: List of providers (wayback, commoncrawl, otx, urlscan)
            threads: Number of threads
            timeout: Timeout per provider
            output_file: Path to save raw output
            dedupe_params: Remove duplicate endpoints with different params

        Returns:
            GauResult with categorized URLs
        """
        logger.info(f"Fetching historical URLs for {domain}")

        result = GauResult(domain=domain)

        if not self.is_available():
            result.errors.append("gau tool not found in PATH")
            logger.error("gau not available")
            return result

        # Build command
        gau_path = ToolExecutor.get_tool_path("gau")
        cmd = [gau_path]

        # Add blacklist (extensions to skip)
        if self.blacklist:
            for ext in self.blacklist:
                cmd.extend(["--blacklist", ext])

        # Add options
        if include_subs:
            cmd.append("--subs")

        # Note: --fp flag removed - too aggressive, filters out most URLs
        # Deduplication is handled in post-processing instead
        # if dedupe_params:
        #     cmd.append("--fp")

        if providers:
            # GAU expects comma-separated providers, not multiple flags
            cmd.extend(["--providers", ",".join(providers)])

        cmd.extend(["--threads", str(threads)])
        cmd.extend(["--timeout", str(timeout)])

        # Output file
        if output_file is None:
            output_file = secure_temp_file(suffix="_gau.txt")

        cmd.extend(["--o", str(output_file)])

        # Add domain as final argument
        cmd.append(domain)

        # Execute gau
        exec_timeout = timeout * 4 + 60  # Allow time for all providers
        exec_result = await self.executor.run(cmd, timeout=exec_timeout)

        if not exec_result.success:
            result.errors.append(f"gau failed: {exec_result.error or exec_result.stderr}")
            logger.error(f"gau failed: {exec_result.error}")
            return result

        # Parse results
        if output_file.exists():
            raw_urls = output_file.read_text().strip().split("\n")
            raw_urls = [u.strip() for u in raw_urls if u.strip()]
            result.total_urls = len(raw_urls)

            # Deduplicate and parse
            seen_urls = set()
            for url in raw_urls:
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                parsed = self._parse_url(url)
                if parsed:
                    result.all_urls.append(parsed)

                    # Track params
                    if parsed.has_params:
                        result.urls_with_params += 1

                    # Categorize
                    for category in parsed.categories:
                        if category not in result.categorized_urls:
                            result.categorized_urls[category] = []
                        result.categorized_urls[category].append(parsed)

            result.unique_urls = len(result.all_urls)

        logger.info(
            f"GAU complete for {domain}",
            total=result.total_urls,
            unique=result.unique_urls,
            with_params=result.urls_with_params,
            categories=len(result.categorized_urls),
        )

        return result

    def _parse_url(self, url: str) -> Optional[GauUrl]:
        """Parse a URL and categorize it."""
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return None

            params = {}
            if parsed.query:
                params = parse_qs(parsed.query)

            gau_url = GauUrl(
                url=url,
                domain=parsed.netloc,
                path=parsed.path,
                params=params,
            )

            # Categorize by pattern matching
            for category, pattern in INTERESTING_PATTERNS.items():
                if pattern.search(url):
                    gau_url.categories.append(category)

            return gau_url

        except Exception as e:
            logger.debug(f"Failed to parse URL {url}: {e}")
            return None

    async def validate_urls(
        self,
        urls: list[GauUrl],
        max_concurrent: int = 20,
        timeout: int = 10,
    ) -> list[GauUrl]:
        """
        Validate URLs by checking if they still respond.

        Args:
            urls: List of GauUrl to validate
            max_concurrent: Max concurrent requests
            timeout: Request timeout

        Returns:
            List of validated URLs with status codes
        """
        logger.info(f"Validating {len(urls)} URLs")

        # Use httpx for async validation
        try:
            import httpx
        except ImportError:
            logger.warning("httpx not available for validation")
            return urls

        semaphore = asyncio.Semaphore(max_concurrent)

        async def check_url(gau_url: GauUrl) -> GauUrl:
            async with semaphore:
                try:
                    async with httpx.AsyncClient(
                        timeout=timeout,
                        follow_redirects=True,
                        verify=False,
                    ) as client:
                        resp = await client.head(gau_url.url)
                        gau_url.validation_status = resp.status_code
                except Exception:
                    gau_url.validation_status = 0
            return gau_url

        tasks = [check_url(url) for url in urls]
        validated = await asyncio.gather(*tasks)

        valid_count = sum(1 for u in validated if u.validation_status and u.validation_status < 400)
        logger.info(f"Validation complete: {valid_count}/{len(urls)} URLs accessible")

        return validated

    def get_high_value_urls(
        self,
        result: GauResult,
        categories: Optional[list[str]] = None,
        limit: int = 500,
    ) -> list[GauUrl]:
        """
        Get high-value URLs for targeted testing.

        Args:
            result: GauResult from fetch_urls
            categories: Specific categories to include (defaults to security-relevant)
            limit: Max URLs to return

        Returns:
            List of high-value URLs sorted by category count
        """
        if categories is None:
            # Security-relevant categories
            categories = [
                "ssrf_candidates", "lfi_candidates", "sqli_candidates",
                "xss_candidates", "open_redirect", "rce_candidates",
                "auth_endpoints", "admin_paths", "debug_paths",
                "api_endpoints", "file_operations",
            ]

        # Collect URLs from specified categories
        high_value = set()
        for category in categories:
            if category in result.categorized_urls:
                for url in result.categorized_urls[category][:limit // len(categories)]:
                    high_value.add(url.url)

        # Also include all URLs with params if we have room
        if len(high_value) < limit:
            for url in result.all_urls:
                if url.has_params and url.url not in high_value:
                    high_value.add(url.url)
                    if len(high_value) >= limit:
                        break

        # Convert back to GauUrl objects
        url_map = {u.url: u for u in result.all_urls}
        return [url_map[u] for u in list(high_value)[:limit] if u in url_map]

    @staticmethod
    def is_available() -> bool:
        """Check if gau is installed."""
        return get_executor().check_tool_available("gau")


async def fetch_historical_urls(
    domain: str,
    include_subs: bool = True,
    validate: bool = False,
) -> GauResult:
    """
    Convenience function to fetch historical URLs.

    Args:
        domain: Target domain
        include_subs: Include subdomains
        validate: Validate URLs still exist

    Returns:
        GauResult with categorized URLs
    """
    wrapper = GauWrapper()
    result = await wrapper.fetch_urls(domain, include_subs=include_subs)

    if validate and result.all_urls:
        # Only validate high-value URLs to save time
        high_value = wrapper.get_high_value_urls(result, limit=200)
        await wrapper.validate_urls(high_value)

    return result
