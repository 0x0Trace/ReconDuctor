"""Passive subdomain enumeration using various sources."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from reconductor.core.logger import get_logger
from reconductor.models.subdomain import Subdomain, SubdomainSource
from reconductor.utils.executor import ToolExecutor, get_executor
from reconductor.utils.parser import OutputParser
from reconductor.utils.deduplicator import Deduplicator
from reconductor.utils.tempfiles import secure_temp_file

logger = get_logger(__name__)


class PassiveEnumerator:
    """
    Passive subdomain enumeration using multiple sources.

    Primary tool: subfinder (wraps 10+ passive sources)
    Additional sources can be added via API integrations.
    """

    def __init__(
        self,
        executor: Optional[ToolExecutor] = None,
        timeout: int = 600,
    ):
        """
        Initialize passive enumerator.

        Args:
            executor: Tool executor instance
            timeout: Timeout for enumeration in seconds
        """
        self.executor = executor or get_executor()
        self.timeout = timeout

    async def enumerate(
        self,
        domain: str,
        use_all_sources: bool = True,
        recursive: bool = True,
        output_file: Optional[Path] = None,
    ) -> list[Subdomain]:
        """
        Enumerate subdomains passively using subfinder.

        Args:
            domain: Target domain
            use_all_sources: Use all available sources
            recursive: Enable recursive enumeration
            output_file: Optional file to save results

        Returns:
            List of discovered Subdomain objects
        """
        logger.info(f"Starting passive enumeration for {domain}")

        # Build command - use full path to avoid conflicts
        subfinder_path = ToolExecutor.get_tool_path("subfinder")
        if not subfinder_path:
            logger.error("subfinder tool not found")
            return []

        cmd = [subfinder_path, "-d", domain, "-json", "-silent"]

        if use_all_sources:
            cmd.append("-all")

        if recursive:
            cmd.append("-recursive")

        # Use temp file if output not specified (secure creation)
        if output_file is None:
            output_file = secure_temp_file(suffix=".json")

        cmd.extend(["-o", str(output_file)])

        # Execute subfinder
        result = await self.executor.run(cmd, timeout=self.timeout)

        if not result.success:
            logger.error(f"Subfinder failed: {result.error or result.stderr}")
            return []

        # Parse results
        subdomains = []
        if output_file.exists():
            content = output_file.read_text()
            subdomains = OutputParser.parse_subfinder(content, json_format=True)

            logger.info(
                f"Subfinder found {len(subdomains)} subdomains",
                domain=domain,
                count=len(subdomains),
            )

        return subdomains

    async def enumerate_with_sources(
        self,
        domain: str,
        sources: Optional[list[str]] = None,
        exclude_sources: Optional[list[str]] = None,
    ) -> list[Subdomain]:
        """
        Enumerate with specific sources.

        Args:
            domain: Target domain
            sources: Specific sources to use
            exclude_sources: Sources to exclude

        Returns:
            List of discovered Subdomain objects
        """
        subfinder_path = ToolExecutor.get_tool_path("subfinder")
        if not subfinder_path:
            logger.error("subfinder tool not found")
            return []

        cmd = [subfinder_path, "-d", domain, "-json", "-silent"]

        if sources:
            cmd.extend(["-s", ",".join(sources)])

        if exclude_sources:
            cmd.extend(["-es", ",".join(exclude_sources)])

        output_file = secure_temp_file(suffix=".json")
        cmd.extend(["-o", str(output_file)])

        result = await self.executor.run(cmd, timeout=self.timeout)

        if not result.success:
            logger.error(f"Subfinder failed: {result.error or result.stderr}")
            return []

        if output_file.exists():
            content = output_file.read_text()
            return OutputParser.parse_subfinder(content, json_format=True)

        return []

    async def enumerate_multiple(
        self,
        domains: list[str],
        use_all_sources: bool = True,
        output_dir: Optional[Path] = None,
    ) -> dict[str, list[Subdomain]]:
        """
        Enumerate subdomains for multiple domains.

        Args:
            domains: List of target domains
            use_all_sources: Use all available sources
            output_dir: Directory to save results

        Returns:
            Dictionary mapping domain to subdomains
        """
        results = {}

        # Create domains file (secure creation)
        domains_file = secure_temp_file(suffix=".txt")
        domains_file.write_text("\n".join(domains))

        # Build command - use full path to avoid conflicts
        subfinder_path = ToolExecutor.get_tool_path("subfinder")
        if not subfinder_path:
            logger.error("subfinder tool not found")
            return results

        cmd = [subfinder_path, "-dL", str(domains_file), "-json", "-silent"]

        if use_all_sources:
            cmd.append("-all")

        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            cmd.extend(["-oD", str(output_dir)])

        result = await self.executor.run(cmd, timeout=self.timeout * len(domains))

        if not result.success:
            logger.error(f"Subfinder failed: {result.error or result.stderr}")
            return results

        # Parse results from output directory
        if output_dir:
            for domain in domains:
                domain_file = output_dir / f"{domain}.txt"
                if domain_file.exists():
                    content = domain_file.read_text()
                    subs = OutputParser.parse_subfinder(content, json_format=False)
                    results[domain] = subs
        else:
            # Parse from stdout
            content = result.stdout
            all_subs = OutputParser.parse_subfinder(content, json_format=True)

            # Group by domain
            for sub in all_subs:
                if sub.domain not in results:
                    results[sub.domain] = []
                results[sub.domain].append(sub)

        return results


class CrtshEnumerator:
    """
    Certificate Transparency log enumeration via crt.sh.

    Provides additional subdomain discovery through SSL certificate logs.
    """

    def __init__(self, timeout: int = 180, retries: int = 5):
        """
        Initialize crt.sh enumerator.

        Args:
            timeout: Request timeout in seconds (default 180s - crt.sh can be slow)
            retries: Number of retry attempts on 503/timeout (default 5)
        """
        self.timeout = timeout
        self.retries = retries
        self.base_url = "https://crt.sh"

    async def enumerate(self, domain: str) -> list[Subdomain]:
        """
        Enumerate subdomains from crt.sh with retry logic.

        Args:
            domain: Target domain

        Returns:
            List of discovered Subdomain objects
        """
        import asyncio
        import httpx

        subdomains = []
        url = f"{self.base_url}/?q=%.{domain}&output=json"

        for attempt in range(self.retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(url)

                    # Retry on server errors (5xx) with exponential backoff
                    if response.status_code >= 500:
                        if attempt < self.retries:
                            wait_time = min(10 * (2 ** attempt), 120)  # 10s, 20s, 40s, 80s, 120s
                            logger.warning(f"crt.sh returned {response.status_code}, retrying in {wait_time}s (attempt {attempt + 1}/{self.retries + 1})...")
                            await asyncio.sleep(wait_time)
                            continue
                        else:
                            logger.warning(f"crt.sh returned {response.status_code} after {self.retries + 1} attempts - skipping")
                            return []

                    if response.status_code != 200:
                        logger.warning(f"crt.sh returned {response.status_code}")
                        return []

                    data = response.json()

                    seen = set()
                    for entry in data:
                        name = entry.get("name_value", "")
                        # Handle wildcard entries
                        for name_part in name.split("\n"):
                            name_part = name_part.strip().lower()
                            if name_part.startswith("*."):
                                name_part = name_part[2:]

                            if name_part and name_part not in seen:
                                if name_part.endswith(f".{domain}") or name_part == domain:
                                    seen.add(name_part)
                                    sub = Subdomain.from_name(
                                        name_part,
                                        source=SubdomainSource.CRTSH,
                                    )
                                    subdomains.append(sub)

                    logger.info(
                        f"crt.sh found {len(subdomains)} subdomains",
                        domain=domain,
                    )
                    return subdomains

            except httpx.TimeoutException:
                if attempt < self.retries:
                    wait_time = min(15 * (2 ** attempt), 120)  # 15s, 30s, 60s, 120s
                    logger.warning(f"crt.sh timeout, retrying in {wait_time}s (attempt {attempt + 1}/{self.retries + 1})...")
                    await asyncio.sleep(wait_time)
                    continue
                else:
                    logger.warning(f"crt.sh timeout after {self.retries + 1} attempts - skipping")

            except Exception as e:
                logger.error(f"crt.sh enumeration failed: {e}")
                break

        return subdomains


class PassiveEnumerationPipeline:
    """
    Combined passive enumeration using multiple sources.

    Sources:
    - Subfinder (wraps 10+ sources including SecurityTrails, VirusTotal, etc.)
    - crt.sh (Certificate Transparency logs)
    - Shodan (SSL certificate CN/O search)
    """

    def __init__(
        self,
        executor: Optional[ToolExecutor] = None,
        timeout: int = 600,
        shodan_api_key: Optional[str] = None,
    ):
        """
        Initialize enumeration pipeline.

        Args:
            executor: Tool executor instance
            timeout: Timeout in seconds
            shodan_api_key: Shodan API key for enhanced enumeration
        """
        self.subfinder = PassiveEnumerator(executor, timeout)
        self.crtsh = CrtshEnumerator(timeout=120, retries=2)
        self.deduplicator = Deduplicator()

        # Shodan enumerator (optional, requires API key)
        self.shodan = None
        self._init_shodan(shodan_api_key)

        # Track source counts for statistics
        self.source_counts: dict[str, int] = {}

    def _init_shodan(self, api_key: Optional[str] = None) -> None:
        """Initialize Shodan enumerator if API key available."""
        try:
            from reconductor.modules.recon.shodan_recon import ShodanEnumerator
            self.shodan = ShodanEnumerator(api_key=api_key)
            if self.shodan.api_key:
                logger.info("Shodan enumerator initialized")
            else:
                self.shodan = None
        except ImportError:
            logger.debug("Shodan module not available")

    async def enumerate(
        self,
        domain: str,
        use_crtsh: bool = True,
        use_shodan: bool = True,
    ) -> list[Subdomain]:
        """
        Enumerate subdomains from all passive sources in parallel.

        Args:
            domain: Target domain
            use_crtsh: Include crt.sh results
            use_shodan: Include Shodan results (requires API key)

        Returns:
            Deduplicated list of subdomains
        """
        import asyncio

        all_subdomains: list[Subdomain] = []
        self.source_counts = {}

        # Build list of tasks to run in parallel
        tasks = {}

        # Subfinder (always run)
        tasks["subfinder"] = self.subfinder.enumerate(domain)

        # crt.sh (runs in parallel, won't block others)
        if use_crtsh:
            tasks["crtsh"] = self.crtsh.enumerate(domain)

        # Shodan (runs in parallel)
        if use_shodan and self.shodan:
            tasks["shodan"] = self.shodan.enumerate(domain)

        # Run all sources concurrently
        task_names = list(tasks.keys())
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        # Process results
        for name, result in zip(task_names, results):
            if isinstance(result, Exception):
                logger.warning(f"{name} enumeration failed: {result}")
                self.source_counts[name] = 0
            else:
                all_subdomains.extend(result)
                self.source_counts[name] = len(result)

        # Deduplicate by subdomain name
        unique = self.deduplicator.deduplicate_with_key(
            all_subdomains,
            key_func=lambda s: s.name,
        )

        logger.info(
            f"Passive enumeration complete",
            domain=domain,
            total=len(all_subdomains),
            unique=len(unique),
            sources=self.source_counts,
        )

        return unique
