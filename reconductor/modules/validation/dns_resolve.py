"""DNS resolution using dnsx for record enumeration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from reconductor.core.logger import get_logger
from reconductor.utils.executor import ToolExecutor, get_executor
from reconductor.utils.parser import OutputParser
from reconductor.utils.tempfiles import secure_temp_file

logger = get_logger(__name__)


@dataclass
class DnsRecord:
    """DNS record data."""
    hostname: str
    record_type: str
    values: list[str] = field(default_factory=list)
    ttl: int = 0


@dataclass
class DnsResult:
    """Complete DNS resolution result for a host."""
    hostname: str
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    cname_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    soa_records: list[str] = field(default_factory=list)
    cdn_provider: Optional[str] = None
    asn: Optional[str] = None

    @property
    def has_records(self) -> bool:
        """Check if any records were found."""
        return bool(
            self.a_records or
            self.aaaa_records or
            self.cname_records
        )

    @property
    def primary_ip(self) -> Optional[str]:
        """Get primary IP address."""
        if self.a_records:
            return self.a_records[0]
        if self.aaaa_records:
            return self.aaaa_records[0]
        return None


class DnsResolver:
    """
    DNS resolution using dnsx for comprehensive DNS enumeration.

    Supports multiple record types, CDN detection, and ASN lookups.
    """

    def __init__(
        self,
        executor: Optional[ToolExecutor] = None,
        resolver_file: Optional[Path] = None,
    ):
        """
        Initialize DNS resolver.

        Args:
            executor: Tool executor instance
            resolver_file: Custom resolver file path
        """
        self.executor = executor or get_executor()
        self.resolver_file = resolver_file

    async def resolve(
        self,
        hostnames: list[str],
        output_file: Optional[Path] = None,
        record_types: Optional[list[str]] = None,
        threads: int = 100,
        rate_limit: int = 500,
        detect_cdn: bool = True,
        detect_asn: bool = False,
    ) -> dict[str, DnsResult]:
        """
        Resolve hostnames and gather DNS information.

        Args:
            hostnames: List of hostnames to resolve
            output_file: Output file path (optional)
            record_types: Specific record types to query
            threads: Number of concurrent threads
            rate_limit: DNS queries per second
            detect_cdn: Enable CDN detection
            detect_asn: Enable ASN detection

        Returns:
            Dictionary mapping hostname to DnsResult
        """
        logger.info(f"Starting DNS resolution for {len(hostnames)} hosts")

        # Write hostnames to temp file (secure creation)
        input_file = secure_temp_file(suffix="_hosts.txt")
        input_file.write_text("\n".join(hostnames))

        # Prepare output
        if output_file is None:
            output_file = secure_temp_file(suffix="_dnsx.json")

        # Build command - use full path to avoid conflicts
        dnsx_path = ToolExecutor.get_tool_path("dnsx")
        if not dnsx_path:
            logger.error("dnsx tool not found")
            return {}

        cmd = [
            dnsx_path,
            "-l", str(input_file),
            "-o", str(output_file),
            "-json",
            "-silent",
            "-threads", str(threads),
            "-rate-limit", str(rate_limit),
        ]

        # Add resolver file if specified
        if self.resolver_file and self.resolver_file.exists():
            cmd.extend(["-r", str(self.resolver_file)])

        # Record types
        if record_types:
            for rt in record_types:
                cmd.append(f"-{rt.lower()}")
        else:
            # Default: A, AAAA, CNAME
            cmd.extend(["-a", "-aaaa", "-cname"])

        # CDN detection
        if detect_cdn:
            cmd.append("-cdn")

        # ASN detection
        if detect_asn:
            cmd.append("-asn")

        # Response only (no input echo)
        cmd.append("-resp-only")

        # Execute dnsx
        result = await self.executor.run(cmd, timeout=600)

        if not result.success:
            logger.error(f"dnsx failed: {result.error or result.stderr}")
            return {}

        # Parse results
        results = {}
        if output_file.exists():
            content = output_file.read_text()
            raw_results = OutputParser.parse_dnsx(content)

            for hostname, data in raw_results.items():
                results[hostname] = DnsResult(
                    hostname=hostname,
                    a_records=data.get("a", []),
                    aaaa_records=data.get("aaaa", []),
                    cname_records=data.get("cname", []),
                    mx_records=data.get("mx", []),
                    ns_records=data.get("ns", []),
                    txt_records=data.get("txt", []),
                    soa_records=data.get("soa", []),
                )

        resolved_count = sum(1 for r in results.values() if r.has_records)
        logger.info(
            f"DNS resolution complete",
            total=len(hostnames),
            resolved=resolved_count,
        )

        return results

    async def resolve_all_records(
        self,
        hostnames: list[str],
    ) -> dict[str, DnsResult]:
        """
        Resolve all DNS record types for hostnames.

        Args:
            hostnames: List of hostnames

        Returns:
            Dictionary mapping hostname to DnsResult
        """
        return await self.resolve(
            hostnames,
            record_types=["a", "aaaa", "cname", "mx", "ns", "txt", "soa"],
            detect_cdn=True,
            detect_asn=True,
        )

    async def resolve_single(
        self,
        hostname: str,
    ) -> Optional[DnsResult]:
        """
        Resolve a single hostname.

        Args:
            hostname: Hostname to resolve

        Returns:
            DnsResult if resolved, None otherwise
        """
        results = await self.resolve([hostname], threads=1)
        return results.get(hostname)

    async def filter_alive(
        self,
        hostnames: list[str],
    ) -> list[str]:
        """
        Filter to only hostnames that resolve.

        Args:
            hostnames: List of hostnames to check

        Returns:
            List of resolvable hostnames
        """
        results = await self.resolve(hostnames)
        return [
            hostname for hostname, result in results.items()
            if result.has_records
        ]

    async def get_ips(
        self,
        hostnames: list[str],
    ) -> dict[str, list[str]]:
        """
        Get IP addresses for hostnames.

        Args:
            hostnames: List of hostnames

        Returns:
            Dictionary mapping hostname to list of IPs
        """
        results = await self.resolve(hostnames, record_types=["a", "aaaa"])
        return {
            hostname: result.a_records + result.aaaa_records
            for hostname, result in results.items()
            if result.has_records
        }

    async def get_cname_chains(
        self,
        hostnames: list[str],
    ) -> dict[str, list[str]]:
        """
        Get CNAME chains for hostnames.

        Args:
            hostnames: List of hostnames

        Returns:
            Dictionary mapping hostname to CNAME chain
        """
        results = await self.resolve(hostnames, record_types=["cname"])
        return {
            hostname: result.cname_records
            for hostname, result in results.items()
            if result.cname_records
        }

    @staticmethod
    def is_available() -> bool:
        """Check if dnsx is installed."""
        return get_executor().check_tool_available("dnsx")


class ResolverPool:
    """
    Maintains a healthy pool of DNS resolvers.

    Monitors resolver health and fetches fresh resolvers
    when the pool becomes too small.
    """

    RESOLVER_SOURCES = [
        "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
        "https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt",
    ]

    def __init__(
        self,
        initial_resolvers: Optional[list[str]] = None,
        min_pool_size: int = 20,
        resolver_file: Optional[Path] = None,
    ):
        """
        Initialize resolver pool.

        Args:
            initial_resolvers: List of resolver IPs
            min_pool_size: Minimum number of healthy resolvers
            resolver_file: File to persist resolvers
        """
        self.resolvers = set(initial_resolvers or [])
        self.healthy_resolvers: set[str] = set()
        self.min_pool_size = min_pool_size
        self.resolver_file = resolver_file

        # Load from file if exists
        if resolver_file and resolver_file.exists():
            self._load_from_file()

    def _load_from_file(self) -> None:
        """Load resolvers from file."""
        if not self.resolver_file:
            return

        content = self.resolver_file.read_text()
        for line in content.strip().split("\n"):
            resolver = line.strip()
            if resolver and not resolver.startswith("#"):
                self.resolvers.add(resolver)

        logger.info(f"Loaded {len(self.resolvers)} resolvers from file")

    async def fetch_fresh_resolvers(self) -> list[str]:
        """
        Fetch fresh resolvers from online sources.

        Returns:
            List of resolver IPs
        """
        import httpx

        new_resolvers = []

        for source_url in self.RESOLVER_SOURCES:
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    response = await client.get(source_url)
                    if response.status_code == 200:
                        for line in response.text.strip().split("\n"):
                            resolver = line.strip()
                            if resolver and not resolver.startswith("#"):
                                new_resolvers.append(resolver)
                        break  # Success, don't try other sources
            except Exception as e:
                logger.warning(f"Failed to fetch resolvers from {source_url}: {e}")

        if new_resolvers:
            logger.info(f"Fetched {len(new_resolvers)} fresh resolvers")
            self.resolvers.update(new_resolvers)

            # Save to file
            if self.resolver_file:
                self.resolver_file.parent.mkdir(parents=True, exist_ok=True)
                self.resolver_file.write_text("\n".join(sorted(self.resolvers)))

        return new_resolvers

    def get_resolver_file(self) -> Path:
        """
        Get path to resolver file, creating if needed.

        Returns:
            Path to resolver file
        """
        if self.resolver_file and self.resolver_file.exists():
            return self.resolver_file

        # Create default resolver file
        default_resolvers = [
            "8.8.8.8",
            "8.8.4.4",
            "1.1.1.1",
            "1.0.0.1",
            "9.9.9.9",
            "149.112.112.112",
            "208.67.222.222",
            "208.67.220.220",
        ]

        if not self.resolver_file:
            self.resolver_file = secure_temp_file(suffix="_resolvers.txt")

        self.resolver_file.parent.mkdir(parents=True, exist_ok=True)
        self.resolver_file.write_text("\n".join(default_resolvers))

        return self.resolver_file
