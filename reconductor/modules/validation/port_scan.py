"""Port scanning using naabu for service discovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from reconductor.core.logger import get_logger
from reconductor.core.scope import ScopeValidator
from reconductor.utils.executor import ToolExecutor, get_executor
from reconductor.utils.parser import OutputParser
from reconductor.utils.tempfiles import secure_temp_file

logger = get_logger(__name__)


# Smart port selection based on common web services
COMMON_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]
TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 5901, 8080, 8443, 8888,
]
FULL_WEB_PORTS = [
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
    443, 444, 445,
    800, 801, 808, 880, 888,
    1080, 1443, 1880,
    2000, 2001, 2082, 2083, 2086, 2087,
    3000, 3001, 3128, 3333, 3443,
    4000, 4001, 4040, 4080, 4443, 4444,
    5000, 5001, 5080, 5443, 5555,
    6000, 6001, 6080, 6443, 6666,
    7000, 7001, 7070, 7080, 7443, 7777,
    8000, 8001, 8008, 8009, 8010, 8080, 8081, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8180, 8181, 8443, 8444, 8445, 8880, 8888,
    9000, 9001, 9080, 9090, 9091, 9443, 9999,
    10000, 10001, 10080, 10443,
]


@dataclass
class PortScanResult:
    """Port scan result for a host."""
    host: str
    open_ports: list[int] = field(default_factory=list)
    ip_address: Optional[str] = None
    scan_time: float = 0.0

    @property
    def has_web_ports(self) -> bool:
        """Check if any common web ports are open."""
        return bool(set(self.open_ports) & set(COMMON_WEB_PORTS))

    @property
    def web_ports(self) -> list[int]:
        """Get only web-related ports."""
        return [p for p in self.open_ports if p in FULL_WEB_PORTS]


class PortScanner:
    """
    Port scanning using naabu for service discovery.

    Supports smart port selection and scope validation.
    """

    def __init__(
        self,
        executor: Optional[ToolExecutor] = None,
        scope_validator: Optional[ScopeValidator] = None,
    ):
        """
        Initialize port scanner.

        Args:
            executor: Tool executor instance
            scope_validator: Scope validator for IP validation
        """
        self.executor = executor or get_executor()
        self.scope_validator = scope_validator

    async def scan(
        self,
        targets: list[str],
        ports: Optional[list[int]] = None,
        output_file: Optional[Path] = None,
        rate: int = 1000,
        threads: int = 25,
        top_ports: Optional[int] = None,
        scan_all: bool = False,
    ) -> dict[str, PortScanResult]:
        """
        Scan targets for open ports.

        Args:
            targets: List of hosts/IPs to scan
            ports: Specific ports to scan
            output_file: Output file path (optional)
            rate: Packets per second
            threads: Number of threads
            top_ports: Scan top N ports
            scan_all: Scan all ports (1-65535)

        Returns:
            Dictionary mapping host to PortScanResult
        """
        logger.info(f"Starting port scan for {len(targets)} targets")

        # Validate IPs if scope validator is configured
        if self.scope_validator:
            valid_targets = []
            for target in targets:
                if self.scope_validator.is_ip_in_scope(target):
                    valid_targets.append(target)
                else:
                    logger.warning(f"Skipping out-of-scope target: {target}")
            targets = valid_targets

        if not targets:
            logger.warning("No valid targets after scope validation")
            return {}

        # Write targets to temp file (secure creation)
        input_file = secure_temp_file(suffix="_targets.txt")
        input_file.write_text("\n".join(targets))

        # Prepare output
        if output_file is None:
            output_file = secure_temp_file(suffix="_naabu.json")

        # Build command - use full path to avoid conflicts
        naabu_path = ToolExecutor.get_tool_path("naabu")
        if not naabu_path:
            logger.error("naabu tool not found")
            return {}

        cmd = [
            naabu_path,
            "-l", str(input_file),
            "-o", str(output_file),
            "-json",
            "-silent",
            "-rate", str(rate),
            "-c", str(threads),
        ]

        # Port selection
        if scan_all:
            cmd.extend(["-p", "-"])  # All ports
        elif top_ports:
            cmd.extend(["-top-ports", str(top_ports)])
        elif ports:
            port_str = ",".join(str(p) for p in ports)
            cmd.extend(["-p", port_str])
        else:
            # Default: common web ports
            port_str = ",".join(str(p) for p in COMMON_WEB_PORTS)
            cmd.extend(["-p", port_str])

        # Execute naabu - scale timeout based on target count
        # ~3 seconds per host minimum, plus 10 min base
        timeout = max(3600, 600 + len(targets) * 3)  # Min 1 hour, scales with targets
        result = await self.executor.run(cmd, timeout=timeout)

        if not result.success:
            logger.error(f"naabu failed: {result.error or result.stderr}")
            return {}

        # Parse results
        results = {}
        if output_file.exists():
            content = output_file.read_text()
            raw_results = OutputParser.parse_naabu(content)

            for host, open_ports in raw_results.items():
                results[host] = PortScanResult(
                    host=host,
                    open_ports=open_ports,
                    scan_time=result.duration,
                )

        total_ports = sum(len(r.open_ports) for r in results.values())
        logger.info(
            f"Port scan complete",
            targets=len(targets),
            hosts_with_ports=len(results),
            total_open_ports=total_ports,
        )

        return results

    async def scan_web_ports(
        self,
        targets: list[str],
        rate: int = 1000,
    ) -> dict[str, PortScanResult]:
        """
        Scan targets for common web ports.

        Args:
            targets: List of hosts/IPs
            rate: Packets per second

        Returns:
            Dictionary mapping host to PortScanResult
        """
        return await self.scan(
            targets,
            ports=FULL_WEB_PORTS,
            rate=rate,
        )

    async def scan_single(
        self,
        target: str,
        ports: Optional[list[int]] = None,
    ) -> Optional[PortScanResult]:
        """
        Scan a single target.

        Args:
            target: Host/IP to scan
            ports: Ports to scan

        Returns:
            PortScanResult if successful
        """
        results = await self.scan(
            [target],
            ports=ports,
            rate=100,
            threads=1,
        )
        return results.get(target)

    async def quick_scan(
        self,
        targets: list[str],
    ) -> dict[str, PortScanResult]:
        """
        Quick scan for most common web ports.

        Args:
            targets: List of hosts/IPs

        Returns:
            Dictionary mapping host to PortScanResult
        """
        return await self.scan(
            targets,
            ports=[80, 443, 8080, 8443],
            rate=2000,
        )

    async def scan_all_ports(
        self,
        targets: list[str],
        rate: int = 500,
    ) -> dict[str, PortScanResult]:
        """
        Scan targets for top 1000 common ports (service discovery).

        Used for non-HTTP subdomains to find other services (SSH, FTP, databases, etc).

        Args:
            targets: List of hosts/IPs
            rate: Packets per second (lower for stealth)

        Returns:
            Dictionary mapping host to PortScanResult
        """
        logger.info(f"Scanning {len(targets)} non-HTTP subdomains for open ports (top 1000)")
        return await self.scan(
            targets,
            top_ports=1000,  # Top 1000 most common ports
            rate=rate,
        )

    @staticmethod
    def get_urls_from_results(
        results: dict[str, PortScanResult],
    ) -> list[str]:
        """
        Generate URLs from port scan results.

        Args:
            results: Port scan results

        Returns:
            List of URLs with scheme and port
        """
        urls = []
        https_ports = {443, 8443, 4443, 9443}

        for host, result in results.items():
            for port in result.open_ports:
                if port in https_ports or port > 1000:
                    scheme = "https"
                else:
                    scheme = "http"

                if (scheme == "https" and port == 443) or \
                   (scheme == "http" and port == 80):
                    urls.append(f"{scheme}://{host}")
                else:
                    urls.append(f"{scheme}://{host}:{port}")

        return urls

    @staticmethod
    def is_available() -> bool:
        """Check if naabu is installed."""
        return get_executor().check_tool_available("naabu")
