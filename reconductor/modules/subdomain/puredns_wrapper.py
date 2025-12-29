"""Puredns wrapper for DNS resolution and brute-force with wildcard filtering."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from reconductor.core.config import PurednsConfig
from reconductor.core.logger import get_logger
from reconductor.models.subdomain import Subdomain, SubdomainSource
from reconductor.utils.executor import ToolExecutor, get_executor
from reconductor.utils.parser import OutputParser
from reconductor.utils.tempfiles import secure_temp_file

logger = get_logger(__name__)


@dataclass
class BruteforceResult:
    """Result from puredns bruteforce operation."""
    valid_subdomains: list[str]
    wildcard_roots: list[str]
    total_tested: int
    duration: float
    success: bool
    error: Optional[str] = None


@dataclass
class ResolveResult:
    """Result from puredns resolve operation."""
    resolved_subdomains: list[str]
    failed_subdomains: list[str]
    wildcard_filtered: int
    duration: float
    success: bool
    error: Optional[str] = None


class PurednsWrapper:
    """
    Puredns integration for DNS brute-force with wildcard filtering.

    Puredns is the industry standard for high-volume DNS resolution
    with sophisticated wildcard detection that handles DNS load balancing.
    """

    def __init__(
        self,
        config: Optional[PurednsConfig] = None,
        executor: Optional[ToolExecutor] = None,
    ):
        """
        Initialize puredns wrapper.

        Args:
            config: Puredns configuration
            executor: Tool executor instance
        """
        self.config = config or PurednsConfig()
        self.executor = executor or get_executor()

    async def bruteforce(
        self,
        domain: str,
        wordlist: Path,
        output: Optional[Path] = None,
        rate_limit: Optional[int] = None,
    ) -> BruteforceResult:
        """
        Run puredns bruteforce with wildcard filtering.

        Args:
            domain: Target domain
            wordlist: Path to wordlist file
            output: Output file path (optional)
            rate_limit: DNS queries per second

        Returns:
            BruteforceResult with valid subdomains
        """
        logger.info(f"Starting puredns bruteforce on {domain}")

        # Prepare output paths (secure creation)
        if output is None:
            output = secure_temp_file(suffix="_valid.txt")

        wildcard_output = secure_temp_file(suffix="_wildcards.txt")

        # Build command - use full path to avoid conflicts
        puredns_path = ToolExecutor.get_tool_path("puredns")
        if not puredns_path:
            logger.error("puredns tool not found")
            return BruteforceResult(
                valid_subdomains=[],
                wildcard_roots=[],
                total_tested=0,
                duration=0,
                success=False,
                error="puredns not found",
            )

        cmd = [
            puredns_path, "bruteforce",
            str(wordlist),
            domain,
            "-w", str(output),
            "--wildcard-tests", str(self.config.wildcard_tests),
            "--write-wildcards", str(wildcard_output),
            "-q",
        ]

        # Add resolver file if specified
        if self.config.resolver_file:
            resolver_path = Path(self.config.resolver_file)
            if resolver_path.exists():
                cmd.extend(["-r", str(resolver_path)])

        # Add rate limit
        if rate_limit or self.config.rate_limit:
            cmd.extend(["--rate-limit", str(rate_limit or self.config.rate_limit)])

        # Execute puredns
        result = await self.executor.run(cmd, timeout=3600)  # 1 hour timeout

        if not result.success:
            error_msg = result.error or result.stderr
            logger.error(f"Puredns bruteforce failed: {error_msg}")
            return BruteforceResult(
                valid_subdomains=[],
                wildcard_roots=[],
                total_tested=0,
                duration=result.duration,
                success=False,
                error=error_msg,
            )

        # Read results
        valid_subdomains = []
        if output.exists():
            valid_subdomains = output.read_text().strip().split("\n")
            valid_subdomains = [s for s in valid_subdomains if s]

        wildcard_roots = []
        if wildcard_output.exists():
            wildcard_roots = wildcard_output.read_text().strip().split("\n")
            wildcard_roots = [w for w in wildcard_roots if w]

        # Count total tested (from wordlist)
        total_tested = 0
        if wordlist.exists():
            total_tested = sum(1 for _ in open(wordlist))

        logger.info(
            f"Puredns bruteforce complete",
            domain=domain,
            valid=len(valid_subdomains),
            wildcards=len(wildcard_roots),
            tested=total_tested,
        )

        return BruteforceResult(
            valid_subdomains=valid_subdomains,
            wildcard_roots=wildcard_roots,
            total_tested=total_tested,
            duration=result.duration,
            success=True,
        )

    async def resolve(
        self,
        subdomains_file: Path,
        output: Optional[Path] = None,
        rate_limit: Optional[int] = None,
    ) -> ResolveResult:
        """
        Resolve subdomain list with wildcard filtering.

        Args:
            subdomains_file: Path to file containing subdomains
            output: Output file path (optional)
            rate_limit: DNS queries per second

        Returns:
            ResolveResult with resolved subdomains
        """
        logger.info(f"Starting puredns resolve")

        # Prepare output path (secure creation)
        if output is None:
            output = secure_temp_file(suffix="_resolved.txt")

        # Build command - use full path to avoid conflicts
        puredns_path = ToolExecutor.get_tool_path("puredns")
        if not puredns_path:
            logger.error("puredns tool not found")
            return ResolveResult(
                resolved_subdomains=[],
                failed_subdomains=[],
                wildcard_filtered=0,
                duration=0,
                success=False,
                error="puredns not found",
            )

        cmd = [
            puredns_path, "resolve",
            str(subdomains_file),
            "-w", str(output),
            "--wildcard-tests", str(self.config.wildcard_tests),
            "-q",
        ]

        # Add resolver file if specified
        if self.config.resolver_file:
            resolver_path = Path(self.config.resolver_file)
            if resolver_path.exists():
                cmd.extend(["-r", str(resolver_path)])

        # Add rate limit
        if rate_limit or self.config.rate_limit:
            cmd.extend(["--rate-limit", str(rate_limit or self.config.rate_limit)])

        # Execute puredns
        result = await self.executor.run(cmd, timeout=3600)

        if not result.success:
            error_msg = result.error or result.stderr
            logger.error(f"Puredns resolve failed: {error_msg}")
            return ResolveResult(
                resolved_subdomains=[],
                failed_subdomains=[],
                wildcard_filtered=0,
                duration=result.duration,
                success=False,
                error=error_msg,
            )

        # Read results
        resolved = []
        if output.exists():
            resolved = output.read_text().strip().split("\n")
            resolved = [s for s in resolved if s]

        # Calculate stats
        total_input = sum(1 for _ in open(subdomains_file)) if subdomains_file.exists() else 0
        failed = total_input - len(resolved)

        logger.info(
            f"Puredns resolve complete",
            resolved=len(resolved),
            failed=failed,
        )

        return ResolveResult(
            resolved_subdomains=resolved,
            failed_subdomains=[],  # Puredns doesn't output failed list by default
            wildcard_filtered=0,  # Would need to parse stderr for this
            duration=result.duration,
            success=True,
        )

    async def resolve_list(
        self,
        subdomains: list[str],
        output: Optional[Path] = None,
    ) -> ResolveResult:
        """
        Resolve a list of subdomains.

        Args:
            subdomains: List of subdomains to resolve
            output: Output file path (optional)

        Returns:
            ResolveResult with resolved subdomains
        """
        # Write subdomains to temp file (secure creation)
        input_file = secure_temp_file(suffix="_input.txt")
        input_file.write_text("\n".join(subdomains))

        return await self.resolve(input_file, output)

    async def bruteforce_and_resolve(
        self,
        domain: str,
        wordlist: Path,
        seed_subdomains: Optional[list[str]] = None,
    ) -> list[Subdomain]:
        """
        Combined bruteforce and resolution pipeline.

        Args:
            domain: Target domain
            wordlist: Bruteforce wordlist
            seed_subdomains: Optional seed subdomains to also resolve

        Returns:
            List of valid Subdomain objects
        """
        all_valid = []

        # Run bruteforce
        brute_result = await self.bruteforce(domain, wordlist)
        if brute_result.success:
            for sub_name in brute_result.valid_subdomains:
                sub = Subdomain.from_name(sub_name, source=SubdomainSource.PUREDNS)
                all_valid.append(sub)

        # Resolve seed subdomains if provided
        if seed_subdomains:
            resolve_result = await self.resolve_list(seed_subdomains)
            if resolve_result.success:
                for sub_name in resolve_result.resolved_subdomains:
                    sub = Subdomain.from_name(sub_name, source=SubdomainSource.PUREDNS)
                    all_valid.append(sub)

        return all_valid

    @staticmethod
    def is_available() -> bool:
        """Check if puredns is installed."""
        return get_executor().check_tool_available("puredns")


async def create_resolver_file(
    output_path: Path,
    fetch_fresh: bool = True,
) -> Path:
    """
    Create or fetch a resolver file for puredns.

    Args:
        output_path: Path to save resolver file
        fetch_fresh: Fetch fresh resolvers from trickest

    Returns:
        Path to resolver file
    """
    if fetch_fresh:
        import httpx

        url = "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url)
                if response.status_code == 200:
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    output_path.write_text(response.text)
                    logger.info(f"Fetched fresh resolvers to {output_path}")
                    return output_path
        except Exception as e:
            logger.warning(f"Failed to fetch resolvers: {e}")

    # Fallback to default resolvers
    default_resolvers = """
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
""".strip()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(default_resolvers)
    logger.info(f"Created default resolvers at {output_path}")

    return output_path
