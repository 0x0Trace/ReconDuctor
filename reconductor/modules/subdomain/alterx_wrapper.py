"""Alterx wrapper for pattern-based subdomain permutations."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from reconductor.core.logger import get_logger
from reconductor.utils.executor import ToolExecutor, get_executor
from reconductor.utils.tempfiles import secure_temp_file

logger = get_logger(__name__)


# Default patterns for alterx
DEFAULT_PATTERNS = """
patterns:
  - "{{sub}}-{{word}}"
  - "{{word}}-{{sub}}"
  - "{{sub}}.{{word}}"
  - "{{sub}}{{number}}"
  - "{{word}}.{{sub}}"
  - "{{sub}}-{{word}}-{{number}}"
  - "{{word}}-{{sub}}-{{number}}"
  - "{{sub}}-{{number}}"
  - "{{sub}}{{word}}"
  - "{{word}}{{sub}}"
  - "{{sub}}-v{{number}}"
  - "v{{number}}-{{sub}}"
  - "{{sub}}-{{region}}"
  - "{{region}}-{{sub}}"

payloads:
  word:
    - dev
    - staging
    - prod
    - production
    - api
    - admin
    - internal
    - test
    - uat
    - qa
    - backup
    - old
    - new
    - beta
    - alpha
    - demo
    - sandbox
    - stage
    - preprod
    - pre
    - post
    - int
    - external
    - public
    - private
    - app
    - web
    - mobile
    - cdn
    - static
    - assets
    - media
    - img
    - images
    - docs
    - portal
    - dashboard
    - console
    - panel
    - mgmt
    - management
    - cms
    - blog
    - shop
    - store
    - mail
    - email
    - smtp
    - imap
    - pop
    - ftp
    - sftp
    - vpn
    - git
    - gitlab
    - jenkins
    - ci
    - cd
    - build
    - deploy
    - k8s
    - kubernetes
    - docker
    - aws
    - azure
    - gcp
    - cloud

  number:
    - 1
    - 2
    - 3
    - 01
    - 02
    - 03
    - 001
    - 002
    - 2023
    - 2024
    - 2025

  region:
    - us
    - eu
    - asia
    - uk
    - au
    - de
    - fr
    - jp
    - cn
    - in
    - br
    - ca
    - east
    - west
    - north
    - south
    - central
"""


class AlterxWrapper:
    """
    Alterx integration for pattern-based subdomain permutations.

    Alterx is the industry standard for intelligent subdomain
    permutation generation based on patterns.
    """

    def __init__(
        self,
        executor: Optional[ToolExecutor] = None,
        patterns_file: Optional[Path] = None,
    ):
        """
        Initialize alterx wrapper.

        Args:
            executor: Tool executor instance
            patterns_file: Custom patterns YAML file
        """
        self.executor = executor or get_executor()
        self.patterns_file = patterns_file

    async def generate_permutations(
        self,
        subdomains: list[str],
        patterns_file: Optional[Path] = None,
        limit: int = 0,
    ) -> list[str]:
        """
        Generate permutations using Alterx.

        Args:
            subdomains: List of seed subdomains
            patterns_file: Custom patterns file (optional)
            limit: Maximum permutations to generate (0 = unlimited)

        Returns:
            List of generated permutations
        """
        logger.info(f"Starting alterx permutation generation with {len(subdomains)} seeds")

        # Write input subdomains to temp file (secure creation)
        input_file = secure_temp_file(suffix="_input.txt")
        output_file = secure_temp_file(suffix="_output.txt")
        input_file.write_text("\n".join(subdomains))

        # Build command - use full path to avoid conflicts
        alterx_path = ToolExecutor.get_tool_path("alterx")
        if not alterx_path:
            logger.error("alterx tool not found")
            return []

        cmd = [
            alterx_path,
            "-l", str(input_file),
            "-o", str(output_file),
            "-silent",
        ]

        # Use custom patterns if provided
        use_patterns = patterns_file or self.patterns_file
        if use_patterns and use_patterns.exists():
            cmd.extend(["-p", str(use_patterns)])

        # Add limit if specified
        if limit > 0:
            cmd.extend(["-limit", str(limit)])

        # Execute alterx
        result = await self.executor.run(cmd, timeout=600)

        if not result.success:
            logger.error(f"Alterx failed: {result.error or result.stderr}")
            return []

        # Read results
        permutations = []
        if output_file.exists():
            permutations = output_file.read_text().strip().split("\n")
            permutations = [p for p in permutations if p]

        logger.info(
            f"Alterx generated {len(permutations)} permutations",
            input_count=len(subdomains),
        )

        return permutations

    async def generate_with_enrichment(
        self,
        subdomains: list[str],
        enrich: bool = True,
    ) -> list[str]:
        """
        Generate permutations with additional enrichment.

        Args:
            subdomains: List of seed subdomains
            enrich: Enable enrichment mode

        Returns:
            List of generated permutations
        """
        # Write input (secure creation)
        input_file = secure_temp_file(suffix="_input.txt")
        output_file = secure_temp_file(suffix="_output.txt")
        input_file.write_text("\n".join(subdomains))

        # Build command with enrichment - use full path
        alterx_path = ToolExecutor.get_tool_path("alterx")
        if not alterx_path:
            logger.error("alterx tool not found")
            return []

        cmd = [
            alterx_path,
            "-l", str(input_file),
            "-o", str(output_file),
            "-silent",
        ]

        if enrich:
            cmd.append("-enrich")

        result = await self.executor.run(cmd, timeout=600)

        if not result.success:
            logger.error(f"Alterx enrichment failed: {result.error or result.stderr}")
            return []

        permutations = []
        if output_file.exists():
            permutations = output_file.read_text().strip().split("\n")
            permutations = [p for p in permutations if p]

        return permutations

    async def generate_for_domain(
        self,
        domain: str,
        seed_subdomains: list[str],
    ) -> list[str]:
        """
        Generate permutations for a specific domain.

        Args:
            domain: Base domain
            seed_subdomains: Seed subdomains for permutation

        Returns:
            List of full subdomain permutations
        """
        # Extract just the prefixes from seed subdomains
        prefixes = []
        suffix = f".{domain}"
        for sub in seed_subdomains:
            if sub.endswith(suffix):
                prefix = sub[:-len(suffix)]
                if prefix:
                    prefixes.append(prefix)

        if not prefixes:
            logger.warning("No valid prefixes extracted from seed subdomains")
            return []

        # Generate permutations
        permutations = await self.generate_permutations(seed_subdomains)

        # Filter to only include those for the target domain
        valid_permutations = [
            p for p in permutations
            if p.endswith(suffix) or "." not in p
        ]

        # Add domain suffix to bare prefixes
        full_permutations = []
        for p in valid_permutations:
            if p.endswith(suffix):
                full_permutations.append(p)
            else:
                full_permutations.append(f"{p}.{domain}")

        return full_permutations

    @staticmethod
    def create_patterns_file(
        output_path: Path,
        patterns: Optional[str] = None,
    ) -> Path:
        """
        Create a patterns file for alterx.

        Args:
            output_path: Path to save patterns file
            patterns: Custom patterns YAML content

        Returns:
            Path to created patterns file
        """
        content = patterns or DEFAULT_PATTERNS
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content)
        logger.info(f"Created patterns file at {output_path}")
        return output_path

    @staticmethod
    def is_available() -> bool:
        """Check if alterx is installed."""
        return get_executor().check_tool_available("alterx")


class SmartPermutationGenerator:
    """
    Context-aware permutation generation.

    Analyzes existing subdomains to detect naming patterns
    and generates targeted permutations.
    """

    def __init__(self):
        """Initialize smart generator."""
        self.detected_separators = set()
        self.detected_prefixes = set()
        self.detected_suffixes = set()
        self.detected_patterns = []

    def analyze_naming_patterns(
        self,
        subdomains: list[str],
    ) -> dict[str, any]:
        """
        Analyze existing subdomain naming conventions.

        Args:
            subdomains: List of existing subdomains

        Returns:
            Dictionary with detected patterns
        """
        import re
        from collections import Counter

        patterns = {
            "separators": Counter(),
            "prefixes": Counter(),
            "suffixes": Counter(),
            "numeric_patterns": Counter(),
            "regional_patterns": Counter(),
        }

        for sub in subdomains:
            # Get just the prefix part
            parts = sub.split(".")
            if len(parts) < 2:
                continue

            prefix = parts[0]

            # Detect separators
            if "-" in prefix:
                patterns["separators"]["-"] += 1
                segments = prefix.split("-")
                if segments:
                    patterns["prefixes"][segments[0]] += 1
                    if len(segments) > 1:
                        patterns["suffixes"][segments[-1]] += 1

            # Detect regional patterns
            regional = re.match(r"^(us|eu|asia|uk|au|de|fr|jp|cn|east|west|north|south)-?", prefix)
            if regional:
                patterns["regional_patterns"][regional.group(1)] += 1

            # Detect numeric patterns
            if re.search(r"\d+$", prefix):
                patterns["numeric_patterns"]["trailing_number"] += 1
            if re.search(r"^\d+", prefix):
                patterns["numeric_patterns"]["leading_number"] += 1

            # Common environment prefixes
            env_match = re.match(r"^(dev|staging|prod|test|uat|qa|beta|alpha|demo)", prefix)
            if env_match:
                patterns["prefixes"][env_match.group(1)] += 1

        # Store detected patterns
        self.detected_separators = set(patterns["separators"].keys())
        self.detected_prefixes = set(k for k, v in patterns["prefixes"].items() if v > 1)
        self.detected_patterns = patterns

        return patterns

    def generate_contextual_patterns(
        self,
        domain: str,
        existing: list[str],
    ) -> str:
        """
        Generate custom patterns based on observed naming conventions.

        Args:
            domain: Target domain
            existing: List of existing subdomains

        Returns:
            YAML patterns content
        """
        self.analyze_naming_patterns(existing)

        # Determine separator preference
        sep = "-" if "-" in self.detected_separators else "."

        # Build patterns list
        pattern_lines = []

        # Add patterns based on detected prefixes
        for prefix in list(self.detected_prefixes)[:10]:
            pattern_lines.append(f'  - "{{{{sub}}}}{sep}{prefix}"')
            pattern_lines.append(f'  - "{prefix}{sep}{{{{sub}}}}"')

        # Add regional patterns if detected
        for region in list(self.detected_patterns.get("regional_patterns", {}).keys())[:5]:
            pattern_lines.append(f'  - "{region}{sep}{{{{sub}}}}"')

        # Default patterns
        default_patterns = [
            f'  - "{{{{sub}}}}{sep}{{{{word}}}}"',
            f'  - "{{{{word}}}}{sep}{{{{sub}}}}"',
            '  - "{{sub}}{{number}}"',
            f'  - "{{{{sub}}}}{sep}v{{{{number}}}}"',
        ]
        pattern_lines.extend(default_patterns)

        patterns_yaml = f"""
patterns:
{chr(10).join(pattern_lines)}

payloads:
  word:
    - dev
    - staging
    - prod
    - api
    - test
    - internal
    - external
  number:
    - 1
    - 2
    - 01
    - 02
    - 2024
    - 2025
"""
        return patterns_yaml
