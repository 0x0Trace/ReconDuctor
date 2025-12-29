"""Subjack wrapper for subdomain takeover detection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from reconductor.core.logger import get_logger
from reconductor.models.finding import Severity, TakeoverFinding
from reconductor.utils.executor import ToolExecutor, get_executor
from reconductor.utils.tempfiles import secure_temp_file

logger = get_logger(__name__)

# Default fingerprints path (installed via go install)
DEFAULT_FINGERPRINTS_PATHS = [
    Path.home() / "go/pkg/mod/github.com/haccer/subjack@v0.0.0-20201112041112-49c51e57deab/fingerprints.json",
    Path.home() / "go/src/github.com/haccer/subjack/fingerprints.json",
    Path("/usr/share/subjack/fingerprints.json"),
]

# Service severity mapping (some takeovers are more critical than others)
SERVICE_SEVERITY = {
    "aws_s3": Severity.HIGH,
    "github": Severity.HIGH,
    "heroku": Severity.HIGH,
    "azure": Severity.HIGH,
    "shopify": Severity.HIGH,
    "fastly": Severity.HIGH,
    "cloudfront": Severity.HIGH,
    "netlify": Severity.MEDIUM,
    "vercel": Severity.MEDIUM,
    "surge": Severity.MEDIUM,
    "tumblr": Severity.MEDIUM,
    "wordpress": Severity.MEDIUM,
    "ghost": Severity.MEDIUM,
    "pantheon": Severity.MEDIUM,
    "teamwork": Severity.LOW,
    "helpjuice": Severity.LOW,
    "helpscout": Severity.LOW,
    "freshdesk": Severity.LOW,
}

# Documentation links for services
SERVICE_DOCS = {
    "github": "https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site",
    "heroku": "https://devcenter.heroku.com/articles/custom-domains",
    "aws_s3": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteHosting.html",
    "azure": "https://docs.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-domain",
    "shopify": "https://help.shopify.com/en/manual/domains",
    "netlify": "https://docs.netlify.com/domains-https/custom-domains/",
    "vercel": "https://vercel.com/docs/concepts/projects/domains",
    "fastly": "https://docs.fastly.com/en/guides/working-with-domains",
}


class SubjackWrapper:
    """
    Wrapper for subjack subdomain takeover detection tool.

    Runs subjack against DNS-resolved subdomains to find potential takeovers.
    This should run on ALL subdomains, not just live HTTP ones.
    """

    def __init__(
        self,
        executor: Optional[ToolExecutor] = None,
        fingerprints_path: Optional[Path] = None,
    ):
        """
        Initialize subjack wrapper.

        Args:
            executor: Tool executor instance
            fingerprints_path: Path to fingerprints.json (auto-detected if not provided)
        """
        self.executor = executor or get_executor()
        self.fingerprints_path = fingerprints_path or self._find_fingerprints()

    def _find_fingerprints(self) -> Optional[Path]:
        """Find subjack fingerprints.json file."""
        for path in DEFAULT_FINGERPRINTS_PATHS:
            if path.exists():
                logger.debug(f"Found subjack fingerprints at {path}")
                return path

        # Try to find it dynamically
        import subprocess
        try:
            result = subprocess.run(
                ["find", str(Path.home() / "go"), "-name", "fingerprints.json", "-path", "*subjack*"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.stdout.strip():
                path = Path(result.stdout.strip().split("\n")[0])
                if path.exists():
                    logger.debug(f"Found subjack fingerprints at {path}")
                    return path
        except Exception:
            pass

        logger.warning("Could not find subjack fingerprints.json")
        return None

    async def scan(
        self,
        subdomains: list[str],
        threads: int = 50,
        timeout: int = 10,
        use_ssl: bool = True,
        check_all: bool = False,
    ) -> list[TakeoverFinding]:
        """
        Scan subdomains for takeover vulnerabilities.

        Args:
            subdomains: List of DNS-resolved subdomains to check
            threads: Number of concurrent threads
            timeout: Connection timeout in seconds
            use_ssl: Force HTTPS connections
            check_all: Send requests to all URLs (not just CNAMEs)

        Returns:
            List of TakeoverFinding objects for vulnerable subdomains
        """
        if not subdomains:
            logger.debug("No subdomains to scan for takeover")
            return []

        if not self.is_available():
            logger.warning("subjack not available, skipping takeover scan")
            return []

        logger.info(f"Starting subjack takeover scan for {len(subdomains)} subdomains")

        # Write subdomains to temp file
        input_file = secure_temp_file(suffix="_subjack_input.txt")
        input_file.write_text("\n".join(subdomains))

        # Output file (JSON format)
        output_file = secure_temp_file(suffix="_subjack_output.json")

        # Build command
        subjack_path = ToolExecutor.get_tool_path("subjack")
        if not subjack_path:
            logger.error("subjack binary not found")
            return []

        cmd = [
            subjack_path,
            "-w", str(input_file),
            "-o", str(output_file),
            "-t", str(threads),
            "-timeout", str(timeout),
        ]

        # Add fingerprints path if found
        if self.fingerprints_path:
            cmd.extend(["-c", str(self.fingerprints_path)])

        # Optional flags
        if use_ssl:
            cmd.append("-ssl")
        if check_all:
            cmd.append("-a")

        # Execute subjack
        result = await self.executor.run(cmd, timeout=600)  # 10 min timeout

        if not result.success and not output_file.exists():
            logger.error(f"subjack failed: {result.error or result.stderr}")
            return []

        # Parse results
        findings = self._parse_results(output_file)

        logger.info(
            f"Subjack scan complete",
            subdomains_scanned=len(subdomains),
            takeovers_found=len(findings),
        )

        return findings

    def _parse_results(self, output_file: Path) -> list[TakeoverFinding]:
        """Parse subjack JSON output into TakeoverFinding objects."""
        findings = []

        if not output_file.exists():
            return findings

        try:
            content = output_file.read_text().strip()
            if not content:
                return findings

            results = json.loads(content)

            for result in results:
                subdomain = result.get("subdomain", "")
                service = result.get("service", "unknown").lower()
                vulnerable = result.get("vulnerable", False)

                if not vulnerable or not subdomain:
                    continue

                # Determine severity based on service
                severity = SERVICE_SEVERITY.get(service, Severity.MEDIUM)

                # Get documentation link
                docs = SERVICE_DOCS.get(service, "")

                finding = TakeoverFinding(
                    title=f"Subdomain Takeover - {service.upper()}",
                    target=subdomain,
                    subdomain=subdomain,
                    vulnerable_service=service,
                    takeover_documentation=docs,
                    confidence=0.85,  # subjack has good accuracy
                    severity=severity,
                    description=f"Subdomain {subdomain} is vulnerable to takeover via {service}. "
                                f"The CNAME points to a {service} service that can be claimed.",
                    evidence=f"Service: {service}, Detected by subjack",
                )
                findings.append(finding)

                logger.warning(
                    f"Takeover vulnerability found",
                    subdomain=subdomain,
                    service=service,
                    severity=severity.value,
                )

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse subjack output: {e}")
        except Exception as e:
            logger.error(f"Error processing subjack results: {e}")

        return findings

    @staticmethod
    def is_available() -> bool:
        """Check if subjack is installed."""
        return get_executor().check_tool_available("subjack")

    @staticmethod
    def get_tool_info() -> dict:
        """Get tool information."""
        return {
            "name": "subjack",
            "description": "Subdomain takeover detection tool",
            "url": "https://github.com/haccer/subjack",
            "available": SubjackWrapper.is_available(),
        }
