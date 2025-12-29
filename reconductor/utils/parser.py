"""Output parsers for various reconnaissance tools."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from reconductor.core.logger import get_logger
from reconductor.models.finding import Finding
from reconductor.models.host import Host
from reconductor.models.subdomain import Subdomain, SubdomainSource

logger = get_logger(__name__)


class OutputParser:
    """
    Parser for various reconnaissance tool outputs.

    Supports parsing JSON, JSONL, and plain text outputs
    from tools like subfinder, httpx, nuclei, etc.
    """

    @staticmethod
    def parse_jsonl(content: str) -> list[dict[str, Any]]:
        """
        Parse JSONL (JSON Lines) content.

        Args:
            content: JSONL string

        Returns:
            List of parsed JSON objects
        """
        results = []
        for line in content.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError as e:
                logger.debug(f"Failed to parse JSON line: {e}")
        return results

    @staticmethod
    def parse_json(content: str) -> Any:
        """
        Parse JSON content.

        Args:
            content: JSON string

        Returns:
            Parsed JSON object
        """
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON: {e}")
            return None

    @staticmethod
    def parse_lines(content: str) -> list[str]:
        """
        Parse plain text content into lines.

        Args:
            content: Text content

        Returns:
            List of non-empty lines
        """
        return [
            line.strip()
            for line in content.strip().split("\n")
            if line.strip()
        ]

    @classmethod
    def parse_subfinder(
        cls,
        content: str,
        json_format: bool = True,
    ) -> list[Subdomain]:
        """
        Parse subfinder output.

        Args:
            content: Subfinder output
            json_format: Whether output is in JSON format

        Returns:
            List of Subdomain objects
        """
        subdomains = []

        if json_format:
            for item in cls.parse_jsonl(content):
                if "host" in item:
                    sub = Subdomain.from_name(
                        item["host"],
                        source=SubdomainSource.SUBFINDER,
                    )
                    # Add source attribution if available
                    if "sources" in item:
                        sub.extra["sources"] = item["sources"]
                    subdomains.append(sub)
        else:
            for line in cls.parse_lines(content):
                sub = Subdomain.from_name(line, source=SubdomainSource.SUBFINDER)
                subdomains.append(sub)

        return subdomains

    @classmethod
    def parse_puredns(
        cls,
        content: str,
        source: SubdomainSource = SubdomainSource.PUREDNS,
    ) -> list[Subdomain]:
        """
        Parse puredns output.

        Args:
            content: Puredns output (plain text or JSON)
            source: Source to assign

        Returns:
            List of Subdomain objects
        """
        subdomains = []

        # Try JSON first
        try:
            data = cls.parse_jsonl(content)
            if data:
                for item in data:
                    if "host" in item or "subdomain" in item:
                        name = item.get("host") or item.get("subdomain")
                        sub = Subdomain.from_name(name, source=source)
                        subdomains.append(sub)
                return subdomains
        except Exception:
            pass

        # Fall back to plain text
        for line in cls.parse_lines(content):
            sub = Subdomain.from_name(line, source=source)
            subdomains.append(sub)

        return subdomains

    @classmethod
    def parse_httpx(cls, content: str) -> list[Host]:
        """
        Parse httpx JSON output.

        Args:
            content: httpx JSONL output

        Returns:
            List of Host objects
        """
        hosts = []

        for item in cls.parse_jsonl(content):
            try:
                host = Host.from_httpx_result(item)
                hosts.append(host)
            except Exception as e:
                logger.debug(f"Failed to parse httpx result: {e}")

        return hosts

    @classmethod
    def parse_dnsx(cls, content: str) -> dict[str, dict[str, Any]]:
        """
        Parse dnsx JSON output.

        Args:
            content: dnsx JSONL output

        Returns:
            Dictionary mapping hostname to DNS records
        """
        results = {}

        for item in cls.parse_jsonl(content):
            host = item.get("host", "")
            if not host:
                continue

            results[host] = {
                "a": item.get("a", []),
                "aaaa": item.get("aaaa", []),
                "cname": item.get("cname", []),
                "mx": item.get("mx", []),
                "ns": item.get("ns", []),
                "txt": item.get("txt", []),
                "soa": item.get("soa", []),
                "resolver": item.get("resolver", []),
            }

        return results

    @classmethod
    def parse_nuclei(cls, content: str) -> list[Finding]:
        """
        Parse nuclei JSON output.

        Args:
            content: nuclei JSONL output

        Returns:
            List of Finding objects
        """
        findings = []

        for item in cls.parse_jsonl(content):
            try:
                finding = Finding.from_nuclei_result(item)
                findings.append(finding)
            except Exception as e:
                logger.debug(f"Failed to parse nuclei result: {e}")

        return findings

    @classmethod
    def parse_naabu(cls, content: str) -> dict[str, list[int]]:
        """
        Parse naabu port scan output.

        Args:
            content: naabu output

        Returns:
            Dictionary mapping host to list of open ports
        """
        results: dict[str, list[int]] = {}

        for item in cls.parse_jsonl(content):
            host = item.get("host", item.get("ip", ""))
            port = item.get("port")

            if host and port:
                if host not in results:
                    results[host] = []
                results[host].append(int(port))

        # Sort ports for each host
        for host in results:
            results[host].sort()

        return results

    @classmethod
    def parse_alterx(cls, content: str) -> list[str]:
        """
        Parse alterx permutation output.

        Args:
            content: alterx output (one per line)

        Returns:
            List of generated permutations
        """
        return cls.parse_lines(content)

    @classmethod
    def parse_file(
        cls,
        file_path: Path,
        tool: str,
        **kwargs: Any,
    ) -> Any:
        """
        Parse a tool output file.

        Args:
            file_path: Path to output file
            tool: Tool name (subfinder, httpx, nuclei, etc.)
            **kwargs: Additional parser arguments

        Returns:
            Parsed results
        """
        if not file_path.exists():
            logger.warning(f"Output file not found: {file_path}")
            return []

        content = file_path.read_text()

        parsers = {
            "subfinder": cls.parse_subfinder,
            "puredns": cls.parse_puredns,
            "httpx": cls.parse_httpx,
            "dnsx": cls.parse_dnsx,
            "nuclei": cls.parse_nuclei,
            "naabu": cls.parse_naabu,
            "alterx": cls.parse_alterx,
        }

        parser = parsers.get(tool.lower())
        if parser:
            return parser(content, **kwargs)

        logger.warning(f"No parser available for tool: {tool}")
        return cls.parse_lines(content)


class CNAMEParser:
    """Parser for CNAME chain resolution."""

    @staticmethod
    def parse_chain(dns_result: dict[str, Any]) -> list[str]:
        """
        Extract CNAME chain from DNS result.

        Args:
            dns_result: DNS lookup result

        Returns:
            List of CNAME targets in order
        """
        chain = []
        cnames = dns_result.get("cname", [])

        if isinstance(cnames, list):
            chain = cnames
        elif isinstance(cnames, str):
            chain = [cnames]

        return chain

    @staticmethod
    def detect_potential_takeover(cname: str) -> Optional[str]:
        """
        Check if CNAME suggests potential takeover.

        Args:
            cname: CNAME target

        Returns:
            Service name if potential takeover, None otherwise
        """
        # Common patterns for takeover-vulnerable services
        patterns = {
            r"\.s3\.amazonaws\.com$": "aws-s3",
            r"\.s3-website.*\.amazonaws\.com$": "aws-s3",
            r"\.cloudfront\.net$": "aws-cloudfront",
            r"\.elasticbeanstalk\.com$": "aws-elasticbeanstalk",
            r"\.azurewebsites\.net$": "azure",
            r"\.blob\.core\.windows\.net$": "azure-blob",
            r"\.cloudapp\.azure\.com$": "azure",
            r"\.trafficmanager\.net$": "azure-trafficmanager",
            r"\.github\.io$": "github",
            r"\.githubusercontent\.com$": "github",
            r"\.herokuapp\.com$": "heroku",
            r"\.herokudns\.com$": "heroku",
            r"\.pantheonsite\.io$": "pantheon",
            r"\.netlify\.app$": "netlify",
            r"\.netlify\.com$": "netlify",
            r"\.vercel\.app$": "vercel",
            r"\.now\.sh$": "vercel",
            r"\.surge\.sh$": "surge",
            r"\.firebaseapp\.com$": "firebase",
            r"\.web\.app$": "firebase",
            r"\.ghost\.io$": "ghost",
            r"\.helpjuice\.com$": "helpjuice",
            r"\.helpscoutdocs\.com$": "helpscout",
            r"\.readme\.io$": "readme",
            r"\.zendesk\.com$": "zendesk",
            r"\.wordpress\.com$": "wordpress",
            r"\.shopify\.com$": "shopify",
            r"\.myshopify\.com$": "shopify",
            r"\.tumblr\.com$": "tumblr",
            r"\.bitbucket\.io$": "bitbucket",
            r"\.cargo\.site$": "cargo",
            r"\.feedpress\.me$": "feedpress",
            r"\.freshdesk\.com$": "freshdesk",
            r"\.ghost\.org$": "ghost",
            r"\.bigcartel\.com$": "bigcartel",
            r"\.teamwork\.com$": "teamwork",
            r"\.proposify\.com$": "proposify",
            r"\.tictail\.com$": "tictail",
            r"\.unbounce\.com$": "unbounce",
            r"\.launchrock\.com$": "launchrock",
            r"\.pingdom\.com$": "pingdom",
            r"\.tilda\.cc$": "tilda",
            r"\.cargocollective\.com$": "cargo",
            r"\.statuspage\.io$": "statuspage",
            r"\.uservoice\.com$": "uservoice",
        }

        cname_lower = cname.lower()
        for pattern, service in patterns.items():
            if re.search(pattern, cname_lower):
                return service

        return None
