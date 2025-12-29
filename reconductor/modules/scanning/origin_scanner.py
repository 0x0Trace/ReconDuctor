"""
Origin IP Scanner - Aggressive scanning against origin IPs bypassing CDN/WAF.

When scanning origin IPs directly, we can:
1. Use more aggressive templates (WAF would block these)
2. Include fuzzing and injection tests
3. Scan at higher rates (no CDN rate limiting)
4. Detect version-specific vulnerabilities
5. Find information disclosure hidden by CDN

This module runs nuclei directly against discovered origin IPs
with the Host header set to the target domain.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from reconductor.core.logger import get_logger

logger = get_logger(__name__)


@dataclass
class OriginFinding:
    """A finding from origin IP scanning."""
    template_id: str
    name: str
    severity: str
    ip: str
    host: str
    matched_at: str
    description: str = ""
    tags: list[str] = field(default_factory=list)
    reference: list[str] = field(default_factory=list)
    extracted: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "severity": self.severity,
            "ip": self.ip,
            "host": self.host,
            "matched_at": self.matched_at,
            "description": self.description,
            "tags": self.tags,
            "reference": self.reference,
            "extracted": self.extracted,
        }


@dataclass
class OriginScanResult:
    """Result of scanning origin IPs."""
    domain: str
    origin_ips: list[str]
    findings: list[OriginFinding] = field(default_factory=list)
    version_info: dict[str, str] = field(default_factory=dict)
    scan_stats: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "origin_ips": self.origin_ips,
            "findings": [f.to_dict() for f in self.findings],
            "version_info": self.version_info,
            "scan_stats": self.scan_stats,
            "errors": self.errors,
            "summary": {
                "total_findings": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity == "critical"),
                "high": sum(1 for f in self.findings if f.severity == "high"),
                "medium": sum(1 for f in self.findings if f.severity == "medium"),
                "low": sum(1 for f in self.findings if f.severity == "low"),
                "info": sum(1 for f in self.findings if f.severity == "info"),
            },
        }


class OriginScanner:
    """
    Aggressive scanner for origin IPs that bypasses CDN/WAF.

    Unlike scanning through CDN, origin scanning can:
    - Use injection/fuzzing templates
    - Detect exact software versions
    - Find hidden endpoints
    - Test for misconfigurations
    - Run at higher speeds

    Usage:
        scanner = OriginScanner(domain="example.com")
        result = await scanner.scan(["1.2.3.4", "5.6.7.8"])
    """

    # Template directories for aggressive scanning (relative to nuclei-templates)
    # Using directories is faster than tag matching
    # Keep focused for reasonable scan time (~2000 templates max)
    TEMPLATE_DIRS = [
        "http/cves/2025/",          # Latest CVEs (~268)
        "http/cves/2024/",          # Recent CVEs (~500)
        "http/cves/2023/",          # Recent CVEs (~525)
        "http/technologies/",        # Tech detection (~427)
        "http/misconfiguration/",    # Misconfigs (~371)
        "http/vulnerabilities/",     # General vulns (~23)
        "http/default-logins/",      # Default creds (~21)
    ]

    # Tags for secondary scan (if dirs not available)
    AGGRESSIVE_TAGS = [
        "cve", "cve2025", "cve2024", "cve2023",
        "exposure", "misconfig", "tech", "panel",
        "rce", "lfi", "ssrf", "sqli", "xss",
        "default-login", "unauth",
    ]

    # Tags to exclude (dangerous/noisy)
    EXCLUDE_TAGS = [
        "dos", "fuzz", "brute", "bruteforce",
        "intrusive", "oast", "interactsh",
    ]

    def __init__(
        self,
        domain: str,
        nuclei_path: str = "nuclei",
        rate_limit: int = 150,
        concurrency: int = 25,
        timeout: int = 10,
        retries: int = 2,
    ):
        """
        Initialize origin scanner.

        Args:
            domain: Target domain (used for Host header)
            nuclei_path: Path to nuclei binary
            rate_limit: Requests per second
            concurrency: Concurrent templates
            timeout: Request timeout in seconds
            retries: Number of retries per request
        """
        self.domain = domain
        self.nuclei_path = nuclei_path
        self.rate_limit = rate_limit
        self.concurrency = concurrency
        self.timeout = timeout
        self.retries = retries

    async def scan(
        self,
        origin_ips: list[str],
        severity: list[str] = None,
        extra_tags: list[str] = None,
        extra_exclude_tags: list[str] = None,
        custom_templates: list[str] = None,
    ) -> OriginScanResult:
        """
        Scan origin IPs with aggressive nuclei templates.

        Args:
            origin_ips: List of origin IP addresses
            severity: Severity levels to include (default: all)
            extra_tags: Additional tags to include
            extra_exclude_tags: Additional tags to exclude
            custom_templates: Custom template paths

        Returns:
            OriginScanResult with findings
        """
        result = OriginScanResult(
            domain=self.domain,
            origin_ips=origin_ips,
        )

        if not origin_ips:
            logger.warning("No origin IPs provided for scanning")
            return result

        # Build target URLs with Host header notation
        targets = []
        for ip in origin_ips:
            # Scan both HTTP and HTTPS
            targets.append(f"https://{ip}")
            targets.append(f"http://{ip}")

        # First, detect versions
        logger.info(f"Detecting versions on {len(origin_ips)} origin IPs...")
        version_info = await self._detect_versions(origin_ips)
        result.version_info = version_info

        # Run main scan
        logger.info(f"Running aggressive nuclei scan against {len(origin_ips)} origin IPs...")

        findings, stats = await self._run_nuclei_scan(
            targets=targets,
            severity=severity or ["info", "low", "medium", "high", "critical"],
            extra_tags=extra_tags,
            extra_exclude_tags=extra_exclude_tags,
            custom_templates=custom_templates,
        )

        result.findings = findings
        result.scan_stats = stats

        # Log summary
        summary = result.to_dict()["summary"]
        logger.info(
            f"Origin scan complete: {summary['total_findings']} findings "
            f"(C:{summary['critical']} H:{summary['high']} M:{summary['medium']} "
            f"L:{summary['low']} I:{summary['info']})"
        )

        return result

    async def _detect_versions(self, ips: list[str]) -> dict[str, str]:
        """Detect software versions from headers."""
        import httpx

        versions = {}

        async def check_ip(ip: str):
            try:
                async with httpx.AsyncClient(timeout=10, verify=False) as client:
                    for scheme in ["https", "http"]:
                        try:
                            response = await client.get(
                                f"{scheme}://{ip}",
                                headers={"Host": self.domain},
                            )

                            # Extract version info from headers
                            server = response.headers.get("server", "")
                            powered_by = response.headers.get("x-powered-by", "")

                            if server:
                                versions[f"{ip}_server"] = server
                            if powered_by:
                                versions[f"{ip}_powered_by"] = powered_by

                            # Also check common version headers
                            for header in ["x-aspnet-version", "x-aspnetmvc-version",
                                          "x-generator", "x-drupal-cache", "x-varnish"]:
                                val = response.headers.get(header, "")
                                if val:
                                    versions[f"{ip}_{header}"] = val

                            break  # Success, don't try other scheme

                        except Exception:
                            continue

            except Exception as e:
                logger.debug(f"Version detection failed for {ip}: {e}")

        await asyncio.gather(*[check_ip(ip) for ip in ips])
        return versions

    async def _run_nuclei_scan(
        self,
        targets: list[str],
        severity: list[str],
        extra_tags: list[str] = None,
        extra_exclude_tags: list[str] = None,
        custom_templates: list[str] = None,
    ) -> tuple[list[OriginFinding], dict]:
        """Run nuclei scan with aggressive settings."""

        findings = []
        stats = {"templates": 0, "requests": 0, "errors": 0}

        # Create temp file for targets
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            for target in targets:
                f.write(f"{target}\n")
            targets_file = f.name

        # Create temp file for output
        output_file = tempfile.mktemp(suffix=".json")

        try:
            # Build nuclei command
            cmd = [
                self.nuclei_path,
                "-l", targets_file,
                "-H", f"Host: {self.domain}",
                "-severity", ",".join(severity),
                "-rl", str(self.rate_limit),
                "-c", str(self.concurrency),
                "-timeout", str(self.timeout),
                "-retries", str(self.retries),
                "-no-interactsh",
                "-silent",
                "-j",
                "-o", output_file,
            ]

            # Use template directories for better performance
            nuclei_templates = Path.home() / "nuclei-templates"
            templates_added = False

            for tpl_dir in self.TEMPLATE_DIRS:
                full_path = nuclei_templates / tpl_dir
                if full_path.exists():
                    cmd.extend(["-t", str(full_path)])
                    templates_added = True

            # Fall back to tags if no template dirs found
            if not templates_added:
                all_tags = self.AGGRESSIVE_TAGS.copy()
                if extra_tags:
                    all_tags.extend(extra_tags)
                cmd.extend(["-tags", ",".join(all_tags)])

            # Add exclude tags
            all_exclude = self.EXCLUDE_TAGS.copy()
            if extra_exclude_tags:
                all_exclude.extend(extra_exclude_tags)
            cmd.extend(["-exclude-tags", ",".join(all_exclude)])

            # Add custom templates
            if custom_templates:
                for tpl in custom_templates:
                    cmd.extend(["-t", tpl])

            logger.debug(f"Running nuclei: {' '.join(cmd)}")

            # Run nuclei
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=600,  # 10 minute max
            )

            if proc.returncode != 0 and stderr:
                logger.warning(f"Nuclei stderr: {stderr.decode()[:500]}")

            # Parse output
            if Path(output_file).exists():
                with open(output_file) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            finding = self._parse_finding(data)
                            if finding:
                                findings.append(finding)
                        except json.JSONDecodeError:
                            continue

            stats["findings"] = len(findings)

        except asyncio.TimeoutError:
            logger.error("Nuclei scan timed out after 10 minutes")
            stats["errors"] = 1
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            stats["errors"] = 1
        finally:
            # Cleanup
            Path(targets_file).unlink(missing_ok=True)
            Path(output_file).unlink(missing_ok=True)

        return findings, stats

    def _parse_finding(self, data: dict) -> Optional[OriginFinding]:
        """Parse nuclei JSON output into OriginFinding."""
        try:
            info = data.get("info", {})

            # Extract IP from host
            host = data.get("host", "")
            ip = host.replace("https://", "").replace("http://", "").split(":")[0]

            return OriginFinding(
                template_id=data.get("template-id", ""),
                name=info.get("name", ""),
                severity=info.get("severity", "info"),
                ip=ip,
                host=self.domain,
                matched_at=data.get("matched-at", host),
                description=info.get("description", ""),
                tags=info.get("tags", []),
                reference=info.get("reference", []),
                extracted=data.get("extracted-results", {}),
                raw=data,
            )
        except Exception as e:
            logger.debug(f"Failed to parse finding: {e}")
            return None


async def scan_origin_ips(
    domain: str,
    origin_ips: list[str],
    rate_limit: int = 150,
    severity: list[str] = None,
) -> OriginScanResult:
    """
    Convenience function to scan origin IPs.

    Args:
        domain: Target domain
        origin_ips: List of origin IPs to scan
        rate_limit: Requests per second
        severity: Severity levels (default: all)

    Returns:
        OriginScanResult
    """
    scanner = OriginScanner(domain=domain, rate_limit=rate_limit)
    return await scanner.scan(origin_ips, severity=severity)
