"""AI-powered GAU Target Selector Agent.

This agent analyzes live hosts and selects high-value targets for
historical URL mining via GAU. Instead of scanning all 500+ hosts,
it identifies the most interesting targets based on:
1. Hostname patterns (api.*, admin.*, portal.*, etc.)
2. Detected technologies (WordPress, APIs, admin panels)
3. Response characteristics (login pages, dashboards)
4. Environment classification (production vs dev/staging)

Security Notes:
    - All host data is sanitized before prompt injection
    - Uses Claude Code CLI (haiku for speed/efficiency)
    - Limits output to prevent context overflow
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from reconductor.core.logger import get_logger

logger = get_logger(__name__)

# Maximum hosts to include in prompt (context limit)
MAX_HOSTS_IN_PROMPT = 200
MAX_PROMPT_LENGTH = 40000  # Haiku handles 200K tokens, 40K chars is safe
MAX_TARGETS_OUTPUT = 50

# Pre-compiled patterns for high-value target detection
RE_HIGH_VALUE_NAMES = re.compile(
    r'(^api[-.]|[-.]api[.-]|^admin[-.]|[-.]admin[.-]|'
    r'^portal[-.]|[-.]portal[.-]|^dashboard[-.]|[-.]dashboard[.-]|'
    r'^auth[-.]|[-.]auth[.-]|^login[-.]|[-.]login[.-]|'
    r'^sso[-.]|[-.]sso[.-]|^oauth[-.]|[-.]oauth[.-]|'
    r'^app[-.]|[-.]app[.-]|^cms[-.]|[-.]cms[.-]|'
    r'^upload[-.]|[-.]upload[.-]|^file[-.]|[-.]file[.-]|'
    r'^internal[-.]|[-.]internal[.-]|^intranet[-.]|'
    r'^dev[-.]|[-.]dev[.-]|^staging[-.]|[-.]staging[.-]|'
    r'^test[-.]|[-.]test[.-]|^uat[-.]|[-.]uat[.-]|'
    r'^jenkins[-.]|^gitlab[-.]|^jira[-.]|^confluence[-.]|'
    r'^grafana[-.]|^kibana[-.]|^prometheus[-.])',
    re.IGNORECASE
)

RE_HIGH_VALUE_TECH = re.compile(
    r'(wordpress|drupal|joomla|magento|shopify|'
    r'jenkins|gitlab|bitbucket|jira|confluence|'
    r'grafana|kibana|elasticsearch|prometheus|'
    r'phpmyadmin|adminer|pgadmin|'
    r'tomcat|weblogic|jboss|'
    r'struts|spring|laravel|django|rails|'
    r'angular|react|vue|'
    r'swagger|graphql|api|rest)',
    re.IGNORECASE
)

# The agent prompt - structured with few-shot example for reliable JSON output
GAU_TARGET_AGENT_PROMPT = """Select hostnames for Wayback Machine archival lookup.

INPUT FORMAT:
- h: hostname
- s: HTTP status code
- t: page title (if available)
- tech: detected technologies (if available)

SELECTION CRITERIA (priority order):

By HOSTNAME pattern:
1. API endpoints (api.*, swagger, graphql, rest, /v1/)
2. Admin interfaces (admin.*, panel.*, dashboard.*, manage.*)
3. Auth systems (auth.*, login.*, sso.*, oauth.*, accounts.*)
4. Dev/staging (dev.*, staging.*, test.*, uat.*, beta.*, sandbox.*)
5. DevOps tools (jenkins.*, gitlab.*, grafana.*, kibana.*, prometheus.*)

By TECHNOLOGY (high CVE count - prioritize these):
- Java frameworks: Struts, Spring, WebLogic, JBoss, Tomcat
- CMS: WordPress, Drupal, Joomla, Magento, Typo3
- Collaboration: Jira, Confluence, SharePoint, GitLab
- PHP apps: phpMyAdmin, Laravel, Symfony

SKIP: Static assets, CDNs (CloudFront, Cloudflare, Akamai), pure nginx/Apache without apps

EXAMPLE:
Input: {{"h":"api.acme.com","s":200,"tech":["Swagger"]}},{{"h":"www.acme.com","s":200}},{{"h":"cdn.acme.com","s":200,"cdn":"Cloudflare"}},{{"h":"app.acme.com","s":200,"tech":["Struts"]}}
Output: ["api.acme.com","app.acme.com"]

Select up to {max_targets} from:
{hosts_json}

JSON array only:"""


@dataclass
class TargetSelectionResult:
    """Result from GAU target selection."""
    domain: str
    total_hosts: int
    selected_targets: list[str] = field(default_factory=list)
    selection_reasoning: dict[str, str] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)


class GauTargetAgent:
    """
    AI-powered agent that selects high-value targets for GAU scanning.

    Instead of running GAU on all live hosts (which could be 500+),
    this agent analyzes hosts and picks the most interesting ones
    for historical URL mining.
    """

    def __init__(
        self,
        model: str = "haiku",
        timeout: int = 60,
        max_targets: int = 30,
    ):
        """
        Initialize the GAU target selector agent.

        Args:
            model: Claude model to use (haiku for speed)
            timeout: Timeout for Claude Code CLI
            max_targets: Maximum targets to select
        """
        self.model = model
        self.timeout = timeout
        self.max_targets = min(max_targets, MAX_TARGETS_OUTPUT)
        self._claude_path: Optional[str] = shutil.which("claude")

    async def select_targets(
        self,
        domain: str,
        hosts: list[dict[str, Any]],
        fallback_on_error: bool = True,
    ) -> TargetSelectionResult:
        """
        Select high-value targets for GAU scanning.

        Args:
            domain: Target domain
            hosts: List of host dictionaries from httpx probe
            fallback_on_error: Use heuristic fallback if AI fails

        Returns:
            TargetSelectionResult with selected targets
        """
        result = TargetSelectionResult(
            domain=domain,
            total_hosts=len(hosts),
        )

        if not hosts:
            logger.warning("No hosts provided for target selection")
            return result

        logger.info(f"Selecting high-value GAU targets from {len(hosts)} hosts")

        # First, apply heuristic pre-filtering to reduce AI workload
        heuristic_candidates = self._heuristic_filter(hosts)
        result.stats["heuristic_candidates"] = len(heuristic_candidates)

        # If we have few enough candidates, skip AI
        if len(heuristic_candidates) <= self.max_targets:
            logger.info(f"Heuristic filter sufficient: {len(heuristic_candidates)} candidates")
            result.selected_targets = [h.get("hostname", "") for h in heuristic_candidates]
            result.stats["method"] = "heuristic_only"
            return result

        # Use AI to prioritize among candidates
        if self._claude_path:
            ai_targets = await self._ai_select(domain, heuristic_candidates)
            if ai_targets:
                result.selected_targets = ai_targets[:self.max_targets]
                result.stats["method"] = "ai_prioritized"
                logger.info(f"AI selected {len(result.selected_targets)} targets")
                return result

        # Fallback to heuristic selection
        if fallback_on_error:
            logger.info("Falling back to heuristic target selection")
            result.selected_targets = self._heuristic_select(heuristic_candidates)
            result.stats["method"] = "heuristic_fallback"

        return result

    def _heuristic_filter(self, hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Apply heuristic filters to identify potential high-value targets."""
        candidates = []

        for host in hosts:
            hostname = host.get("hostname", "").lower()
            title = (host.get("title") or "").lower()
            tech = " ".join(host.get("technologies", [])).lower()
            status = host.get("status_code", 0)

            score = 0
            reasons = []

            # Check hostname patterns
            if RE_HIGH_VALUE_NAMES.search(hostname):
                score += 3
                reasons.append("high_value_name")

            # Check technologies
            if RE_HIGH_VALUE_TECH.search(tech):
                score += 2
                reasons.append("interesting_tech")

            # Check title for interesting keywords
            if any(kw in title for kw in ["admin", "login", "dashboard", "portal", "panel", "api", "upload"]):
                score += 2
                reasons.append("interesting_title")

            # Non-standard status codes might indicate interesting behavior
            if status not in [200, 301, 302, 403]:
                score += 1
                reasons.append("non_standard_status")

            # Hosts without CDN are more interesting (direct access)
            if not host.get("cdn_provider"):
                score += 1
                reasons.append("no_cdn")

            if score > 0:
                host["_gau_score"] = score
                host["_gau_reasons"] = reasons
                candidates.append(host)

        # Sort by score descending
        candidates.sort(key=lambda h: h.get("_gau_score", 0), reverse=True)

        return candidates[:MAX_HOSTS_IN_PROMPT]

    def _heuristic_select(self, candidates: list[dict[str, Any]]) -> list[str]:
        """Select targets using heuristics only (no AI)."""
        # Already sorted by score from _heuristic_filter
        selected = []
        for host in candidates[:self.max_targets]:
            hostname = host.get("hostname", "")
            if hostname:
                selected.append(hostname)
        return selected

    async def _ai_select(
        self,
        domain: str,
        candidates: list[dict[str, Any]],
    ) -> list[str]:
        """Use AI to prioritize and select targets."""
        # Build compact host summaries for the prompt
        # Strip common domain suffix to reduce token usage
        domain_suffix = f".{domain}"

        def build_summaries(hosts: list[dict]) -> list[dict]:
            summaries = []
            for host in hosts:
                hostname = host.get("hostname", "")
                # Strip domain suffix for compactness (e.g., "api.example.com" -> "api")
                short_host = hostname[:-len(domain_suffix)] if hostname.endswith(domain_suffix) else hostname
                summary = {
                    "h": short_host,
                    "s": host.get("status_code", 0),
                }
                if host.get("title"):
                    summary["t"] = host["title"][:40]  # Shorter titles
                if host.get("technologies"):
                    summary["tech"] = host["technologies"][:2]  # Fewer techs
                if host.get("cdn_provider"):
                    summary["cdn"] = host["cdn_provider"]
                summaries.append(summary)
            return summaries

        # Start with max hosts, iteratively reduce if needed
        num_hosts = min(MAX_HOSTS_IN_PROMPT, len(candidates))
        prompt = ""

        while num_hosts >= 20:  # Minimum useful batch
            host_summaries = build_summaries(candidates[:num_hosts])
            hosts_json = json.dumps(host_summaries, separators=(',', ':'))

            prompt = GAU_TARGET_AGENT_PROMPT.format(
                domain=domain,
                total_hosts=len(candidates),
                max_targets=self.max_targets,
                hosts_json=hosts_json,
            )

            if len(prompt) <= MAX_PROMPT_LENGTH:
                break

            # Reduce by 30% and retry
            old_num = num_hosts
            num_hosts = int(num_hosts * 0.7)
            logger.warning(f"Prompt too long ({len(prompt)} chars), reducing hosts {old_num} -> {num_hosts}")

        if len(prompt) > MAX_PROMPT_LENGTH:
            logger.error(f"Cannot reduce prompt below limit, using heuristic fallback")
            return []

        logger.debug(f"Final prompt: {len(prompt)} chars for {num_hosts} hosts")

        # Invoke Claude Code CLI
        raw_output = await self._invoke_claude(prompt)
        if not raw_output:
            return []

        # Parse JSON array from output - restore full hostnames
        short_targets = self._parse_target_list(raw_output)
        full_targets = []
        for t in short_targets:
            # Restore domain suffix if it was stripped
            if not t.endswith(domain_suffix) and "." not in t:
                full_targets.append(f"{t}{domain_suffix}")
            else:
                full_targets.append(t)
        return full_targets

    async def _invoke_claude(self, prompt: str) -> str:
        """Invoke Claude Code CLI."""
        if not self._claude_path:
            logger.warning("Claude Code CLI not found")
            return ""

        process = None
        try:
            cmd = [
                self._claude_path,
                "--print",
                "-p", prompt,
                "--model", self.model,
                "--max-turns", "1",
            ]

            logger.info(f"Invoking Claude ({self.model}) for GAU target selection...")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=self.timeout,
            )

            result = stdout.decode("utf-8", errors="replace").strip()

            if process.returncode == 0 and result:
                logger.info(f"Claude returned {len(result)} chars")
                return result
            else:
                stderr_text = stderr.decode("utf-8", errors="replace")
                logger.warning(f"Claude failed: code={process.returncode}, stderr={stderr_text[:100]}")

        except asyncio.TimeoutError:
            logger.warning("Claude Code timeout")
            if process:
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass

        except Exception as e:
            logger.warning(f"Claude Code exception: {e}")
            if process:
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass

        return ""

    def _parse_target_list(self, raw_output: str) -> list[str]:
        """Parse JSON array of hostnames from LLM output."""
        targets = []

        # Try to find JSON array in output
        # Handle markdown code blocks
        output = raw_output.strip()
        if "```" in output:
            # Extract content between code blocks
            match = re.search(r'```(?:json)?\s*([\s\S]*?)```', output)
            if match:
                output = match.group(1).strip()

        # Try to parse as JSON array
        try:
            parsed = json.loads(output)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, str) and item.strip():
                        targets.append(item.strip())
        except json.JSONDecodeError:
            # Try to extract hostnames line by line
            for line in output.split("\n"):
                line = line.strip().strip('"').strip("'").strip(",").strip("[").strip("]")
                if line and "." in line and not line.startswith("#"):
                    targets.append(line)

        # Deduplicate while preserving order
        seen = set()
        unique_targets = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                unique_targets.append(t)

        return unique_targets[:self.max_targets]


async def select_gau_targets(
    domain: str,
    hosts: list[dict[str, Any]],
    max_targets: int = 30,
) -> list[str]:
    """
    Convenience function to select GAU targets.

    Args:
        domain: Target domain
        hosts: List of host dictionaries
        max_targets: Maximum targets to select

    Returns:
        List of hostnames to scan with GAU
    """
    agent = GauTargetAgent(max_targets=max_targets)
    result = await agent.select_targets(domain, hosts)
    return result.selected_targets
