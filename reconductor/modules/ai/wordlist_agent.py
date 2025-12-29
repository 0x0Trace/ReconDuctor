"""Wordlist Generator Agent using Claude Code CLI in headless mode.

This agent orchestrates intelligent subdomain wordlist generation by:
1. Gathering intelligence from multiple sources (CT logs, Wayback, etc.)
2. Analyzing patterns in discovered subdomains
3. Using Claude Code CLI (headless) to generate targeted wordlists
4. Validating and deduplicating results

Security Notes:
    - Prompt context is sanitized to prevent injection
    - Processes are killed on timeout to prevent resource leaks
    - All inputs are validated before processing
"""

from __future__ import annotations

import asyncio
import json
import random
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from reconductor.core.logger import get_logger
from reconductor.modules.ai.intelligence_gatherer import (
    DomainIntelligence,
    IntelligenceGatherer,
)

logger = get_logger(__name__)

# Pre-compiled regex for validation
RE_VALID_PREFIX = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$')
RE_LLM_ARTIFACTS = re.compile(r'^[\d]+[.\)]\s*|^[-*]\s*|`')

# Limits - conservative to prevent context overflow
MAX_PROMPT_LENGTH = 15000  # ~3750 tokens, well under haiku's limit
MAX_WORDLIST_SIZE = 10000
MAX_INTEL_SUBS = 40  # Max subdomains from intel sources
MAX_PRIOR_HITS = 20  # Max prior successful predictions


# The agent prompt - compact JSON format for efficiency
WORDLIST_AGENT_PROMPT = """<role>Subdomain wordlist generator for security recon</role>
<intel>{intelligence_json}</intel>
<task>Generate {count} subdomain prefixes based on intel patterns</task>
<rules>
- Output ONLY prefixes, one per line, no explanations
- Lowercase letters, numbers, hyphens only (no underscores)
- 1-63 chars, start/end alphanumeric
- No duplicates
</rules>
<priority>1.Variations of existing 2.Tech-specific 3.Industry-specific 4.Common(api,admin,vpn) 5.Numbered/regional</priority>
<output>{count} prefixes, one per line:</output>"""


@dataclass
class WordlistResult:
    """Result from wordlist generation."""

    domain: str
    wordlist: list[str]
    intelligence: DomainIntelligence
    stats: dict = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.wordlist)

    def get_llm_contribution(self) -> dict:
        """Get statistics about LLM contribution to the wordlist."""
        base_count = self.stats.get("base_wordlist_count", 0)
        llm_count = self.stats.get("llm_generated_valid", 0)
        total = self.count

        return {
            "total_wordlist": total,
            "from_llm": llm_count,
            "from_base": base_count,
            "from_intelligence": self.stats.get("from_intelligence", 0),
            "llm_percentage": round(llm_count / total * 100, 1) if total > 0 else 0,
        }


class WordlistGeneratorAgent:
    """
    AI-powered wordlist generator agent using Claude Code CLI.

    This agent provides consistent, high-quality subdomain wordlists by:
    1. Gathering intelligence from CT logs, Wayback Machine, etc.
    2. Analyzing naming patterns and technologies
    3. Using Claude Code (haiku for speed/efficiency) to generate targeted wordlists
    4. Validating output for DNS compliance
    """

    # Base wordlist - common subdomain prefixes
    BASE_WORDLIST = [
        "admin", "api", "app", "auth", "backup", "beta", "blog", "cdn",
        "ci", "cms", "console", "dashboard", "db", "demo", "dev", "docs",
        "email", "ftp", "git", "gitlab", "grafana", "internal", "intranet",
        "jenkins", "jira", "k8s", "login", "mail", "metrics", "monitor",
        "mysql", "new", "ns1", "ns2", "old", "panel", "portal", "prod",
        "production", "prometheus", "proxy", "qa", "redis", "server",
        "shop", "smtp", "sso", "staging", "static", "status", "store",
        "support", "test", "uat", "upload", "vault", "vpn", "web", "www",
    ]

    def __init__(
        self,
        model: str = "haiku",  # Use haiku for speed and cost efficiency
        timeout: int = 60,  # Reduced timeout - haiku is fast
        max_retries: int = 2,
    ):
        """
        Initialize the wordlist generator agent.

        Args:
            model: Claude model to use (haiku recommended for efficiency)
            timeout: Timeout for Claude Code CLI execution
            max_retries: Maximum retries on failure

        Raises:
            ValueError: If parameters are invalid
        """
        if timeout < 30 or timeout > 600:
            raise ValueError("timeout must be between 30 and 600 seconds")
        if max_retries < 0 or max_retries > 5:
            raise ValueError("max_retries must be between 0 and 5")

        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        self.intel_gatherer = IntelligenceGatherer()

        # Cache claude path
        self._claude_path: Optional[str] = shutil.which("claude")

    async def generate(
        self,
        domain: str,
        existing_subdomains: Optional[list[str]] = None,
        count: int = 200,
        include_base_wordlist: bool = True,
    ) -> WordlistResult:
        """
        Generate an intelligent wordlist for a domain.

        Args:
            domain: Target domain
            existing_subdomains: Already discovered subdomains
            count: Number of wordlist entries to generate
            include_base_wordlist: Include common base wordlist

        Returns:
            WordlistResult with generated wordlist and metadata
        """
        # Validate domain
        if not self._is_valid_domain(domain):
            logger.error(f"Invalid domain: {domain}")
            return WordlistResult(
                domain=domain,
                wordlist=[],
                intelligence=DomainIntelligence(domain=domain),
                stats={"error": "Invalid domain"},
            )

        # Validate count
        count = max(10, min(count, 1000))

        logger.info(f"Starting wordlist generation for {domain}")

        stats: dict = {
            "requested_count": count,
            "domain": domain,
        }

        # Step 1: Gather intelligence
        logger.info("Gathering intelligence from CT logs, Wayback, etc.")
        intel = await self.intel_gatherer.gather(
            domain=domain,
            existing_subdomains=existing_subdomains or [],
        )
        stats["ct_subdomains"] = len(intel.ct_subdomains)
        stats["wayback_subdomains"] = len(intel.wayback_subdomains)

        # Step 2: Load previous successful AI predictions (feedback loop)
        prior_successes = self._load_prior_successes(domain)
        if prior_successes:
            stats["prior_successes_loaded"] = len(prior_successes)
            logger.info(f"Loaded {len(prior_successes)} prior successful AI predictions")

        # Step 3: Build compact JSON intelligence context
        # This is much more token-efficient than verbose text
        # Use conservative limits to prevent context overflow
        intel_subs = (intel.ct_subdomains + intel.wayback_subdomains)[:MAX_INTEL_SUBS]
        intel_json = {
            "domain": domain,
            "subs": intel_subs,
            "patterns": intel.detected_patterns[:5],
            "tech": intel.technologies[:8],
            "industry": intel.industry_hints[:3],
            "prefixes": intel.common_prefixes[:15],
        }
        # Add prior successful predictions to guide AI (limited)
        if prior_successes:
            intel_json["prior_hits"] = prior_successes[:MAX_PRIOR_HITS]
        # Compact JSON (no spaces)
        intel_str = json.dumps(intel_json, separators=(',', ':'))

        prompt = WORDLIST_AGENT_PROMPT.format(
            intelligence_json=intel_str,
            count=count,
        )

        # Validate prompt length and estimate tokens
        estimated_tokens = len(prompt) // 4  # Rough estimate: 4 chars per token
        logger.debug(f"Prompt: {len(prompt)} chars, ~{estimated_tokens} tokens")

        if len(prompt) > MAX_PROMPT_LENGTH:
            logger.warning(f"Prompt too long ({len(prompt)} chars, ~{estimated_tokens} tokens), truncating")
            # Aggressively reduce context
            intel_json["subs"] = intel_json["subs"][:15]
            intel_json["prefixes"] = intel_json.get("prefixes", [])[:10]
            intel_json.pop("prior_hits", None)  # Remove prior hits if still too long
            intel_str = json.dumps(intel_json, separators=(',', ':'))
            prompt = WORDLIST_AGENT_PROMPT.format(
                intelligence_json=intel_str,
                count=count,
            )
            logger.info(f"Truncated prompt: {len(prompt)} chars")

        # Step 3: Generate wordlist using Claude Code CLI
        logger.info("Invoking Claude Code CLI for wordlist generation")
        raw_output = await self._invoke_claude_code(prompt)

        llm_generated: list[str] = []
        if raw_output:
            llm_generated = self._validate_and_clean(raw_output)
            stats["llm_raw_lines"] = raw_output.count("\n") + 1
            stats["llm_generated_valid"] = len(llm_generated)
            logger.info(f"LLM generated {len(llm_generated)} valid prefixes")
        else:
            logger.warning("Claude Code returned empty output, using fallback")
            stats["llm_generated_valid"] = 0

        # Step 4: Combine sources
        all_prefixes: set[str] = set()

        # Add LLM generated
        all_prefixes.update(llm_generated)

        # Add from intelligence (CT logs + Wayback)
        intel_prefixes = set(intel.ct_subdomains + intel.wayback_subdomains)
        stats["from_intelligence"] = len(intel_prefixes)
        all_prefixes.update(intel_prefixes)

        # Add base wordlist if requested
        if include_base_wordlist:
            all_prefixes.update(self.BASE_WORDLIST)
            stats["base_wordlist_count"] = len(self.BASE_WORDLIST)
        else:
            stats["base_wordlist_count"] = 0

        # Step 5: Remove already-known subdomains
        existing_set = set(existing_subdomains or [])
        stats["existing_count"] = len(existing_set)
        all_prefixes -= existing_set

        # Step 6: Final validation and sort
        wordlist = sorted([
            p for p in all_prefixes
            if self._is_valid_prefix(p)
        ])[:MAX_WORDLIST_SIZE]

        stats["final_wordlist_count"] = len(wordlist)
        stats["patterns_detected"] = len(intel.detected_patterns)
        stats["technologies_detected"] = len(intel.technologies)

        logger.info(
            f"Wordlist generation complete for {domain}",
            total=len(wordlist),
            llm_contribution=stats.get("llm_generated_valid", 0),
        )

        return WordlistResult(
            domain=domain,
            wordlist=wordlist,
            intelligence=intel,
            stats=stats,
        )

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain name format."""
        if not domain or len(domain) > 253:
            return False
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))

    async def _invoke_claude_code(self, prompt: str) -> str:
        """Invoke Claude Code CLI in headless mode with proper cleanup."""
        if not self._claude_path:
            logger.warning("Claude Code CLI not found in PATH - AI wordlist skipped")
            return ""

        for attempt in range(self.max_retries + 1):
            process: Optional[asyncio.subprocess.Process] = None

            try:
                cmd = [
                    self._claude_path,
                    "--print",
                    "-p", prompt,
                    "--model", self.model,
                    "--max-turns", "1",
                ]

                logger.info(f"Invoking Claude ({self.model}) for wordlist generation...")

                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout,
                )

                # Decode with error handling
                result = stdout.decode("utf-8", errors="replace").strip()
                stderr_text = stderr.decode("utf-8", errors="replace").strip()

                if stderr_text:
                    logger.warning(f"Claude stderr: {stderr_text[:300]}")

                if process.returncode == 0 and result:
                    logger.info(f"Claude returned {len(result)} chars, {result.count(chr(10)) + 1} lines")
                    return result
                elif process.returncode == 0 and not result:
                    logger.warning("Claude returned empty output")
                else:
                    logger.warning(
                        f"Claude failed (attempt {attempt + 1}/{self.max_retries + 1}): "
                        f"code={process.returncode}, stderr={stderr_text[:100]}"
                    )

            except asyncio.TimeoutError:
                logger.warning(f"Claude Code timeout (attempt {attempt + 1})")
                # CRITICAL: Kill the process to prevent resource leak
                if process is not None:
                    try:
                        process.kill()
                        await process.wait()
                    except Exception:
                        pass

            except Exception as e:
                logger.warning(f"Claude Code exception (attempt {attempt + 1}): {e}")
                if process is not None:
                    try:
                        process.kill()
                        await process.wait()
                    except Exception:
                        pass

            if attempt < self.max_retries:
                # Exponential backoff with jitter
                delay = (2 ** attempt) + random.uniform(0, 1)
                await asyncio.sleep(delay)

        return ""

    def _validate_and_clean(self, raw_output: str) -> list[str]:
        """Validate and clean LLM output into valid subdomain prefixes."""
        valid: list[str] = []
        seen: set[str] = set()

        for line in raw_output.strip().split("\n")[:MAX_WORDLIST_SIZE]:
            # Clean the line
            prefix = line.strip().lower()

            # Remove common LLM artifacts
            prefix = RE_LLM_ARTIFACTS.sub('', prefix)
            prefix = prefix.strip()

            # Skip empty or already seen
            if not prefix or prefix in seen:
                continue

            # Validate DNS compliance
            if self._is_valid_prefix(prefix):
                valid.append(prefix)
                seen.add(prefix)

        return valid

    def _is_valid_prefix(self, prefix: str) -> bool:
        """Check if prefix is a valid DNS subdomain component."""
        if not prefix or len(prefix) > 63:
            return False

        # Must start and end with alphanumeric
        if not prefix[0].isalnum() or not prefix[-1].isalnum():
            return False

        # Use pre-compiled regex
        return bool(RE_VALID_PREFIX.match(prefix))

    async def enhance_existing(
        self,
        domain: str,
        existing_wordlist: list[str],
        count: int = 100,
    ) -> WordlistResult:
        """
        Enhance an existing wordlist with AI-generated additions.

        Args:
            domain: Target domain
            existing_wordlist: Current wordlist to enhance
            count: Number of new entries to generate

        Returns:
            Enhanced wordlist result
        """
        result = await self.generate(
            domain=domain,
            existing_subdomains=existing_wordlist,
            count=count,
            include_base_wordlist=False,
        )

        # Merge with existing
        original_count = len(existing_wordlist)
        result.wordlist = sorted(set(existing_wordlist + result.wordlist))
        result.stats["original_count"] = original_count
        result.stats["enhanced_count"] = len(result.wordlist)
        result.stats["added"] = len(result.wordlist) - original_count

        return result

    def _load_prior_successes(self, domain: str) -> list[str]:
        """Load previously successful AI predictions for this domain."""
        try:
            # Check common output locations
            feedback_paths = [
                Path(f"output/{domain}/ai_feedback/successful_prefixes.txt"),
                Path(f"~/.reconductor/ai_feedback/{domain}.txt").expanduser(),
            ]

            for path in feedback_paths:
                if path.exists():
                    content = path.read_text().strip()
                    if content:
                        prefixes = [p.strip() for p in content.split("\n") if p.strip()]
                        return prefixes[:50]  # Limit to 50 for context size

        except Exception as e:
            logger.debug(f"Could not load prior successes: {e}")

        return []

    def save_wordlist(
        self,
        result: WordlistResult,
        output_path: Path,
    ) -> None:
        """Save wordlist to file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(result.wordlist))
        logger.info(f"Wordlist saved to {output_path} ({result.count} entries)")


async def generate_wordlist(
    domain: str,
    existing_subdomains: Optional[list[str]] = None,
    count: int = 200,
    output_path: Optional[Path] = None,
) -> WordlistResult:
    """
    Convenience function to generate a wordlist.

    Args:
        domain: Target domain
        existing_subdomains: Known subdomains for context
        count: Number of entries to generate
        output_path: Optional path to save wordlist

    Returns:
        WordlistResult with generated wordlist
    """
    agent = WordlistGeneratorAgent()
    result = await agent.generate(
        domain=domain,
        existing_subdomains=existing_subdomains,
        count=count,
    )

    if output_path:
        agent.save_wordlist(result, output_path)

    return result
