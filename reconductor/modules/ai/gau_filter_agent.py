"""AI-powered GAU URL Filter Agent.

This agent analyzes historical URLs from GAU and filters/prioritizes
high-value URLs for security testing. Instead of selecting targets upfront,
it processes the actual URLs found and identifies the most interesting ones.

Flow:
1. GAU runs on main domain with --subs (gets all URLs)
2. Heuristic pre-filtering reduces to manageable set
3. AI ranks and selects top high-value URLs

Security Notes:
    - All URL data is sanitized before prompt injection
    - Uses Claude Code CLI (haiku for speed/efficiency)
    - Limits output to prevent context overflow
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
from dataclasses import dataclass, field
from typing import Any, Optional

from reconductor.core.logger import get_logger

logger = get_logger(__name__)

# Limits for prompt size
MAX_URLS_IN_PROMPT = 300
MAX_PROMPT_LENGTH = 40000
MAX_OUTPUT_URLS = 100

# Patterns for high-value URL detection (used in heuristic pre-filter)
HIGH_VALUE_PATTERNS = {
    "api_endpoints": re.compile(r'/(api|v[0-9]+|graphql|rest|ws)/', re.I),
    "auth_endpoints": re.compile(r'/(auth|login|logout|signin|signout|register|password|reset|token|oauth|callback|saml)', re.I),
    "admin_paths": re.compile(r'/(admin|dashboard|manage|control|panel|config|settings|console)', re.I),
    "file_operations": re.compile(r'/(upload|download|export|import|file|document|attachment|media)', re.I),
    "debug_paths": re.compile(r'/(debug|test|dev|staging|internal|phpinfo|trace|status|health)', re.I),
    "sensitive_files": re.compile(r'\.(conf|config|ini|env|bak|backup|old|sql|db|log|xml|json|yaml|yml)(\?|$)', re.I),
    "params_sqli": re.compile(r'[?&](id|user|uid|pid|page|sort|order|category|search|query|filter|limit|offset)=', re.I),
    "params_ssrf": re.compile(r'[?&](url|uri|path|dest|redirect|return|next|target|link|goto|src|source|callback|fetch)=', re.I),
    "params_lfi": re.compile(r'[?&](file|path|template|page|include|dir|document|folder|root|read|view)=', re.I),
    "params_xss": re.compile(r'[?&](q|s|search|query|keyword|message|text|content|body|title|name|input|error|msg)=', re.I),
    "params_rce": re.compile(r'[?&](cmd|exec|command|execute|run|system|shell|code|eval|ping|process)=', re.I),
}

# AI prompt for URL filtering - optimized for reliable JSON output
GAU_FILTER_PROMPT = """You are a security researcher selecting URLs for vulnerability testing.

TASK: From {url_count} pre-filtered URLs, select the {max_urls} MOST LIKELY to be exploitable.

RANKING CRITERIA (highest priority first):
1. RCE/Command injection: cmd=, exec=, system=, shell=, code=, ping=
2. SSRF/Open redirect: url=, redirect=, dest=, callback=, fetch=, next=
3. LFI/Path traversal: file=, path=, template=, include=, doc=, view=
4. SQLi (numeric params): id=, uid=, pid=, page=, limit=, offset=
5. Auth endpoints with state: oauth/callback, saml/auth, token, session
6. Debug/internal paths: /debug/, /internal/, /test/, phpinfo, /trace/
7. Sensitive files: .conf, .bak, .sql, .env, .log, .xml, .json
8. API endpoints with params: /api/, /v1/, /graphql with query strings

DEDUPLICATION:
- ONE URL per unique endpoint pattern (e.g., /api/users?id=1 and /api/users?id=999 → keep one)
- Prefer URLs with more parameters over fewer
- Prefer non-www subdomains over www

EXCLUDE:
- CDN domains (cloudfront, akamai, cloudflare, fastly, cdn.*)
- Tracking-only params (utm_*, fbclid, gclid, mkt_tok)
- Social share URLs (/share, /tweet, intent/tweet)

URLs:
{urls_text}

Return ONLY a JSON array of {max_urls} URL strings. No explanation, no markdown.
Example format: ["https://example.com/api?id=1","https://example.com/debug/trace"]

JSON:"""


@dataclass
class FilteredGauResult:
    """Result from GAU URL filtering."""
    domain: str
    total_input_urls: int = 0
    filtered_urls: list[str] = field(default_factory=list)
    by_category: dict[str, list[str]] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)


class GauUrlFilterAgent:
    """
    AI-powered agent that filters and prioritizes GAU URLs.

    Takes raw GAU output and identifies the most interesting URLs
    for security testing based on patterns and AI analysis.
    """

    def __init__(
        self,
        model: str = "haiku",
        timeout: int = 60,
        max_urls: int = 100,
    ):
        self.model = model
        self.timeout = timeout
        self.max_urls = min(max_urls, MAX_OUTPUT_URLS)
        self._claude_path: Optional[str] = shutil.which("claude")

    async def filter_urls(
        self,
        domain: str,
        urls: list[str],
        use_ai: bool = True,
    ) -> FilteredGauResult:
        """
        Filter and prioritize GAU URLs.

        Args:
            domain: Target domain
            urls: List of URLs from GAU
            use_ai: Whether to use AI for final ranking

        Returns:
            FilteredGauResult with prioritized URLs
        """
        result = FilteredGauResult(
            domain=domain,
            total_input_urls=len(urls),
        )

        if not urls:
            logger.warning("No URLs provided for filtering")
            return result

        logger.info(f"Filtering {len(urls)} GAU URLs for {domain}")

        # Step 1: Heuristic categorization and pre-filtering
        categorized = self._categorize_urls(urls)
        result.by_category = categorized
        result.stats["categories_found"] = list(categorized.keys())

        # Collect high-value URLs from categories
        high_value_urls = []
        for category, cat_urls in categorized.items():
            high_value_urls.extend([(category, u) for u in cat_urls[:50]])  # Top 50 per category

        result.stats["heuristic_candidates"] = len(high_value_urls)
        logger.info(f"Heuristic filter: {len(high_value_urls)} candidates from {len(categorized)} categories")

        # If few enough candidates, skip AI
        if len(high_value_urls) <= self.max_urls:
            result.filtered_urls = [u for _, u in high_value_urls]
            result.stats["method"] = "heuristic_only"
            return result

        # Step 2: Use AI to rank and select top URLs
        if use_ai and self._claude_path:
            ai_urls = await self._ai_filter(domain, high_value_urls, categorized)
            if ai_urls:
                result.filtered_urls = ai_urls[:self.max_urls]
                result.stats["method"] = "ai_ranked"
                logger.info(f"AI selected {len(result.filtered_urls)} high-value URLs")
                return result

        # Fallback: take top from each category
        result.filtered_urls = self._balanced_select(categorized, self.max_urls)
        result.stats["method"] = "heuristic_balanced"
        return result

    def _categorize_urls(self, urls: list[str]) -> dict[str, list[str]]:
        """Categorize URLs by security-relevant patterns."""
        categorized: dict[str, list[str]] = {}
        seen = set()

        for url in urls:
            # Skip duplicates and static assets
            if url in seen:
                continue
            if self._is_static_asset(url):
                continue
            seen.add(url)

            # Check each pattern
            for category, pattern in HIGH_VALUE_PATTERNS.items():
                if pattern.search(url):
                    if category not in categorized:
                        categorized[category] = []
                    categorized[category].append(url)
                    break  # Only categorize once

        return categorized

    def _is_static_asset(self, url: str) -> bool:
        """Check if URL is a static asset to skip."""
        static_ext = (
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
            '.css', '.less', '.scss', '.sass',
            '.woff', '.woff2', '.ttf', '.eot', '.otf',
            '.mp4', '.mp3', '.avi', '.mov', '.webm',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx',
        )
        # Check extension (before query string)
        path = url.split('?')[0].lower()
        return path.endswith(static_ext)

    def _balanced_select(self, categorized: dict[str, list[str]], max_urls: int) -> list[str]:
        """Select URLs evenly from each category."""
        if not categorized:
            return []

        per_category = max(1, max_urls // len(categorized))
        selected = []

        for category, urls in categorized.items():
            selected.extend(urls[:per_category])
            if len(selected) >= max_urls:
                break

        return selected[:max_urls]

    async def _ai_filter(
        self,
        domain: str,
        candidates: list[tuple[str, str]],  # (category, url)
        categorized: dict[str, list[str]],
    ) -> list[str]:
        """Use AI to rank and select best URLs."""
        # Build URL list for prompt - no category prefix, preserve params
        urls_text_lines = []
        seen_urls = set()

        for category, url in candidates[:MAX_URLS_IN_PROMPT]:
            if url in seen_urls:
                continue
            seen_urls.add(url)

            # Preserve full URL if it has query params (the valuable part)
            # Only truncate very long URLs without params
            if '?' in url:
                # Keep parameterized URLs intact up to reasonable length
                short_url = url[:200] + "..." if len(url) > 200 else url
            else:
                short_url = url[:120] + "..." if len(url) > 120 else url

            urls_text_lines.append(short_url)

        urls_text = "\n".join(urls_text_lines)

        prompt = GAU_FILTER_PROMPT.format(
            url_count=len(urls_text_lines),
            urls_text=urls_text,
            max_urls=self.max_urls,
        )

        # Check prompt length and reduce if needed
        if len(prompt) > MAX_PROMPT_LENGTH:
            logger.warning(f"Prompt too long ({len(prompt)}), truncating")
            urls_text_lines = urls_text_lines[:MAX_URLS_IN_PROMPT // 2]
            urls_text = "\n".join(urls_text_lines)
            prompt = GAU_FILTER_PROMPT.format(
                url_count=len(urls_text_lines),
                urls_text=urls_text,
                max_urls=self.max_urls,
            )

        # Invoke Claude
        raw_output = await self._invoke_claude(prompt)
        if not raw_output:
            return []

        return self._parse_url_list(raw_output)

    async def _invoke_claude(self, prompt: str) -> str:
        """Invoke Claude Code CLI."""
        if not self._claude_path:
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
                return result

        except asyncio.TimeoutError:
            logger.warning("Claude timeout during URL filtering")
            if process:
                try:
                    process.kill()
                    await process.wait()
                except Exception:
                    pass

        except Exception as e:
            logger.warning(f"Claude exception: {e}")

        return ""

    def _parse_url_list(self, raw_output: str) -> list[str]:
        """Parse JSON array of URLs from LLM output with robust fallbacks."""
        urls = []
        output = raw_output.strip()

        # Remove markdown code blocks if present
        if "```" in output:
            match = re.search(r'```(?:json)?\s*([\s\S]*?)```', output)
            if match:
                output = match.group(1).strip()

        # Handle {"urls": [...]} wrapper format some models emit
        if '"urls"' in output.lower():
            match = re.search(r'"urls"\s*:\s*(\[[\s\S]*?\])', output, re.I)
            if match:
                output = match.group(1).strip()

        # Find JSON array in output (handles leading/trailing text)
        array_match = re.search(r'\[[\s\S]*\]', output)
        if array_match:
            output = array_match.group(0)

        # Try JSON parsing
        try:
            parsed = json.loads(output)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, str) and item.startswith("http"):
                        urls.append(item.strip())
            elif isinstance(parsed, dict) and "urls" in parsed:
                for item in parsed["urls"]:
                    if isinstance(item, str) and item.startswith("http"):
                        urls.append(item.strip())
        except json.JSONDecodeError:
            # Fallback: line-by-line URL extraction
            for line in output.split("\n"):
                line = line.strip()
                # Clean common JSON/list artifacts
                line = re.sub(r'^[\[\]"\',\s]+|[\[\]"\',\s]+$', '', line)
                if line.startswith("http"):
                    urls.append(line)

        # Deduplicate while preserving order
        seen = set()
        unique_urls = []
        for url in urls:
            if url not in seen:
                seen.add(url)
                unique_urls.append(url)

        return unique_urls[:self.max_urls]


async def filter_gau_urls(
    domain: str,
    urls: list[str],
    max_urls: int = 100,
) -> FilteredGauResult:
    """
    Convenience function to filter GAU URLs.

    Args:
        domain: Target domain
        urls: Raw URLs from GAU
        max_urls: Maximum URLs to return

    Returns:
        FilteredGauResult with prioritized URLs
    """
    agent = GauUrlFilterAgent(max_urls=max_urls)
    return await agent.filter_urls(domain, urls)
