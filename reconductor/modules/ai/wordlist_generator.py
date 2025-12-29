"""AI-powered wordlist generation for subdomain enumeration.

This module provides both legacy LLM-based generation and the new
WordlistGeneratorAgent using Claude Code CLI in headless mode.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from reconductor.core.logger import get_logger
from reconductor.modules.ai.llm_client import LLMClient, get_llm_client
from reconductor.utils.validator import LLMOutputValidator

# Import the new agent for Claude Code CLI integration
from reconductor.modules.ai.wordlist_agent import (
    WordlistGeneratorAgent,
    WordlistResult,
    generate_wordlist as generate_wordlist_with_agent,
)

logger = get_logger(__name__)

# Re-export the new agent components
__all__ = [
    "AIWordlistGenerator",
    "WordlistGeneratorAgent",
    "WordlistResult",
    "generate_wordlist_with_agent",
    "get_base_wordlist",
    "BASE_WORDLIST",
]


# Prompt templates for subdomain prediction
SUBDOMAIN_PREDICTION_PROMPT = """You are an expert in subdomain enumeration for security research.
Given the following information about a target domain, generate a list of likely subdomain prefixes.

Domain: {domain}
Industry/Type: {industry}
Existing subdomains found: {existing_subdomains}

Based on common naming conventions, technology patterns, and industry-specific terms,
generate {count} unique subdomain prefixes that are likely to exist.

Rules:
1. Output ONLY the subdomain prefix (e.g., "api", not "api.example.com")
2. One prefix per line
3. Use only lowercase letters, numbers, and hyphens
4. NO underscores (they're invalid in DNS)
5. Focus on realistic, common patterns like:
   - Environment: dev, staging, prod, test, uat, qa
   - Services: api, auth, mail, vpn, cdn, static
   - Internal: internal, intranet, admin, portal
   - Regional: us, eu, asia, east, west
   - Numbered: app1, app2, server01, node-1

Output only the prefixes, one per line, no explanations:"""


INDUSTRY_ANALYSIS_PROMPT = """Analyze this domain and its existing subdomains to determine:
1. The likely industry/business type
2. Technology stack hints
3. Naming convention patterns

Domain: {domain}
Existing subdomains: {subdomains}

Respond in this format:
Industry: <industry>
Tech Stack: <technologies>
Naming Pattern: <pattern description>
Separator: <- or .>"""


class AIWordlistGenerator:
    """
    AI-powered wordlist generation for subdomain enumeration.

    Uses LLMs to predict likely subdomains based on context,
    industry patterns, and existing subdomain analysis.
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
    ):
        """
        Initialize AI wordlist generator.

        Args:
            llm_client: LLM client for generation
        """
        self.llm = llm_client or get_llm_client()
        self._validator: Optional[LLMOutputValidator] = None

    async def generate_wordlist(
        self,
        domain: str,
        existing_subdomains: Optional[list[str]] = None,
        industry: str = "unknown",
        count: int = 100,
    ) -> list[str]:
        """
        Generate a custom wordlist for a domain.

        Args:
            domain: Target domain
            existing_subdomains: Known subdomains for context
            industry: Industry type for targeting
            count: Number of predictions to generate

        Returns:
            List of validated subdomain names
        """
        logger.info(f"Generating AI wordlist for {domain}")

        # Initialize validator for this domain
        self._validator = LLMOutputValidator(domain)

        # Format existing subdomains for prompt
        existing_str = ", ".join(existing_subdomains[:20]) if existing_subdomains else "none found yet"

        # Build prompt
        prompt = SUBDOMAIN_PREDICTION_PROMPT.format(
            domain=domain,
            industry=industry,
            existing_subdomains=existing_str,
            count=count,
        )

        # Generate predictions
        raw_output = await self.llm.generate(
            prompt,
            max_tokens=count * 20,  # Rough estimate
            temperature=0.7,
        )

        if not raw_output:
            logger.warning("LLM returned empty output")
            return []

        # Validate and clean output
        validated = self._validator.validate_and_clean(raw_output)

        logger.info(
            f"AI wordlist generated",
            domain=domain,
            raw_count=raw_output.count("\n") + 1,
            validated_count=len(validated),
        )

        return validated

    async def analyze_industry(
        self,
        domain: str,
        subdomains: list[str],
    ) -> dict[str, str]:
        """
        Analyze domain to determine industry and patterns.

        Args:
            domain: Target domain
            subdomains: Existing subdomains

        Returns:
            Dictionary with analysis results
        """
        prompt = INDUSTRY_ANALYSIS_PROMPT.format(
            domain=domain,
            subdomains=", ".join(subdomains[:30]),
        )

        output = await self.llm.generate(prompt, max_tokens=200, temperature=0.3)

        # Parse output
        result = {
            "industry": "unknown",
            "tech_stack": "",
            "naming_pattern": "",
            "separator": "-",
        }

        for line in output.strip().split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower().replace(" ", "_")
                value = value.strip()

                if "industry" in key:
                    result["industry"] = value
                elif "tech" in key:
                    result["tech_stack"] = value
                elif "naming" in key or "pattern" in key:
                    result["naming_pattern"] = value
                elif "separator" in key:
                    result["separator"] = value

        return result

    async def generate_targeted_wordlist(
        self,
        domain: str,
        existing_subdomains: list[str],
        count: int = 100,
    ) -> list[str]:
        """
        Generate a targeted wordlist with automatic industry detection.

        Args:
            domain: Target domain
            existing_subdomains: Known subdomains
            count: Number of predictions

        Returns:
            List of validated subdomain names
        """
        # First, analyze the domain
        analysis = await self.analyze_industry(domain, existing_subdomains)

        logger.info(
            f"Domain analysis complete",
            industry=analysis["industry"],
            separator=analysis["separator"],
        )

        # Generate wordlist with context
        return await self.generate_wordlist(
            domain=domain,
            existing_subdomains=existing_subdomains,
            industry=analysis["industry"],
            count=count,
        )

    async def enhance_wordlist(
        self,
        wordlist: list[str],
        domain: str,
        count: int = 50,
    ) -> list[str]:
        """
        Enhance an existing wordlist with AI predictions.

        Args:
            wordlist: Existing wordlist
            domain: Target domain
            count: Number of additional predictions

        Returns:
            Enhanced wordlist
        """
        # Use existing wordlist as context
        predictions = await self.generate_wordlist(
            domain=domain,
            existing_subdomains=wordlist[:50],
            count=count,
        )

        # Combine and deduplicate
        combined = list(set(wordlist + predictions))

        logger.info(
            f"Wordlist enhanced",
            original=len(wordlist),
            added=len(predictions),
            combined=len(combined),
        )

        return combined

    def save_wordlist(
        self,
        wordlist: list[str],
        output_path: Path,
    ) -> None:
        """
        Save wordlist to file.

        Args:
            wordlist: Wordlist to save
            output_path: Output file path
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(sorted(set(wordlist))))
        logger.info(f"Wordlist saved to {output_path}")


# Common base wordlists for fallback
BASE_WORDLIST = """
admin
api
app
auth
backup
beta
blog
cdn
cms
console
dashboard
db
demo
dev
docs
email
ftp
git
gitlab
internal
intranet
jenkins
jira
login
mail
monitor
mysql
new
old
panel
portal
prod
production
proxy
qa
server
shop
smtp
staging
static
status
store
support
test
uat
upload
vpn
web
www
""".strip().split("\n")


def get_base_wordlist() -> list[str]:
    """Get the base wordlist for enumeration."""
    return BASE_WORDLIST.copy()
