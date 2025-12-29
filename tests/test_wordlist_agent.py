#!/usr/bin/env python3
"""Test script for the WordlistGeneratorAgent with fagi.gr domain."""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path

# Add the project to path
sys.path.insert(0, str(Path(__file__).parent))

from reconductor.modules.ai.wordlist_agent import WordlistGeneratorAgent, generate_wordlist


async def test_wordlist_generation(domain: str = "fagi.gr") -> dict:
    """
    Test wordlist generation for a domain and return statistics.

    Args:
        domain: Target domain to test

    Returns:
        Dictionary with test results and statistics
    """
    print(f"\n{'='*60}")
    print(f"  WORDLIST GENERATOR AGENT TEST")
    print(f"  Domain: {domain}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    agent = WordlistGeneratorAgent(
        model="sonnet",  # Use alias for Claude Sonnet 4
        timeout=180,
        max_retries=2,
    )

    print("[1/4] Gathering intelligence from CT logs, Wayback Machine...")

    # Generate wordlist
    result = await agent.generate(
        domain=domain,
        existing_subdomains=[],  # No existing subdomains
        count=200,
        include_base_wordlist=True,
    )

    print(f"\n[2/4] Intelligence gathering complete:")
    print(f"  - CT logs subdomains: {result.stats.get('ct_subdomains', 0)}")
    print(f"  - Wayback subdomains: {result.stats.get('wayback_subdomains', 0)}")
    print(f"  - Patterns detected: {result.stats.get('patterns_detected', 0)}")
    print(f"  - Technologies detected: {result.stats.get('technologies_detected', 0)}")

    print(f"\n[3/4] LLM Generation Results:")
    print(f"  - LLM raw output lines: {result.stats.get('llm_raw_lines', 0)}")
    print(f"  - LLM valid prefixes: {result.stats.get('llm_generated_valid', 0)}")

    print(f"\n[4/4] Final Wordlist Statistics:")
    llm_contrib = result.get_llm_contribution()
    print(f"  - Total wordlist size: {llm_contrib['total_wordlist']}")
    print(f"  - From LLM (Claude): {llm_contrib['from_llm']}")
    print(f"  - From Intelligence (CT+Wayback): {llm_contrib['from_intelligence']}")
    print(f"  - From Base wordlist: {llm_contrib['from_base']}")
    print(f"  - LLM contribution: {llm_contrib['llm_percentage']}%")

    # Show detected patterns
    if result.intelligence.detected_patterns:
        print(f"\n  Detected Patterns:")
        for pattern in result.intelligence.detected_patterns[:5]:
            print(f"    - {pattern}")

    # Show detected technologies
    if result.intelligence.technologies:
        print(f"\n  Detected Technologies: {', '.join(result.intelligence.technologies)}")

    # Show industry hints
    if result.intelligence.industry_hints:
        print(f"  Industry Hints: {', '.join(result.intelligence.industry_hints)}")

    # Save wordlist
    output_path = Path(f"/home/kali/projects/reconductor/reconductor-v2/output/{domain}_wordlist.txt")
    agent.save_wordlist(result, output_path)
    print(f"\n  Wordlist saved to: {output_path}")

    # Show sample of generated wordlist
    print(f"\n  Sample wordlist entries (first 20):")
    for prefix in result.wordlist[:20]:
        print(f"    - {prefix}")

    if len(result.wordlist) > 20:
        print(f"    ... and {len(result.wordlist) - 20} more")

    # Prepare report
    report = {
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "statistics": {
            "total_wordlist": llm_contrib["total_wordlist"],
            "from_llm": llm_contrib["from_llm"],
            "from_intelligence": llm_contrib["from_intelligence"],
            "from_base": llm_contrib["from_base"],
            "llm_percentage": llm_contrib["llm_percentage"],
            "ct_subdomains": result.stats.get("ct_subdomains", 0),
            "wayback_subdomains": result.stats.get("wayback_subdomains", 0),
            "patterns_detected": result.stats.get("patterns_detected", 0),
            "technologies_detected": result.stats.get("technologies_detected", 0),
        },
        "intelligence": {
            "patterns": result.intelligence.detected_patterns,
            "technologies": result.intelligence.technologies,
            "industry_hints": result.intelligence.industry_hints,
            "common_prefixes": result.intelligence.common_prefixes[:10],
        },
        "wordlist_sample": result.wordlist[:50],
    }

    # Save JSON report
    report_path = Path(f"/home/kali/projects/reconductor/reconductor-v2/output/{domain}_report.json")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2))
    print(f"  Report saved to: {report_path}")

    print(f"\n{'='*60}")
    print(f"  TEST COMPLETE")
    print(f"{'='*60}\n")

    return report


if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "fagi.gr"
    report = asyncio.run(test_wordlist_generation(domain))

    # Print final summary
    stats = report["statistics"]
    print("\n" + "="*60)
    print("  FINAL REPORT SUMMARY")
    print("="*60)
    print(f"""
Domain: {report['domain']}
Timestamp: {report['timestamp']}

WORDLIST STATISTICS:
  Total Wordlist Size: {stats['total_wordlist']}

  Sources Breakdown:
    - LLM Generated (Claude Sonnet 4.5): {stats['from_llm']} ({stats['llm_percentage']}%)
    - CT Logs (crt.sh): {stats['ct_subdomains']}
    - Wayback Machine: {stats['wayback_subdomains']}
    - Base Wordlist: {stats['from_base']}

  Intelligence Analysis:
    - Patterns Detected: {stats['patterns_detected']}
    - Technologies Found: {stats['technologies_detected']}
    - Industry Hints: {', '.join(report['intelligence']['industry_hints']) or 'None'}

LLM CONTRIBUTION ANALYSIS:
  The Claude Sonnet 4.5 model contributed {stats['from_llm']} unique subdomain
  prefixes, representing {stats['llm_percentage']}% of the final wordlist.

  These AI-generated prefixes are based on:
    1. Patterns observed in historical subdomains
    2. Industry-specific naming conventions
    3. Technology-specific subdomain patterns
    4. Regional and environment variations
""")
