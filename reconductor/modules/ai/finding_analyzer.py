"""AI-powered Finding Analyzer for contextual vulnerability triage.

This module transforms raw vulnerability findings into risk-prioritized
actionable intelligence by:
1. Analyzing hostname patterns to infer asset criticality (prod vs dev)
2. Grouping related findings by root cause
3. Identifying attack chains and lateral movement paths
4. Generating executive summaries with remediation priorities

Security Notes:
    - All finding data is sanitized before prompt injection
    - Claude Code CLI is used for local/authenticated LLM access
    - No external API keys required
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
from reconductor.models.finding import Finding
from reconductor.models.host import Host

logger = get_logger(__name__)

# Pre-compiled patterns for asset classification
RE_DEV_PATTERNS = re.compile(
    r'(^dev[-.]|[-.]dev[.-]|[-.]dev$|^test[-.]|[-.]test[.-]|[-.]test$|'
    r'^staging[-.]|[-.]staging[.-]|^uat[-.]|[-.]uat[.-]|^qa[-.]|[-.]qa[.-]|'
    r'^sandbox[-.]|[-.]sandbox[.-]|^demo[-.]|[-.]demo[.-]|'
    r'^local[-.]|[-.]local[.-]|^tmp[-.]|[-.]tmp[.-])',
    re.IGNORECASE
)

RE_PROD_PATTERNS = re.compile(
    r'(^prod[-.]|[-.]prod[.-]|[-.]prod$|^live[-.]|[-.]live[.-]|'
    r'^www\.|^api\.|^app\.|^portal\.|^dashboard\.|^admin\.|'
    r'^auth\.|^sso\.|^login\.|^gateway\.|^payment\.|^checkout\.|'
    r'^db\.|^database\.|^mysql\.|^postgres\.|^mongo\.|'
    r'^mail\.|^smtp\.|^email\.)',
    re.IGNORECASE
)

RE_CRITICAL_SERVICES = re.compile(
    r'(auth|sso|login|session|token|oauth|saml|ldap|'
    r'payment|checkout|billing|stripe|paypal|'
    r'admin|root|super|master|'
    r'database|db|sql|mongo|redis|elastic|'
    r'vault|secret|key|cred|password|'
    r'backup|dump|export)',
    re.IGNORECASE
)

# Maximum prompt length
MAX_PROMPT_LENGTH = 50000


@dataclass
class AssetClassification:
    """Classification of an asset based on hostname analysis."""
    hostname: str
    environment: str  # "production", "development", "staging", "unknown"
    criticality: str  # "critical", "high", "medium", "low"
    services: list[str] = field(default_factory=list)
    reasoning: str = ""


@dataclass
class FindingGroup:
    """A group of related findings sharing a root cause."""
    group_id: str
    title: str
    root_cause: str
    findings: list[Finding] = field(default_factory=list)
    affected_hosts: list[str] = field(default_factory=list)
    max_severity: str = "info"
    environment_breakdown: dict[str, int] = field(default_factory=dict)
    recommended_action: str = ""


@dataclass
class RiskItem:
    """A prioritized risk item for the triage report."""
    rank: int
    risk_level: str  # "critical", "high", "medium", "low"
    title: str
    affected_assets: list[str]
    finding_count: int
    environment: str
    business_impact: str
    technical_details: str
    remediation: str
    attack_chain_potential: Optional[str] = None
    evidence: Optional[str] = None  # Proof of vulnerability (paths, extracted data)
    exploit_availability: Optional[str] = None  # public_exploit, poc_available, theoretical, unknown
    exploit_details: Optional[str] = None  # Name of exploit module/tool
    cve_ids: list[str] = field(default_factory=list)  # List of CVE IDs


@dataclass
class AdditionalFindings:
    """Summary of findings not in top risk items."""
    count: int
    summary: str
    hosts: list[str] = field(default_factory=list)


@dataclass
class TriageReport:
    """Complete triage report with prioritized risks."""
    domain: str
    total_findings: int
    total_risk_items: int
    risk_items: list[RiskItem] = field(default_factory=list)
    executive_summary: str = ""
    additional_findings: Optional[AdditionalFindings] = None
    finding_groups: list[FindingGroup] = field(default_factory=list)
    asset_classifications: list[AssetClassification] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "domain": self.domain,
            "total_findings": self.total_findings,
            "total_risk_items": self.total_risk_items,
            "executive_summary": self.executive_summary,
            "risk_items": [
                {
                    "rank": r.rank,
                    "risk_level": r.risk_level,
                    "title": r.title,
                    "affected_assets": r.affected_assets,
                    "finding_count": r.finding_count,
                    "environment": r.environment,
                    "business_impact": r.business_impact,
                    "technical_details": r.technical_details,
                    "remediation": r.remediation,
                    "attack_chain_potential": r.attack_chain_potential,
                    "evidence": r.evidence,
                    "exploit_availability": r.exploit_availability,
                    "exploit_details": r.exploit_details,
                    "cve_ids": r.cve_ids,
                }
                for r in self.risk_items
            ],
            "additional_findings": None,
            "stats": self.stats,
        }
        if self.additional_findings:
            result["additional_findings"] = {
                "count": self.additional_findings.count,
                "summary": self.additional_findings.summary,
                "hosts": self.additional_findings.hosts,
            }
        return result

    def to_text(self) -> str:
        """Generate human-readable text report."""
        lines = []
        lines.append("=" * 70)
        lines.append(f"RISK PRIORITY REPORT - {self.domain}")
        lines.append("=" * 70)
        lines.append("")

        if self.executive_summary:
            lines.append("EXECUTIVE SUMMARY")
            lines.append("-" * 40)
            lines.append(self.executive_summary)
            lines.append("")

        lines.append(f"Total Findings: {self.total_findings} → {self.total_risk_items} Risk Items")
        lines.append("")

        # Group by risk level
        for level in ["critical", "high", "medium", "low"]:
            level_items = [r for r in self.risk_items if r.risk_level == level]
            if not level_items:
                continue

            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[level]
            lines.append(f"{emoji} {level.upper()} RISK")
            lines.append("-" * 40)

            for item in level_items:
                lines.append(f"\n{item.rank}. {item.title}")
                lines.append(f"   Assets: {', '.join(item.affected_assets[:5])}")
                if len(item.affected_assets) > 5:
                    lines.append(f"           ...and {len(item.affected_assets) - 5} more")
                lines.append(f"   Environment: {item.environment}")
                lines.append(f"   Impact: {item.business_impact}")
                if item.attack_chain_potential:
                    lines.append(f"   Attack Chain: {item.attack_chain_potential}")
                lines.append(f"   Remediation: {item.remediation}")

            lines.append("")

        # Additional findings section
        if self.additional_findings and self.additional_findings.count > 0:
            lines.append("📋 ADDITIONAL FINDINGS")
            lines.append("-" * 40)
            lines.append(f"Count: {self.additional_findings.count}")
            lines.append(f"Summary: {self.additional_findings.summary}")
            if self.additional_findings.hosts:
                lines.append(f"Affected hosts: {', '.join(self.additional_findings.hosts[:10])}")
                if len(self.additional_findings.hosts) > 10:
                    lines.append(f"                ...and {len(self.additional_findings.hosts) - 10} more")
            lines.append("")

        return "\n".join(lines)


# The prompt template for AI analysis
TRIAGE_PROMPT = """<role>Senior penetration tester triaging vulnerabilities for a client report. Prioritize by real-world exploitability and business impact, not just CVSS.</role>

<domain>{domain}</domain>
{batch_context}
<findings count="{finding_count}" format="t=title,s=severity,id=template,h=host,e=evidence,cve=cve_id">
{findings_json}
</findings>

<asset_context>
{asset_classifications}
</asset_context>

<priority_matrix>
CRITICAL: Production auth/payment/admin + any severity OR any environment + RCE/SQLi/auth-bypass
HIGH: Production + critical/high severity OR dev auth services + critical
MEDIUM: Production + medium/low OR dev + critical/high (non-auth)
LOW: Dev/test/staging + medium/low/info
</priority_matrix>

<grouping_rules>
- Same vulnerability template across multiple hosts = 1 risk item (list all affected_assets)
- Same root cause (e.g., "missing auth on Redis") across services = 1 item
- Never list 10 identical findings as 10 separate items
</grouping_rules>

<attack_chains>
Identify combinations that escalate impact:
- Exposed .git + credentials in history → code + secrets
- Redis unauth + auth service → session hijacking
- SSRF + internal services → pivot to internal network
- Info disclosure + targeted exploit → chained RCE
Set attack_chain_potential to null if no meaningful chain exists.
</attack_chains>

<exploit_availability_guide>
Based on the vulnerability type and CVE, assess exploit availability:
- "public_exploit": Metasploit module, ExploitDB, or GitHub PoC exists
- "poc_available": Proof of concept code publicly documented
- "theoretical": Vulnerability confirmed but no public exploit
- "unknown": Cannot determine from available information
For CVEs, check if they are in known exploit frameworks (e.g., CVE-2020-1938 Ghostcat has Metasploit module).
</exploit_availability_guide>

<output_format>
Return ONLY valid JSON (no markdown, no explanation):
{{
  "executive_summary": "2-3 sentences: top risks, affected systems, urgency level",
  "risk_items": [
    {{
      "rank": 1,
      "risk_level": "critical|high|medium|low",
      "title": "Short descriptive title",
      "affected_assets": ["host1.example.com", "host2.example.com"],
      "finding_count": 2,
      "environment": "production|development|mixed",
      "business_impact": "What could happen to the business",
      "technical_details": "Technical explanation of the vulnerability",
      "evidence": "Proof the vulnerability exists: specific paths, responses, or extracted data from the scan",
      "exploit_availability": "public_exploit|poc_available|theoretical|unknown",
      "exploit_details": "Name of exploit module/tool if public, or null",
      "cve_ids": ["CVE-XXXX-XXXX"] or [],
      "remediation": "Specific fix steps with version numbers/config",
      "attack_chain_potential": "How this combines with other findings OR null"
    }}
  ]
}}
</output_format>

<rules>
1. Rank by exploitability × business impact, not raw severity
2. Production + auth/payment = always top priority regardless of severity label
3. Group aggressively: prefer fewer actionable items over exhaustive lists
4. Be specific in remediation: version numbers, config options, not generic advice
5. If hostname ambiguous (no dev/prod indicator), assume production
6. Output ALL risk items for these findings - do not skip any
7. Include actual evidence from the scan (paths found, data extracted) - be specific
8. Assess exploit availability based on CVE and vulnerability type
</rules>

OUTPUT:"""


class FindingAnalyzer:
    """
    AI-powered vulnerability finding analyzer using Claude Code CLI.

    Transforms raw findings into contextual, risk-prioritized reports
    by analyzing asset criticality and grouping related issues.
    """

    def __init__(
        self,
        model: str = "sonnet",
        timeout: int = 180,
        max_retries: int = 2,
    ):
        """
        Initialize the finding analyzer.

        Args:
            model: Claude model to use (sonnet, opus, haiku)
            timeout: Timeout for Claude Code CLI execution
            max_retries: Maximum retries on failure
        """
        if timeout < 30 or timeout > 600:
            raise ValueError("timeout must be between 30 and 600 seconds")

        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        self._claude_path: Optional[str] = shutil.which("claude")

    def classify_asset(self, hostname: str) -> AssetClassification:
        """
        Classify an asset based on hostname patterns.

        Args:
            hostname: The hostname to classify

        Returns:
            AssetClassification with environment and criticality
        """
        hostname_lower = hostname.lower()

        # Detect environment
        if RE_DEV_PATTERNS.search(hostname_lower):
            environment = "development"
        elif RE_PROD_PATTERNS.search(hostname_lower):
            environment = "production"
        else:
            # No clear indicator - assume production for safety
            environment = "unknown"

        # Detect critical services
        services = RE_CRITICAL_SERVICES.findall(hostname_lower)
        services = list(set(s.lower() for s in services))

        # Determine criticality
        if services and any(s in ["auth", "sso", "login", "payment", "admin", "database", "db"] for s in services):
            criticality = "critical"
        elif environment == "production" or services:
            criticality = "high"
        elif environment == "development":
            criticality = "low"
        else:
            criticality = "medium"

        reasoning = f"env={environment}, services={services}"

        return AssetClassification(
            hostname=hostname,
            environment=environment,
            criticality=criticality,
            services=services,
            reasoning=reasoning,
        )

    def group_findings(self, findings: list[Finding]) -> list[FindingGroup]:
        """
        Group related findings by template/root cause.

        Args:
            findings: List of findings to group

        Returns:
            List of finding groups
        """
        groups: dict[str, FindingGroup] = {}

        for finding in findings:
            # Group by template ID
            template = finding.template_id or "unknown"

            # Get severity as string
            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)

            if template not in groups:
                groups[template] = FindingGroup(
                    group_id=template,
                    title=finding.title or finding.template_name or template,
                    root_cause=template,
                    findings=[],
                    affected_hosts=[],
                    max_severity=sev or "info",
                )

            group = groups[template]
            group.findings.append(finding)

            # Extract hostname from URL
            host = finding.target or finding.matched_at or ""
            if host and host not in group.affected_hosts:
                group.affected_hosts.append(host)

            # Track max severity
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            current_sev = group.max_severity.value if hasattr(group.max_severity, 'value') else str(group.max_severity)
            if severity_order.get(sev, 0) > severity_order.get(current_sev, 0):
                group.max_severity = sev

        return list(groups.values())

    async def analyze(
        self,
        findings: list[Finding],
        hosts: Optional[list[Host]] = None,
        domain: str = "",
    ) -> TriageReport:
        """
        Analyze findings and generate a risk-prioritized triage report.

        Processes findings in batches to handle large datasets, then combines
        all risk items into a unified report.

        Args:
            findings: List of vulnerability findings
            hosts: Optional list of hosts for additional context
            domain: Target domain name

        Returns:
            TriageReport with prioritized risk items
        """
        if not findings:
            return TriageReport(
                domain=domain,
                total_findings=0,
                total_risk_items=0,
                executive_summary="No findings to analyze.",
            )

        logger.info(f"Analyzing {len(findings)} findings for {domain}")

        # Step 1: Classify all affected assets
        hostnames = set()
        for f in findings:
            host = f.target or f.matched_at or ""
            if "://" in host:
                host = host.split("://")[1].split("/")[0].split(":")[0]
            elif ":" in host:
                host = host.split(":")[0]
            if host:
                hostnames.add(host)

        classifications = [self.classify_asset(h) for h in hostnames]
        classifications_text = "\n".join([
            f"- {c.hostname}: {c.environment}, {c.criticality} criticality, services={c.services}"
            for c in classifications[:50]
        ])

        # Step 2: Group related findings
        groups = self.group_findings(findings)

        # Step 3: Process in batches if needed
        BATCH_SIZE = 30  # Findings per batch (reduced to prevent context overflow)
        all_risk_items: list[RiskItem] = []
        executive_summaries: list[str] = []

        # Create batches
        batches = [findings[i:i + BATCH_SIZE] for i in range(0, len(findings), BATCH_SIZE)]
        total_batches = len(batches)

        logger.info(f"Processing {total_batches} batch(es) of findings")

        for batch_idx, batch in enumerate(batches):
            batch_num = batch_idx + 1

            # Prepare batch data - compact format to save tokens
            findings_data = []
            for f in batch:
                sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)

                # Extract evidence (matched path, extracted results)
                evidence_parts = []
                if f.matched_at:
                    evidence_parts.append(f.matched_at)
                if f.extracted_results:
                    evidence_parts.extend(f.extracted_results[:2])  # Limit to 2 items
                evidence_str = "; ".join(evidence_parts)[:150] if evidence_parts else None

                # Extract CVE ID
                cve = f.cve_id
                if not cve and f.classification:
                    cve_list = f.classification.get("cve-id", [])
                    if cve_list:
                        cve = cve_list[0] if isinstance(cve_list, list) else cve_list

                finding_entry = {
                    "t": f.title or f.template_name,  # title
                    "s": sev,  # severity
                    "id": f.template_id,
                    "h": f.target or f.matched_at,  # host
                }
                if evidence_str:
                    finding_entry["e"] = evidence_str  # evidence
                if cve:
                    finding_entry["cve"] = cve

                findings_data.append(finding_entry)

            # Build batch context for prompt
            if total_batches > 1:
                batch_context = f"<batch>Processing batch {batch_num} of {total_batches}. Analyze ONLY these {len(batch)} findings.</batch>"
            else:
                batch_context = ""

            # Build prompt with compact JSON (no indent to save tokens)
            prompt = TRIAGE_PROMPT.format(
                domain=domain,
                finding_count=len(batch),
                findings_json=json.dumps(findings_data, separators=(',', ':')),
                asset_classifications=classifications_text,
                batch_context=batch_context,
            )

            # Truncate if too long
            if len(prompt) > MAX_PROMPT_LENGTH:
                logger.warning(f"Batch {batch_num} prompt too long, truncating")
                prompt = prompt[:MAX_PROMPT_LENGTH]

            # Call Claude Code CLI
            logger.info(f"Processing batch {batch_num}/{total_batches} ({len(batch)} findings)")
            ai_response = await self._invoke_claude_code(prompt)

            # Parse response
            batch_report = self._parse_ai_response(ai_response, domain, batch, classifications, groups)

            # Collect risk items
            all_risk_items.extend(batch_report.risk_items)

            # Collect executive summary (only from first batch or combine)
            if batch_report.executive_summary:
                executive_summaries.append(batch_report.executive_summary)

        # Step 4: Combine and re-rank all risk items
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_risk_items.sort(key=lambda r: (severity_order.get(r.risk_level, 4), -r.finding_count))

        # Re-number ranks
        for idx, item in enumerate(all_risk_items, 1):
            item.rank = idx

        # Combine executive summaries
        if len(executive_summaries) == 1:
            final_summary = executive_summaries[0]
        elif executive_summaries:
            final_summary = executive_summaries[0]  # Use first batch summary as primary
        else:
            final_summary = f"Analyzed {len(findings)} findings across {len(hostnames)} assets."

        # Build final report
        report = TriageReport(
            domain=domain,
            total_findings=len(findings),
            total_risk_items=len(all_risk_items),
            risk_items=all_risk_items,
            executive_summary=final_summary,
            asset_classifications=classifications,
            finding_groups=groups,
        )

        logger.info(
            f"Triage complete: {report.total_findings} findings → {report.total_risk_items} risk items"
        )

        return report

    async def _invoke_claude_code(self, prompt: str) -> str:
        """Invoke Claude Code CLI for analysis."""
        if not self._claude_path:
            logger.error("Claude Code CLI not found in PATH")
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
                    logger.debug(f"Claude Code returned {len(result)} chars")
                    return result
                else:
                    logger.warning(f"Claude Code failed (attempt {attempt + 1})")

            except asyncio.TimeoutError:
                logger.warning(f"Claude Code timeout (attempt {attempt + 1})")
                if process is not None:
                    try:
                        process.kill()
                        await process.wait()
                    except Exception:
                        pass

            except Exception as e:
                logger.warning(f"Claude Code exception: {e}")
                if process is not None:
                    try:
                        process.kill()
                        await process.wait()
                    except Exception:
                        pass

            if attempt < self.max_retries:
                await asyncio.sleep(2 ** attempt)

        return ""

    def _parse_ai_response(
        self,
        response: str,
        domain: str,
        findings: list[Finding],
        classifications: list[AssetClassification],
        groups: list[FindingGroup],
    ) -> TriageReport:
        """Parse AI response into a TriageReport."""
        report = TriageReport(
            domain=domain,
            total_findings=len(findings),
            total_risk_items=0,
            asset_classifications=classifications,
            finding_groups=groups,
        )

        if not response:
            # Fallback: generate basic report without AI
            logger.warning("No AI response, generating fallback report")
            return self._generate_fallback_report(report, findings, classifications, groups)

        try:
            # Extract JSON from response (handle markdown code blocks)
            json_match = re.search(r'\{[\s\S]*\}', response)
            if not json_match:
                raise ValueError("No JSON found in response")

            data = json.loads(json_match.group())

            report.executive_summary = data.get("executive_summary", "")

            for idx, item in enumerate(data.get("risk_items", []), 1):
                risk_item = RiskItem(
                    rank=item.get("rank", idx),
                    risk_level=item.get("risk_level", "medium"),
                    title=item.get("title", "Unknown"),
                    affected_assets=item.get("affected_assets", []),
                    finding_count=item.get("finding_count", 1),
                    environment=item.get("environment", "unknown"),
                    business_impact=item.get("business_impact", ""),
                    technical_details=item.get("technical_details", ""),
                    remediation=item.get("remediation", ""),
                    attack_chain_potential=item.get("attack_chain_potential"),
                    evidence=item.get("evidence"),
                    exploit_availability=item.get("exploit_availability"),
                    exploit_details=item.get("exploit_details"),
                    cve_ids=item.get("cve_ids", []),
                )
                report.risk_items.append(risk_item)

            report.total_risk_items = len(report.risk_items)

            # Parse additional findings if present
            additional = data.get("additional_findings")
            if additional and isinstance(additional, dict):
                report.additional_findings = AdditionalFindings(
                    count=additional.get("count", 0),
                    summary=additional.get("summary", ""),
                    hosts=additional.get("hosts", []),
                )

        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse AI response: {e}")
            return self._generate_fallback_report(report, findings, classifications, groups)

        return report

    def _generate_fallback_report(
        self,
        report: TriageReport,
        findings: list[Finding],
        classifications: list[AssetClassification],
        groups: list[FindingGroup],
    ) -> TriageReport:
        """Generate a basic report without AI analysis."""
        # Sort groups by severity and asset criticality
        prod_critical = []
        prod_other = []
        dev_findings = []

        # Build hostname -> classification map
        class_map = {c.hostname: c for c in classifications}

        for group in groups:
            is_prod = False
            is_critical_service = False

            for host in group.affected_hosts:
                # Extract hostname
                hostname = host
                if "://" in hostname:
                    hostname = hostname.split("://")[1].split("/")[0].split(":")[0]
                elif ":" in hostname:
                    hostname = hostname.split(":")[0]

                classification = class_map.get(hostname)
                if classification:
                    if classification.environment == "production":
                        is_prod = True
                    if classification.criticality == "critical":
                        is_critical_service = True

            if is_critical_service or (is_prod and group.max_severity in ["critical", "high"]):
                prod_critical.append(group)
            elif is_prod:
                prod_other.append(group)
            else:
                dev_findings.append(group)

        # Build risk items
        rank = 1

        for group in prod_critical:
            report.risk_items.append(RiskItem(
                rank=rank,
                risk_level="critical" if group.max_severity == "critical" else "high",
                title=group.title,
                affected_assets=group.affected_hosts,
                finding_count=len(group.findings),
                environment="production",
                business_impact="Production system affected - potential service disruption or data breach",
                technical_details=f"Template: {group.root_cause}",
                remediation="Prioritize immediate remediation",
            ))
            rank += 1

        for group in prod_other:
            report.risk_items.append(RiskItem(
                rank=rank,
                risk_level="medium",
                title=group.title,
                affected_assets=group.affected_hosts,
                finding_count=len(group.findings),
                environment="production",
                business_impact="Production exposure - lower severity but should be addressed",
                technical_details=f"Template: {group.root_cause}",
                remediation="Schedule for next maintenance window",
            ))
            rank += 1

        # Group all dev findings into one item if multiple
        if dev_findings:
            all_dev_hosts = []
            total_dev_findings = 0
            for group in dev_findings:
                all_dev_hosts.extend(group.affected_hosts)
                total_dev_findings += len(group.findings)

            report.risk_items.append(RiskItem(
                rank=rank,
                risk_level="low",
                title=f"Development/Test Environment Issues ({len(dev_findings)} types)",
                affected_assets=list(set(all_dev_hosts))[:10],
                finding_count=total_dev_findings,
                environment="development",
                business_impact="Non-production systems - lower business risk but fix to prevent lateral movement",
                technical_details=f"Grouped {len(dev_findings)} finding types across dev/test systems",
                remediation="Batch remediation in scheduled maintenance",
            ))

        report.total_risk_items = len(report.risk_items)
        report.executive_summary = (
            f"Analyzed {report.total_findings} findings across {len(classifications)} assets. "
            f"Identified {len(prod_critical)} critical production issues requiring immediate attention, "
            f"{len(prod_other)} medium-priority production items, and "
            f"{len(dev_findings)} development environment issues."
        )

        return report


async def analyze_findings(
    findings: list[Finding],
    hosts: Optional[list[Host]] = None,
    domain: str = "",
    output_path: Optional[Path] = None,
) -> TriageReport:
    """
    Convenience function to analyze findings.

    Args:
        findings: List of vulnerability findings
        hosts: Optional list of hosts
        domain: Target domain
        output_path: Optional path to save report

    Returns:
        TriageReport with prioritized risks
    """
    analyzer = FindingAnalyzer()
    report = await analyzer.analyze(findings, hosts, domain)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Save JSON report
        json_path = output_path.with_suffix(".json")
        json_path.write_text(json.dumps(report.to_dict(), indent=2))

        # Save text report
        text_path = output_path.with_suffix(".txt")
        text_path.write_text(report.to_text())

        logger.info(f"Triage report saved to {output_path}")

    return report
