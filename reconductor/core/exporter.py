"""Report exporter for generating scan reports in multiple formats."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from reconductor.core.logger import get_logger

logger = get_logger(__name__)


class ReportExporter:
    """
    Exports scan results to multiple formats.

    Generates:
    - subdomains.txt: Plain text list of discovered subdomains
    - subdomains_all.md: Markdown list of all subdomains
    - subdomains_live.md: Markdown list of HTTP-validated subdomains
    - live_hosts.txt: Plain text list of live hosts
    - hosts.json: Detailed JSON with all host information
    - findings.json: All vulnerability findings
    - findings_summary.txt: Human-readable findings summary
    - report.html: Rich HTML report with technical details and triage
    """

    def __init__(self, output_dir: Path):
        """
        Initialize the report exporter.

        Args:
            output_dir: Directory to save reports (will be created if needed)
        """
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_all(self, scan_result: dict[str, Any]) -> dict[str, Path]:
        """
        Export all report formats.

        Args:
            scan_result: The scan result dictionary from orchestrator

        Returns:
            Dictionary mapping report type to file path
        """
        exported = {}

        domain = scan_result.get("domain", "unknown")
        logger.info(f"Exporting reports for {domain}")

        # Export subdomains (txt for tools, md for reference)
        exported["subdomains"] = self.export_subdomains(scan_result)
        exported["subdomains_all_md"] = self.export_subdomains_markdown(scan_result)
        exported["subdomains_live_md"] = self.export_live_subdomains_markdown(scan_result)

        # Export live hosts (text)
        exported["live_hosts"] = self.export_live_hosts_txt(scan_result)

        # Export hosts (JSON)
        exported["hosts_json"] = self.export_hosts_json(scan_result)

        # Export findings (JSON)
        exported["findings_json"] = self.export_findings_json(scan_result)

        # Export findings summary (text)
        exported["findings_summary"] = self.export_findings_summary(scan_result)

        # Export scan metadata
        exported["scan_info"] = self.export_scan_info(scan_result)

        # Export HTML report (raw findings)
        exported["report_html"] = self.export_html_report(scan_result)

        # Export triage report (AI-prioritized) if available
        triage_path = self.export_triage_report(scan_result)
        if triage_path:
            exported["triage_report_html"] = triage_path

        # Export pentester target files (actionable outputs for next phase)
        pentester_exports = self.export_pentester_targets(scan_result)
        exported.update(pentester_exports)

        logger.info(f"Exported {len(exported)} reports to {self.output_dir}")

        return exported

    def export_subdomains_markdown(self, scan_result: dict[str, Any]) -> Path:
        """Export all subdomains to markdown file (simple list)."""
        subdomains = scan_result.get("subdomains", [])
        domain = scan_result.get("domain", "unknown")
        output_path = self.output_dir / "subdomains_all.md"

        unique_subs = sorted(set(subdomains))
        lines = [
            f"# All Discovered Subdomains - {domain}",
            "",
            f"Total: {len(unique_subs)}",
            "",
            "```",
        ]
        lines.extend(unique_subs)
        lines.append("```")

        output_path.write_text("\n".join(lines))
        logger.debug(f"Exported {len(unique_subs)} subdomains to {output_path}")
        return output_path

    def export_live_subdomains_markdown(self, scan_result: dict[str, Any]) -> Path:
        """Export HTTP-validated subdomains to markdown file (simple list)."""
        hosts = scan_result.get("hosts", [])
        domain = scan_result.get("domain", "unknown")
        output_path = self.output_dir / "subdomains_live.md"

        # Extract hostnames from live hosts
        live_hostnames = set()
        for host in hosts:
            if host.get("is_alive", True):
                hostname = host.get("hostname", "")
                if hostname:
                    live_hostnames.add(hostname)

        unique_live = sorted(live_hostnames)
        lines = [
            f"# HTTP-Validated Subdomains - {domain}",
            "",
            f"Total: {len(unique_live)}",
            "",
            "```",
        ]
        lines.extend(unique_live)
        lines.append("```")

        output_path.write_text("\n".join(lines))
        logger.debug(f"Exported {len(unique_live)} live subdomains to {output_path}")
        return output_path

    def export_subdomains(self, scan_result: dict[str, Any]) -> Path:
        """Export subdomains to plain text file."""
        subdomains = scan_result.get("subdomains", [])
        output_path = self.output_dir / "subdomains.txt"

        # Sort and deduplicate
        unique_subs = sorted(set(subdomains))
        output_path.write_text("\n".join(unique_subs))

        logger.debug(f"Exported {len(unique_subs)} subdomains to {output_path}")
        return output_path

    def export_live_hosts_txt(self, scan_result: dict[str, Any]) -> Path:
        """Export live hosts to plain text file (URLs)."""
        hosts = scan_result.get("hosts", [])
        output_path = self.output_dir / "live_hosts.txt"

        urls = []
        for host in hosts:
            if host.get("is_alive", True):
                url = host.get("url") or host.get("full_url")
                if not url:
                    scheme = host.get("scheme", "https")
                    hostname = host.get("hostname", "")
                    port = host.get("port", 443)
                    if port in (80, 443):
                        url = f"{scheme}://{hostname}"
                    else:
                        url = f"{scheme}://{hostname}:{port}"
                urls.append(url)

        output_path.write_text("\n".join(sorted(set(urls))))

        logger.debug(f"Exported {len(urls)} live hosts to {output_path}")
        return output_path

    def export_hosts_json(self, scan_result: dict[str, Any]) -> Path:
        """Export detailed host information to JSON."""
        hosts = scan_result.get("hosts", [])
        output_path = self.output_dir / "hosts.json"

        output_path.write_text(json.dumps(hosts, indent=2, default=str))

        logger.debug(f"Exported {len(hosts)} hosts to {output_path}")
        return output_path

    def export_findings_json(self, scan_result: dict[str, Any]) -> Path:
        """Export findings to JSON."""
        findings = scan_result.get("findings", [])
        output_path = self.output_dir / "findings.json"

        output_path.write_text(json.dumps(findings, indent=2, default=str))

        logger.debug(f"Exported {len(findings)} findings to {output_path}")
        return output_path

    def export_findings_summary(self, scan_result: dict[str, Any]) -> Path:
        """Export human-readable findings summary."""
        findings = scan_result.get("findings", [])
        stats = scan_result.get("stats", {})
        output_path = self.output_dir / "findings_summary.txt"

        lines = [
            "=" * 60,
            "VULNERABILITY FINDINGS SUMMARY",
            "=" * 60,
            "",
            f"Total Findings: {stats.get('findings_total', len(findings))}",
            f"  Critical: {stats.get('findings_critical', 0)}",
            f"  High: {stats.get('findings_high', 0)}",
            f"  Medium: {stats.get('findings_medium', 0)}",
            f"  Low: {stats.get('findings_low', 0)}",
            f"  Info: {stats.get('findings_info', 0)}",
            "",
            "-" * 60,
            "DETAILED FINDINGS",
            "-" * 60,
        ]

        # Group by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        grouped: dict[str, list] = {s: [] for s in severity_order}

        for finding in findings:
            sev = finding.get("severity", "info")
            if isinstance(sev, dict):
                sev = sev.get("value", "info")
            grouped.get(sev.lower(), grouped["info"]).append(finding)

        for severity in severity_order:
            sev_findings = grouped[severity]
            if sev_findings:
                lines.append(f"\n[{severity.upper()}] ({len(sev_findings)} findings)")
                lines.append("-" * 40)
                for f in sev_findings:
                    template = f.get("template_id", "unknown")
                    # Use matched_at (full URL with path) if available
                    location = f.get("matched_at") or f.get("target", "unknown")
                    title = f.get("title", template)
                    lines.append(f"  - {title}")
                    lines.append(f"    URL: {location}")
                    lines.append(f"    Template: {template}")
                    lines.append("")

        output_path.write_text("\n".join(lines))

        logger.debug(f"Exported findings summary to {output_path}")
        return output_path

    def export_scan_info(self, scan_result: dict[str, Any]) -> Path:
        """Export scan metadata to JSON."""
        output_path = self.output_dir / "scan_info.json"

        info = {
            "scan_id": scan_result.get("scan_id"),
            "domain": scan_result.get("domain"),
            "status": scan_result.get("status"),
            "phase": scan_result.get("phase"),
            "started_at": scan_result.get("started_at"),
            "completed_at": scan_result.get("completed_at"),
            "duration_seconds": scan_result.get("duration_seconds"),
            "stats": scan_result.get("stats", {}),
            "errors": scan_result.get("errors", []),
            "exported_at": datetime.now().isoformat(),
        }

        output_path.write_text(json.dumps(info, indent=2, default=str))

        logger.debug(f"Exported scan info to {output_path}")
        return output_path

    def export_pentester_targets(self, scan_result: dict[str, Any]) -> dict[str, Path]:
        """
        Export actionable target files for pentesters.

        Creates a targets/ directory with:
        - fuzz_urls.txt: URLs with parameters ready for ffuf/burp
        - origin_ips.txt: Origin IPs for direct scanning (WAF bypass)
        - sqli_candidates.txt: URLs with injectable-looking parameters
        - ssrf_candidates.txt: URLs with redirect/URL parameters
        - lfi_candidates.txt: URLs with file/path parameters
        - all_params.txt: All discovered parameters for wordlist building
        - next_steps.md: Prioritized action plan for pentester
        """
        exported = {}
        domain = scan_result.get("domain", "unknown")

        # Create targets directory
        targets_dir = self.output_dir / "targets"
        targets_dir.mkdir(exist_ok=True)

        # Get GAU result if available
        gau_result = scan_result.get("gau_result")
        gau_urls = []
        if gau_result:
            if hasattr(gau_result, 'all_urls'):
                gau_urls = gau_result.all_urls
            elif isinstance(gau_result, dict):
                gau_urls = gau_result.get("all_urls", [])

        # Get origin IPs (stored at top level or in extra)
        origin_ips = scan_result.get("origin_ips", [])
        if not origin_ips:
            extra = scan_result.get("extra", {})
            if extra:
                origin_ips = extra.get("origin_ips", [])

        # Get hosts
        hosts = scan_result.get("hosts", [])
        findings = scan_result.get("findings", [])

        # === 1. FUZZ URLs (URLs with params, validated as live) ===
        fuzz_urls = []
        for url_obj in gau_urls:
            url = url_obj.url if hasattr(url_obj, 'url') else url_obj.get('url', '')
            has_params = url_obj.has_params if hasattr(url_obj, 'has_params') else bool(url_obj.get('params'))
            status = url_obj.validation_status if hasattr(url_obj, 'validation_status') else url_obj.get('validation_status')

            if has_params:
                # Prioritize validated live URLs
                if status and status < 400:
                    fuzz_urls.insert(0, url)  # Live URLs first
                else:
                    fuzz_urls.append(url)

        fuzz_path = targets_dir / "fuzz_urls.txt"
        fuzz_path.write_text("\n".join(fuzz_urls[:500]))  # Limit to 500
        exported["fuzz_urls"] = fuzz_path

        # === 2. Origin IPs ===
        origin_lines = []
        for origin in origin_ips:
            ip = origin.get("ip", "") if isinstance(origin, dict) else str(origin)
            confidence = origin.get("confidence", "unknown") if isinstance(origin, dict) else "unknown"
            if ip:
                origin_lines.append(f"{ip}  # confidence: {confidence}")

        origin_path = targets_dir / "origin_ips.txt"
        origin_path.write_text("\n".join(origin_lines))
        exported["origin_ips"] = origin_path

        # === 3. SQLi Candidates (id=, user=, order=, sort=, etc.) ===
        sqli_params = {'id', 'user', 'userid', 'user_id', 'uid', 'pid', 'item', 'itemid',
                       'order', 'sort', 'column', 'field', 'category', 'cat', 'type',
                       'page', 'pageid', 'p', 'q', 'query', 'search', 'keyword',
                       'name', 'username', 'email', 'table', 'from', 'select', 'where'}
        sqli_urls = []
        for url_obj in gau_urls:
            params = url_obj.params if hasattr(url_obj, 'params') else url_obj.get('params', {})
            url = url_obj.url if hasattr(url_obj, 'url') else url_obj.get('url', '')
            if params:
                param_names = set(k.lower() for k in params.keys())
                if param_names & sqli_params:
                    sqli_urls.append(url)

        sqli_path = targets_dir / "sqli_candidates.txt"
        sqli_path.write_text("\n".join(sqli_urls[:200]))
        exported["sqli_candidates"] = sqli_path

        # === 4. SSRF/Redirect Candidates ===
        ssrf_params = {'url', 'uri', 'redirect', 'redirect_url', 'return', 'returnurl',
                       'return_url', 'next', 'nexturl', 'next_url', 'dest', 'destination',
                       'go', 'goto', 'target', 'link', 'linkurl', 'domain', 'host',
                       'callback', 'oauth_callback', 'continue', 'feed', 'proxy', 'site'}
        ssrf_urls = []
        for url_obj in gau_urls:
            params = url_obj.params if hasattr(url_obj, 'params') else url_obj.get('params', {})
            url = url_obj.url if hasattr(url_obj, 'url') else url_obj.get('url', '')
            if params:
                param_names = set(k.lower() for k in params.keys())
                if param_names & ssrf_params:
                    ssrf_urls.append(url)

        ssrf_path = targets_dir / "ssrf_candidates.txt"
        ssrf_path.write_text("\n".join(ssrf_urls[:200]))
        exported["ssrf_candidates"] = ssrf_path

        # === 5. LFI Candidates ===
        lfi_params = {'file', 'filename', 'path', 'filepath', 'document', 'doc', 'folder',
                      'root', 'pg', 'style', 'template', 'tpl', 'include', 'inc', 'locate',
                      'show', 'view', 'content', 'layout', 'mod', 'conf', 'lang', 'language'}
        lfi_urls = []
        for url_obj in gau_urls:
            params = url_obj.params if hasattr(url_obj, 'params') else url_obj.get('params', {})
            url = url_obj.url if hasattr(url_obj, 'url') else url_obj.get('url', '')
            if params:
                param_names = set(k.lower() for k in params.keys())
                if param_names & lfi_params:
                    lfi_urls.append(url)

        lfi_path = targets_dir / "lfi_candidates.txt"
        lfi_path.write_text("\n".join(lfi_urls[:200]))
        exported["lfi_candidates"] = lfi_path

        # === 6. All Parameters (for wordlist building) ===
        all_params = set()
        for url_obj in gau_urls:
            params = url_obj.params if hasattr(url_obj, 'params') else url_obj.get('params', {})
            if params:
                all_params.update(params.keys())

        params_path = targets_dir / "all_params.txt"
        params_path.write_text("\n".join(sorted(all_params)))
        exported["all_params"] = params_path

        # === 7. Live Hosts for scanning ===
        live_urls = []
        for host in hosts:
            if host.get("is_alive", True):
                url = host.get("url", "")
                if url:
                    live_urls.append(url)

        live_path = targets_dir / "live_urls.txt"
        live_path.write_text("\n".join(live_urls))
        exported["live_urls"] = live_path

        # === 8. Next Steps Summary ===
        next_steps = self._generate_next_steps(
            domain=domain,
            fuzz_count=len(fuzz_urls),
            origin_count=len(origin_lines),
            sqli_count=len(sqli_urls),
            ssrf_count=len(ssrf_urls),
            lfi_count=len(lfi_urls),
            findings=findings,
            hosts=hosts,
            all_params=all_params,
        )
        next_path = targets_dir / "next_steps.md"
        next_path.write_text(next_steps)
        exported["next_steps"] = next_path

        logger.info(f"Exported pentester targets to {targets_dir}")
        return exported

    def _generate_next_steps(
        self,
        domain: str,
        fuzz_count: int,
        origin_count: int,
        sqli_count: int,
        ssrf_count: int,
        lfi_count: int,
        findings: list,
        hosts: list,
        all_params: set,
    ) -> str:
        """Generate prioritized next steps for pentester."""

        # Count findings by severity
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        medium = sum(1 for f in findings if f.get("severity") == "medium")

        lines = [
            f"# Next Steps - {domain}",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "",
            "## Priority Actions",
            "",
        ]

        priority = 1

        # Critical/High findings first
        if critical > 0:
            lines.append(f"### {priority}. 🔴 Validate {critical} CRITICAL findings")
            lines.append("```bash")
            lines.append("# Review findings.json for critical vulnerabilities")
            lines.append(f"cat findings.json | jq '.[] | select(.severity==\"critical\")'")
            lines.append("```")
            lines.append("")
            priority += 1

        if high > 0:
            lines.append(f"### {priority}. 🟠 Investigate {high} HIGH findings")
            lines.append("```bash")
            lines.append(f"cat findings.json | jq '.[] | select(.severity==\"high\")'")
            lines.append("```")
            lines.append("")
            priority += 1

        # Origin IPs - WAF bypass
        if origin_count > 0:
            lines.append(f"### {priority}. 🎯 Test {origin_count} Origin IPs (WAF Bypass)")
            lines.append("Direct access to origin bypasses CDN/WAF protections.")
            lines.append("```bash")
            lines.append("# Verify origin responds")
            lines.append(f"while read ip; do curl -sk -H 'Host: {domain}' \"https://$ip\" | head -20; done < targets/origin_ips.txt")
            lines.append("")
            lines.append("# Full port scan on origins")
            lines.append("nmap -sV -sC -p- -iL targets/origin_ips.txt -oA origin_scan")
            lines.append("")
            lines.append("# Directory brute on origin")
            lines.append(f"ffuf -u 'https://ORIGIN/FUZZ' -H 'Host: {domain}' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt")
            lines.append("```")
            lines.append("")
            priority += 1

        # SQLi candidates
        if sqli_count > 0:
            lines.append(f"### {priority}. 💉 Test {sqli_count} SQLi Candidates")
            lines.append("URLs with id/user/order parameters - classic injection points.")
            lines.append("```bash")
            lines.append("# Quick SQLi test with sqlmap")
            lines.append("sqlmap -m targets/sqli_candidates.txt --batch --risk=2 --level=3")
            lines.append("")
            lines.append("# Or manual testing")
            lines.append("cat targets/sqli_candidates.txt | qsreplace \"'\" | httpx -silent -mc 500")
            lines.append("```")
            lines.append("")
            priority += 1

        # SSRF candidates
        if ssrf_count > 0:
            lines.append(f"### {priority}. 🔗 Test {ssrf_count} SSRF/Redirect Candidates")
            lines.append("URLs with redirect/url/callback parameters.")
            lines.append("```bash")
            lines.append("# Test for open redirect")
            lines.append("cat targets/ssrf_candidates.txt | qsreplace 'https://evil.com' | httpx -silent -location")
            lines.append("")
            lines.append("# Test for SSRF (use your collaborator)")
            lines.append("cat targets/ssrf_candidates.txt | qsreplace 'http://YOUR-BURP-COLLAB' | httpx -silent")
            lines.append("```")
            lines.append("")
            priority += 1

        # LFI candidates
        if lfi_count > 0:
            lines.append(f"### {priority}. 📁 Test {lfi_count} LFI Candidates")
            lines.append("URLs with file/path/template parameters.")
            lines.append("```bash")
            lines.append("# Test for LFI")
            lines.append("cat targets/lfi_candidates.txt | qsreplace '../../../../etc/passwd' | httpx -silent -sr -mc 200")
            lines.append("")
            lines.append("# With ffuf")
            lines.append("ffuf -u 'URL' -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt")
            lines.append("```")
            lines.append("")
            priority += 1

        # Parameter fuzzing
        if fuzz_count > 0:
            lines.append(f"### {priority}. 🔨 Fuzz {fuzz_count} URLs with Parameters")
            lines.append("```bash")
            lines.append("# Fuzz all parameters with common payloads")
            lines.append("cat targets/fuzz_urls.txt | qsreplace FUZZ | ffuf -u FUZZ -w payloads.txt")
            lines.append("")
            lines.append("# XSS testing")
            lines.append("cat targets/fuzz_urls.txt | dalfox pipe --skip-bav")
            lines.append("```")
            lines.append("")
            priority += 1

        # Content discovery on live hosts
        live_count = sum(1 for h in hosts if h.get("is_alive", True))
        if live_count > 0:
            lines.append(f"### {priority}. 🔍 Content Discovery on {live_count} Live Hosts")
            lines.append("```bash")
            lines.append("# Directory bruteforce")
            lines.append("feroxbuster -L targets/live_urls.txt -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt")
            lines.append("")
            lines.append("# Find hidden endpoints")
            lines.append("katana -list targets/live_urls.txt -d 3 -jc | tee discovered_endpoints.txt")
            lines.append("```")
            lines.append("")
            priority += 1

        # Parameter discovery
        if all_params:
            lines.append(f"### {priority}. 🔎 Discovered {len(all_params)} Unique Parameters")
            lines.append("Use these for parameter mining on other endpoints.")
            lines.append("```bash")
            lines.append("# Use discovered params as wordlist for arjun")
            lines.append("arjun -i targets/live_urls.txt -w targets/all_params.txt")
            lines.append("```")
            lines.append("")

        # Summary table
        lines.extend([
            "---",
            "## Target Summary",
            "",
            "| Category | Count | File |",
            "|----------|-------|------|",
            f"| URLs with params | {fuzz_count} | `targets/fuzz_urls.txt` |",
            f"| Origin IPs | {origin_count} | `targets/origin_ips.txt` |",
            f"| SQLi candidates | {sqli_count} | `targets/sqli_candidates.txt` |",
            f"| SSRF candidates | {ssrf_count} | `targets/ssrf_candidates.txt` |",
            f"| LFI candidates | {lfi_count} | `targets/lfi_candidates.txt` |",
            f"| Unique params | {len(all_params)} | `targets/all_params.txt` |",
            f"| Live hosts | {live_count} | `targets/live_urls.txt` |",
            "",
            "---",
            "*Generated by Reconductor*",
        ])

        return "\n".join(lines)

    def _generate_ai_impact_section(self, stats: dict[str, Any]) -> str:
        """Generate AI wordlist impact section for report.html."""
        ai_count = stats.get("ai_wordlist_count", 0)
        ai_hits = stats.get("ai_wordlist_hits", 0)
        ai_hit_rate = stats.get("ai_hit_rate", 0.0)
        ai_unique = stats.get("ai_unique_finds", 0)

        # Only show if AI was used
        if ai_count == 0:
            return ""

        # Determine impact level for color
        if ai_hit_rate >= 10:
            impact_class = "high-impact"
            impact_color = "#3fb950"  # green
        elif ai_hit_rate >= 5:
            impact_class = "medium-impact"
            impact_color = "#d29922"  # yellow
        else:
            impact_class = "low-impact"
            impact_color = "#8b949e"  # gray

        return f"""
        <div class="ai-impact-section">
            <h3>AI Wordlist Impact</h3>
            <div class="ai-impact-grid">
                <div class="ai-stat">
                    <div class="ai-stat-number">{ai_count}</div>
                    <div class="ai-stat-label">Generated</div>
                </div>
                <div class="ai-stat">
                    <div class="ai-stat-number" style="color: {impact_color}">{ai_hits}</div>
                    <div class="ai-stat-label">Hits</div>
                </div>
                <div class="ai-stat">
                    <div class="ai-stat-number" style="color: {impact_color}">{ai_hit_rate}%</div>
                    <div class="ai-stat-label">Hit Rate</div>
                </div>
                <div class="ai-stat">
                    <div class="ai-stat-number" style="color: #58a6ff">{ai_unique}</div>
                    <div class="ai-stat-label">Unique Finds</div>
                </div>
            </div>
        </div>
        """

    def _generate_origin_ip_section(self, scan_result: dict[str, Any]) -> str:
        """Generate origin IP discovery section for report.html."""
        origin_discovery = scan_result.get("origin_discovery") or {}
        origin_ips = scan_result.get("origin_ips", [])

        # Check if origin discovery was run
        if not origin_discovery and not origin_ips:
            return ""

        is_behind_cdn = origin_discovery.get("is_behind_cdn", False)
        cdn_provider = origin_discovery.get("cdn_provider", "Unknown")
        confirmed_origins = origin_discovery.get("confirmed_origins", [])
        candidates = origin_discovery.get("candidates", [])

        # If not behind CDN, don't show section
        if not is_behind_cdn and not origin_ips:
            return ""

        # Generate confirmed origins table
        confirmed_rows = ""
        if confirmed_origins:
            for origin in confirmed_origins:
                ip = origin.get("ip", "")
                score = origin.get("validation_score", 0)
                sources = ", ".join(origin.get("sources", [])[:3])
                hostnames = ", ".join(origin.get("hostnames", [])[:2]) or "-"
                score_pct = f"{score * 100:.0f}%" if score else "-"

                confirmed_rows += f'''
                <tr class="origin-confirmed">
                    <td><strong>{ip}</strong></td>
                    <td><span class="origin-score confirmed">{score_pct}</span></td>
                    <td>{sources}</td>
                    <td class="origin-hostname">{hostnames}</td>
                </tr>'''

        # Generate candidate rows
        candidate_rows = ""
        if candidates:
            for candidate in candidates[:5]:
                ip = candidate.get("ip", "")
                confidence = candidate.get("confidence", "low")
                sources = ", ".join(candidate.get("sources", [])[:3])
                hostnames = ", ".join(candidate.get("hostnames", [])[:2]) or "-"

                conf_class = {"high": "high", "medium": "medium", "low": "low"}.get(confidence, "low")
                candidate_rows += f'''
                <tr>
                    <td>{ip}</td>
                    <td><span class="origin-confidence {conf_class}">{confidence.upper()}</span></td>
                    <td>{sources}</td>
                    <td class="origin-hostname">{hostnames}</td>
                </tr>'''

        # Build section HTML
        confirmed_count = len(confirmed_origins)
        candidate_count = len(candidates)

        section = f'''
        <section class="origin-discovery-section">
            <h2>Origin IP Discovery
                <span class="origin-cdn-badge">{cdn_provider}</span>
                {f'<span class="origin-confirmed-count">{confirmed_count} CONFIRMED</span>' if confirmed_count else ''}
            </h2>

            <div class="origin-summary">
                <p>Target is behind <strong>{cdn_provider}</strong> CDN/WAF.
                {'<span class="origin-success">Origin IP(s) confirmed via HTTP validation.</span>' if confirmed_count else
                 f'{candidate_count} candidate IPs found (unconfirmed).' if candidate_count else
                 'No origin IPs discovered.'}
                </p>
            </div>

            {f"""
            <div class="origin-confirmed-section">
                <h3>Confirmed Origins</h3>
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Validation</th>
                            <th>Sources</th>
                            <th>Hostnames</th>
                        </tr>
                    </thead>
                    <tbody>{confirmed_rows}</tbody>
                </table>
            </div>
            """ if confirmed_rows else ""}

            {f"""
            <div class="origin-candidates-section">
                <h3>Candidate IPs {'(Unconfirmed)' if not confirmed_count else ''}</h3>
                <table>
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Confidence</th>
                            <th>Sources</th>
                            <th>Hostnames</th>
                        </tr>
                    </thead>
                    <tbody>{candidate_rows}</tbody>
                </table>
                {f'<div class="origin-more">...and {candidate_count - 5} more candidates</div>' if candidate_count > 5 else ''}
            </div>
            """ if candidate_rows else ""}

            <div class="origin-verify">
                <strong>Verify with:</strong>
                <code>curl -H 'Host: {scan_result.get("domain", "example.com")}' https://&lt;IP&gt; -k</code>
            </div>
        </section>

        <style>
            .origin-discovery-section {{
                margin-top: 2rem;
                padding: 1.5rem;
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                border-radius: 8px;
                border: 1px solid #0f3460;
            }}
            .origin-discovery-section h2 {{
                display: flex;
                align-items: center;
                gap: 1rem;
                margin-bottom: 1rem;
            }}
            .origin-cdn-badge {{
                font-size: 0.75rem;
                padding: 0.25rem 0.5rem;
                background: #f8514920;
                color: #f85149;
                border-radius: 4px;
                font-weight: normal;
            }}
            .origin-confirmed-count {{
                font-size: 0.75rem;
                padding: 0.25rem 0.5rem;
                background: #3fb95020;
                color: #3fb950;
                border-radius: 4px;
                font-weight: normal;
            }}
            .origin-summary {{
                margin-bottom: 1.5rem;
                color: #8b949e;
            }}
            .origin-success {{
                color: #3fb950;
                font-weight: 600;
            }}
            .origin-confirmed-section, .origin-candidates-section {{
                margin-bottom: 1.5rem;
            }}
            .origin-confirmed-section h3 {{
                color: #3fb950;
                margin-bottom: 0.5rem;
            }}
            .origin-candidates-section h3 {{
                color: #d29922;
                margin-bottom: 0.5rem;
            }}
            .origin-score.confirmed {{
                background: #3fb95030;
                color: #3fb950;
                padding: 0.2rem 0.5rem;
                border-radius: 4px;
                font-weight: 600;
            }}
            .origin-confidence {{
                padding: 0.2rem 0.5rem;
                border-radius: 4px;
                font-size: 0.75rem;
                font-weight: 600;
            }}
            .origin-confidence.high {{ background: #3fb95020; color: #3fb950; }}
            .origin-confidence.medium {{ background: #d2992220; color: #d29922; }}
            .origin-confidence.low {{ background: #8b949e20; color: #8b949e; }}
            tr.origin-confirmed {{
                background: #3fb95010;
            }}
            .origin-hostname {{
                font-family: monospace;
                font-size: 0.85rem;
                color: #8b949e;
            }}
            .origin-more {{
                color: #8b949e;
                font-size: 0.85rem;
                margin-top: 0.5rem;
            }}
            .origin-verify {{
                margin-top: 1rem;
                padding: 0.75rem;
                background: #21262d;
                border-radius: 4px;
                font-size: 0.85rem;
            }}
            .origin-verify code {{
                background: #30363d;
                padding: 0.25rem 0.5rem;
                border-radius: 3px;
                margin-left: 0.5rem;
            }}
        </style>
        '''

        return section

    def _generate_origin_scan_section(self, scan_result: dict[str, Any]) -> str:
        """Generate origin nuclei scan results section for report.html."""
        origin_scan = scan_result.get("origin_scan")
        if not origin_scan:
            return ""

        findings = origin_scan.get("findings", [])
        version_info = origin_scan.get("version_info", {})
        summary = origin_scan.get("summary", {})
        origin_ips = origin_scan.get("origin_ips", [])

        if not findings and not version_info:
            return ""

        # Count findings by severity
        critical = summary.get("critical", 0)
        high = summary.get("high", 0)
        medium = summary.get("medium", 0)
        low = summary.get("low", 0)
        info = summary.get("info", 0)
        total = len(findings)

        # Generate version disclosure cards
        version_cards = ""
        unique_versions = set(version_info.values())
        for version in unique_versions:
            # Determine severity based on EOL status
            is_eol = "7.4" in version or "5.6" in version or "5.5" in version  # PHP EOL versions
            severity_class = "high" if is_eol else "info"
            eol_badge = '<span class="eol-badge">END OF LIFE</span>' if is_eol else ''

            version_cards += f'''
            <div class="version-card {severity_class}">
                <div class="version-header">
                    <span class="version-text">{version}</span>
                    {eol_badge}
                </div>
                <div class="version-note">Hidden behind CDN - exposed on origin</div>
            </div>'''

        # Generate finding rows grouped by severity
        finding_rows = ""
        by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for f in findings:
            sev = f.get("severity", "info")
            if sev not in by_severity:
                sev = "info"
            by_severity[sev].append(f)

        # Only show unique findings (deduplicate by template_id)
        seen_templates = set()
        for sev in ["critical", "high", "medium", "low", "info"]:
            for f in by_severity[sev]:
                template_id = f.get("template_id", "")
                if template_id in seen_templates:
                    continue
                seen_templates.add(template_id)

                name = f.get("name", "Unknown")
                matched_at = f.get("matched_at", "")
                tags = ", ".join(f.get("tags", [])[:3]) if f.get("tags") else "-"

                finding_rows += f'''
                <tr class="finding-{sev}">
                    <td><span class="severity-badge {sev}">{sev.upper()}</span></td>
                    <td><strong>{name}</strong></td>
                    <td class="matched-url">{matched_at}</td>
                    <td class="finding-tags">{tags}</td>
                </tr>'''

        # Severity badge colors
        severity_stats = f'''
            <div class="origin-scan-stats">
                {f'<span class="stat critical">{critical} Critical</span>' if critical else ''}
                {f'<span class="stat high">{high} High</span>' if high else ''}
                {f'<span class="stat medium">{medium} Medium</span>' if medium else ''}
                {f'<span class="stat low">{low} Low</span>' if low else ''}
                {f'<span class="stat info">{info} Info</span>' if info else ''}
            </div>
        '''

        section = f'''
        <section class="origin-scan-section">
            <h2>
                <span class="waf-bypass-icon">🛡️⚡</span>
                Origin Scan (WAF Bypass)
                <span class="scan-count">{total} findings</span>
            </h2>

            <div class="origin-scan-summary">
                <p>Nuclei scan ran directly against <strong>{len(origin_ips)} origin IPs</strong>,
                bypassing CDN/WAF protections. These findings are <strong>not visible</strong> through the CDN.</p>
            </div>

            {severity_stats}

            {f"""
            <div class="version-disclosure">
                <h3>🔓 Version Disclosure (Hidden by CDN)</h3>
                <div class="version-grid">
                    {version_cards}
                </div>
            </div>
            """ if version_cards else ""}

            {f"""
            <div class="origin-findings">
                <h3>Vulnerability Findings</h3>
                <table>
                    <thead>
                        <tr>
                            <th style="width:100px">Severity</th>
                            <th>Finding</th>
                            <th>URL</th>
                            <th>Tags</th>
                        </tr>
                    </thead>
                    <tbody>{finding_rows}</tbody>
                </table>
            </div>
            """ if finding_rows else ""}
        </section>

        <style>
            .origin-scan-section {{
                margin-top: 2rem;
                padding: 1.5rem;
                background: linear-gradient(135deg, #2d1b4e 0%, #1a1a2e 100%);
                border-radius: 8px;
                border: 1px solid #6e40c9;
            }}
            .origin-scan-section h2 {{
                display: flex;
                align-items: center;
                gap: 0.75rem;
                margin-bottom: 1rem;
                color: #a371f7;
            }}
            .waf-bypass-icon {{
                font-size: 1.5rem;
            }}
            .scan-count {{
                font-size: 0.75rem;
                padding: 0.25rem 0.75rem;
                background: #a371f720;
                color: #a371f7;
                border-radius: 12px;
                font-weight: normal;
            }}
            .origin-scan-summary {{
                color: #8b949e;
                margin-bottom: 1rem;
            }}
            .origin-scan-stats {{
                display: flex;
                gap: 0.75rem;
                margin-bottom: 1.5rem;
                flex-wrap: wrap;
            }}
            .origin-scan-stats .stat {{
                padding: 0.5rem 1rem;
                border-radius: 6px;
                font-weight: 600;
                font-size: 0.85rem;
            }}
            .stat.critical {{ background: #f8514930; color: #f85149; }}
            .stat.high {{ background: #db6d2830; color: #db6d28; }}
            .stat.medium {{ background: #d2992230; color: #d29922; }}
            .stat.low {{ background: #58a6ff30; color: #58a6ff; }}
            .stat.info {{ background: #8b949e30; color: #8b949e; }}

            .version-disclosure {{
                margin-bottom: 1.5rem;
            }}
            .version-disclosure h3 {{
                color: #f85149;
                margin-bottom: 0.75rem;
            }}
            .version-grid {{
                display: flex;
                gap: 1rem;
                flex-wrap: wrap;
            }}
            .version-card {{
                padding: 1rem;
                background: #21262d;
                border-radius: 6px;
                border-left: 3px solid #8b949e;
                min-width: 200px;
            }}
            .version-card.high {{
                border-left-color: #f85149;
                background: #f8514910;
            }}
            .version-card.info {{
                border-left-color: #58a6ff;
            }}
            .version-header {{
                display: flex;
                align-items: center;
                gap: 0.5rem;
            }}
            .version-text {{
                font-family: monospace;
                font-size: 0.95rem;
                color: #e6edf3;
            }}
            .eol-badge {{
                font-size: 0.65rem;
                padding: 0.15rem 0.4rem;
                background: #f85149;
                color: white;
                border-radius: 3px;
                font-weight: 600;
            }}
            .version-note {{
                font-size: 0.75rem;
                color: #8b949e;
                margin-top: 0.5rem;
            }}

            .origin-findings h3 {{
                color: #a371f7;
                margin-bottom: 0.75rem;
            }}
            .origin-findings table {{
                width: 100%;
            }}
            .severity-badge {{
                padding: 0.2rem 0.5rem;
                border-radius: 4px;
                font-size: 0.7rem;
                font-weight: 600;
            }}
            .severity-badge.critical {{ background: #f85149; color: white; }}
            .severity-badge.high {{ background: #db6d28; color: white; }}
            .severity-badge.medium {{ background: #d29922; color: #000; }}
            .severity-badge.low {{ background: #58a6ff; color: white; }}
            .severity-badge.info {{ background: #8b949e; color: white; }}

            tr.finding-critical {{ background: #f8514910; }}
            tr.finding-high {{ background: #db6d2810; }}
            tr.finding-medium {{ background: #d2992210; }}

            .matched-url {{
                font-family: monospace;
                font-size: 0.8rem;
                max-width: 300px;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                color: #8b949e;
            }}
            .finding-tags {{
                font-size: 0.75rem;
                color: #6e7681;
            }}
        </style>
        '''

        return section

    def _generate_gau_section(self, scan_result: dict[str, Any]) -> str:
        """Generate GAU historical URLs section for report.html."""
        stats = scan_result.get("stats", {})
        gau_total = stats.get("gau_total_urls", 0)
        gau_unique = stats.get("gau_unique_urls", 0)
        gau_with_params = stats.get("gau_urls_with_params", 0)
        gau_categories = stats.get("gau_categories", 0)
        gau_ai_selected = stats.get("gau_targets_selected", 0)

        # Don't show section if GAU wasn't run
        if gau_total == 0:
            return ""

        # Get gau_result for detailed categorized URLs if available
        gau_result = scan_result.get("gau_result")

        # Category labels with colors and descriptions
        category_info = {
            "ssrf_candidates": ("SSRF", "#f85149"),
            "lfi_candidates": ("LFI", "#db6d28"),
            "sqli_candidates": ("SQLi", "#d29922"),
            "xss_candidates": ("XSS", "#a371f7"),
            "open_redirect": ("Redirect", "#f85149"),
            "rce_candidates": ("RCE", "#f85149"),
            "api_endpoints": ("API", "#58a6ff"),
            "auth_endpoints": ("Auth", "#3fb950"),
            "admin_paths": ("Admin", "#d29922"),
            "debug_paths": ("Debug", "#f85149"),
            "file_operations": ("File Ops", "#db6d28"),
            "param_urls": ("Params", "#8b949e"),
        }

        # Generate category breakdown if gau_result available
        category_badges = ""
        sample_urls = ""
        ai_filtered_section = ""

        if gau_result and hasattr(gau_result, 'categorized_urls'):
            # Generate category badges
            badges = []
            for cat, urls in gau_result.categorized_urls.items():
                if urls:
                    label, color = category_info.get(cat, (cat.replace("_", " ").title(), "#8b949e"))
                    badges.append(f'<span class="gau-cat-badge" style="border-color: {color}; color: {color}">{label}: {len(urls)}</span>')
            category_badges = " ".join(badges[:8])  # Limit to 8 badges

            # Check for AI-filtered high-value URLs
            high_value_urls = getattr(gau_result, 'high_value_urls', None)
            filter_stats = getattr(gau_result, 'filter_stats', None)

            if high_value_urls:
                # AI triage was enabled - show filtered URLs
                ai_method = filter_stats.get("method", "unknown") if filter_stats else "ai"
                ai_filtered_rows = ""
                for url in high_value_urls[:15]:
                    truncated_url = url[:100] + "..." if len(url) > 100 else url
                    escaped_url = (url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))
                    ai_filtered_rows += f'''
                    <tr>
                        <td class="gau-url-cell"><a href="{escaped_url}" target="_blank">{truncated_url}</a></td>
                    </tr>'''

                ai_filtered_section = f'''
                <div class="gau-ai-filtered">
                    <div class="gau-ai-header">
                        <span class="gau-ai-badge">AI Filtered</span>
                        <span class="gau-ai-count">{len(high_value_urls)} high-value URLs selected</span>
                        <span class="gau-ai-method">Method: {ai_method}</span>
                    </div>
                    <table>
                        <tbody>{ai_filtered_rows}</tbody>
                    </table>
                    {f'<div class="gau-more">...and {len(high_value_urls) - 15} more URLs</div>' if len(high_value_urls) > 15 else ''}
                </div>'''
            else:
                # No AI filtering - show heuristic samples
                high_value_cats = ["sqli_candidates", "ssrf_candidates", "lfi_candidates", "rce_candidates", "xss_candidates", "auth_endpoints", "api_endpoints"]
                sample_url_list = []
                for cat in high_value_cats:
                    if cat in gau_result.categorized_urls:
                        for url_obj in gau_result.categorized_urls[cat][:3]:
                            url_str = url_obj.url if hasattr(url_obj, 'url') else str(url_obj)
                            if url_str not in [u[1] for u in sample_url_list]:
                                label, color = category_info.get(cat, (cat, "#8b949e"))
                                sample_url_list.append((label, url_str, color))
                                if len(sample_url_list) >= 10:
                                    break
                        if len(sample_url_list) >= 10:
                            break

                if sample_url_list:
                    sample_rows = ""
                    for label, url, color in sample_url_list:
                        truncated_url = url[:100] + "..." if len(url) > 100 else url
                        escaped_url = (url.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))
                        sample_rows += f'''
                        <tr>
                            <td><span class="gau-type-badge" style="background: {color}20; color: {color}">{label}</span></td>
                            <td class="gau-url-cell"><a href="{escaped_url}" target="_blank">{truncated_url}</a></td>
                        </tr>'''
                    sample_urls = f'''
                    <div class="gau-samples">
                        <h4>High-Value URL Samples</h4>
                        <table>
                            <tbody>{sample_rows}</tbody>
                        </table>
                    </div>'''

        # Build AI stat if available
        ai_stat_html = ""
        if gau_ai_selected > 0:
            ai_stat_html = f'''
                    <div class="gau-stat">
                        <span class="gau-stat-number" style="color: #a371f7">{gau_ai_selected}</span>
                        <span class="gau-stat-label">AI Selected</span>
                    </div>'''

        return f"""
        <section class="gau-section">
            <h2>Historical URLs (GAU) <span class="count">{gau_unique}</span></h2>
            <div class="gau-content">
                <div class="gau-stats-row">
                    <div class="gau-stat">
                        <span class="gau-stat-number">{gau_total}</span>
                        <span class="gau-stat-label">Total URLs</span>
                    </div>
                    <div class="gau-stat">
                        <span class="gau-stat-number">{gau_unique}</span>
                        <span class="gau-stat-label">Unique</span>
                    </div>
                    <div class="gau-stat">
                        <span class="gau-stat-number" style="color: #d29922">{gau_with_params}</span>
                        <span class="gau-stat-label">With Params</span>
                    </div>
                    <div class="gau-stat">
                        <span class="gau-stat-number">{gau_categories}</span>
                        <span class="gau-stat-label">Categories</span>
                    </div>{ai_stat_html}
                </div>
                {f'<div class="gau-categories">{category_badges}</div>' if category_badges else ''}
                {ai_filtered_section}
                {sample_urls}
                <div class="gau-footer">
                    <a href="gau_findings.html" class="gau-link">View Full GAU Report →</a>
                </div>
            </div>
        </section>
        """

    def _load_triage_report(self) -> Optional[dict[str, Any]]:
        """Load triage report if it exists."""
        triage_path = self.output_dir / "triage_report.json"
        if triage_path.exists():
            try:
                return json.loads(triage_path.read_text())
            except Exception:
                pass
        return None

    def export_html_report(self, scan_result: dict[str, Any]) -> Path:
        """Export raw HTML report with Nuclei findings and live hosts (no AI triage)."""
        output_path = self.output_dir / "report.html"

        domain = scan_result.get("domain", "Unknown")
        stats = scan_result.get("stats", {})
        subdomains = scan_result.get("subdomains", [])
        hosts = scan_result.get("hosts", [])
        findings = scan_result.get("findings", [])

        # Calculate severity counts
        critical = stats.get("findings_critical", 0)
        high = stats.get("findings_high", 0)
        medium = stats.get("findings_medium", 0)
        low = stats.get("findings_low", 0)
        info = stats.get("findings_info", 0)

        def get_status_color(status):
            """Get color class for HTTP status code."""
            try:
                code = int(status)
                if 200 <= code < 300:
                    return "status-2xx"
                elif 300 <= code < 400:
                    return "status-3xx"
                elif 400 <= code < 500:
                    return "status-4xx"
                elif 500 <= code < 600:
                    return "status-5xx"
            except (ValueError, TypeError):
                pass
            return "status-unknown"

        def escape_html(text: str) -> str:
            """Escape HTML special characters."""
            if not text:
                return ""
            return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))

        # Generate host rows
        host_rows = ""
        for host in hosts[:150]:
            hostname = host.get("hostname", "")
            status = host.get("status_code", "-")
            status_class = get_status_color(status)
            title = escape_html((host.get("title") or "")[:60])
            tech = escape_html(", ".join(host.get("technologies", [])[:3])) or "-"
            cdn = host.get("cdn_provider") or "-"
            url = host.get("url") or f"https://{hostname}"
            content_length = host.get("content_length", "-")
            webserver = escape_html(host.get("webserver", "-") or "-")

            host_rows += f"""
            <tr>
                <td><a href="{url}" target="_blank" class="host-link">{hostname}</a></td>
                <td><span class="status-badge {status_class}">{status}</span></td>
                <td class="title-cell">{title}</td>
                <td class="tech-cell">{tech}</td>
                <td class="server-cell">{webserver}</td>
                <td class="cdn-cell">{cdn}</td>
            </tr>"""

        # Generate detailed finding cards
        finding_cards = ""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(
            (f.get("severity", {}).get("value", f.get("severity", "info")) if isinstance(f.get("severity"), dict) else f.get("severity", "info")).lower(), 5
        ))

        for idx, finding in enumerate(sorted_findings[:50], 1):
            sev = finding.get("severity", "info")
            if isinstance(sev, dict):
                sev = sev.get("value", "info")
            sev = sev.lower()

            template = finding.get("template_id", "unknown")
            location = finding.get("matched_at") or finding.get("target", "unknown")
            title = escape_html(finding.get("title", template))
            description = escape_html(finding.get("description", ""))
            remediation_text = escape_html(finding.get("remediation", ""))

            # Extract CVE and CVSS
            cve_id = finding.get("cve_id") or ""
            cvss_score = finding.get("cvss_score") or ""
            classification = finding.get("classification", {})
            if not cve_id and classification:
                cve_ids = classification.get("cve-id", [])
                if cve_ids:
                    cve_id = cve_ids[0] if isinstance(cve_ids, list) else cve_ids
            if not cvss_score and classification:
                cvss_score = classification.get("cvss-score", "")

            # References
            refs = finding.get("references", [])
            refs_html = ""
            if refs:
                refs_links = " ".join([f'<a href="{r}" target="_blank">[{i+1}]</a>' for i, r in enumerate(refs[:5])])
                refs_html = f'<div class="finding-refs">References: {refs_links}</div>'

            # Tags
            tags = finding.get("tags", [])
            tags_html = ""
            if tags:
                tags_badges = " ".join([f'<span class="tag">{escape_html(t)}</span>' for t in tags[:6]])
                tags_html = f'<div class="finding-tags">{tags_badges}</div>'

            # Evidence/Extracted results
            extracted = finding.get("extracted_results", [])
            evidence_html = ""
            if extracted:
                evidence_items = "<br>".join([escape_html(str(e))[:100] for e in extracted[:3]])
                evidence_html = f'<div class="finding-evidence"><span class="field-label">Evidence:</span><code>{evidence_items}</code></div>'

            finding_cards += f"""
            <div class="finding-card finding-{sev}">
                <div class="finding-header">
                    <span class="severity-badge severity-{sev}">{sev.upper()}</span>
                    <span class="finding-title">{title}</span>
                    {f'<span class="cvss-badge">CVSS {cvss_score}</span>' if cvss_score else ''}
                    {f'<span class="cve-badge">{cve_id}</span>' if cve_id else ''}
                </div>
                <div class="finding-body">
                    <div class="finding-meta">
                        <span><strong>Target:</strong> <a href="{location}" target="_blank">{location}</a></span>
                        <span><strong>Template:</strong> <code>{template}</code></span>
                    </div>
                    {f'<div class="finding-desc">{description}</div>' if description else ''}
                    {evidence_html}
                    {f'<div class="finding-remediation"><span class="field-label">Remediation:</span> {remediation_text}</div>' if remediation_text else ''}
                    {tags_html}
                    {refs_html}
                </div>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconDuctor Report - {domain}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-dark: #0d1117;
            --bg-card: #161b22;
            --bg-card-hover: #1c2128;
            --border-color: #30363d;
            --text-primary: #f0f6fc;
            --text-secondary: #c9d1d9;
            --text-muted: #a0a8b0;
            --accent: #58a6ff;
            --accent-subtle: #388bfd26;
            --critical: #f85149;
            --high: #db6d28;
            --medium: #d29922;
            --low: #58a6ff;
            --info: #8b949e;
            --success: #3fb950;
            --redirect: #a371f7;
            --warning: #d29922;
            --error: #f85149;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Inter', 'Roboto', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            line-height: 1.7;
            font-size: 16px;
            -webkit-font-smoothing: antialiased;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}

        /* Header */
        header {{
            text-align: center;
            padding: 48px 24px;
            background: linear-gradient(180deg, var(--bg-card) 0%, var(--bg-dark) 100%);
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 32px;
        }}
        header h1 {{
            font-size: 2.25rem;
            font-weight: 700;
            margin-bottom: 8px;
            color: var(--text-primary);
            letter-spacing: -0.5px;
        }}
        header .domain {{
            font-size: 1.75rem;
            color: var(--accent);
            font-weight: 600;
            margin-bottom: 16px;
        }}
        header .meta {{
            color: var(--text-secondary);
            font-size: 1rem;
        }}
        header .meta span {{
            margin: 0 8px;
        }}

        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 24px;
            text-align: center;
            transition: border-color 0.2s;
        }}
        .stat-card:hover {{
            border-color: var(--accent);
        }}
        .stat-card .number {{
            font-size: 2.75rem;
            font-weight: 700;
            color: var(--accent);
            line-height: 1.2;
        }}
        .stat-card .label {{
            color: var(--text-secondary);
            font-size: 1rem;
            margin-top: 8px;
            font-weight: 500;
        }}

        /* AI Impact Section */
        .ai-impact-section {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-left: 4px solid #a371f7;
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 24px;
        }}
        .ai-impact-section h3 {{
            color: #a371f7;
            font-size: 0.9rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .ai-impact-section h3::before {{
            content: "🤖";
        }}
        .ai-impact-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
        }}
        .ai-stat {{
            text-align: center;
        }}
        .ai-stat-number {{
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--text-primary);
        }}
        .ai-stat-label {{
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-top: 4px;
        }}

        /* Severity Cards */
        .severity-section {{
            margin-bottom: 24px;
        }}
        .severity-section h3 {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 12px;
        }}
        .severity-grid {{
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 12px;
        }}
        .severity-card {{
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid transparent;
        }}
        .severity-card .count {{
            font-size: 2rem;
            font-weight: 700;
        }}
        .severity-card .label {{
            font-size: 0.9rem;
            font-weight: 600;
            text-transform: uppercase;
            margin-top: 6px;
        }}
        .severity-card.critical {{ background: rgba(248, 81, 73, 0.15); border-color: var(--critical); color: var(--critical); }}
        .severity-card.high {{ background: rgba(219, 109, 40, 0.15); border-color: var(--high); color: var(--high); }}
        .severity-card.medium {{ background: rgba(210, 153, 34, 0.15); border-color: var(--medium); color: var(--medium); }}
        .severity-card.low {{ background: rgba(88, 166, 255, 0.15); border-color: var(--low); color: var(--low); }}
        .severity-card.info {{ background: rgba(139, 148, 158, 0.15); border-color: var(--info); color: var(--info); }}

        /* Sections */
        section {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 24px;
            overflow: hidden;
        }}
        section h2 {{
            color: var(--text-primary);
            font-size: 1.15rem;
            font-weight: 600;
            padding: 18px 24px;
            background: var(--bg-card);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        section h2 .count {{
            background: var(--accent-subtle);
            color: var(--accent);
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.9rem;
            font-weight: 600;
        }}

        /* Tables */
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            text-align: left;
            padding: 14px 20px;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            color: var(--text-secondary);
            background: var(--bg-dark);
            border-bottom: 1px solid var(--border-color);
        }}
        td {{
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: top;
            font-size: 0.95rem;
        }}
        tr:hover {{
            background: var(--bg-card-hover);
        }}
        tr:last-child td {{
            border-bottom: none;
        }}

        /* Status Badges */
        .status-badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85rem;
            font-weight: 600;
            font-family: 'JetBrains Mono', 'Fira Code', ui-monospace, monospace;
        }}
        .status-2xx {{ background: rgba(63, 185, 80, 0.2); color: var(--success); }}
        .status-3xx {{ background: rgba(163, 113, 247, 0.2); color: var(--redirect); }}
        .status-4xx {{ background: rgba(210, 153, 34, 0.2); color: var(--warning); }}
        .status-5xx {{ background: rgba(248, 81, 73, 0.2); color: var(--error); }}
        .status-unknown {{ background: rgba(139, 148, 158, 0.2); color: var(--text-secondary); }}

        /* Severity Badges */
        .severity-badge {{
            display: inline-block;
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .severity-critical {{ background: var(--critical); color: white; }}
        .severity-high {{ background: var(--high); color: white; }}
        .severity-medium {{ background: var(--medium); color: #000; }}
        .severity-low {{ background: var(--low); color: white; }}
        .severity-info {{ background: var(--info); color: white; }}

        /* Finding Rows */
        .finding-row {{
            border-left: 4px solid transparent;
        }}
        .finding-critical {{ border-left-color: var(--critical); }}
        .finding-high {{ border-left-color: var(--high); }}
        .finding-medium {{ border-left-color: var(--medium); }}
        .finding-low {{ border-left-color: var(--low); }}
        .finding-info {{ border-left-color: var(--info); }}

        .finding-title {{
            font-weight: 600;
            font-size: 1rem;
            color: var(--text-primary);
            margin-bottom: 6px;
        }}
        .finding-desc {{
            font-size: 0.9rem;
            color: var(--text-secondary);
            line-height: 1.5;
        }}

        /* Links and Code */
        a {{
            color: var(--accent);
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        .host-link {{
            font-weight: 600;
            font-size: 0.95rem;
        }}
        code, .template-id {{
            font-family: 'JetBrains Mono', 'Fira Code', ui-monospace, monospace;
            font-size: 0.85rem;
            background: var(--bg-dark);
            padding: 4px 8px;
            border-radius: 4px;
            color: var(--text-secondary);
        }}

        /* Cells */
        .title-cell {{
            color: var(--text-secondary);
            max-width: 280px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        .tech-cell {{
            font-size: 0.9rem;
            color: var(--text-muted);
        }}
        .cdn-cell {{
            font-size: 0.9rem;
            color: var(--text-muted);
        }}
        .location-cell {{
            word-break: break-all;
            max-width: 400px;
            font-size: 0.9rem;
        }}

        /* Triage Section */
        .triage-section {{
            margin-bottom: 24px;
        }}
        .triage-section h2 {{
            background: linear-gradient(90deg, rgba(163, 113, 247, 0.1), transparent);
            border-left: 4px solid var(--redirect);
        }}
        .exec-summary {{
            padding: 20px 24px;
            background: var(--bg-dark);
            border-bottom: 1px solid var(--border-color);
            color: var(--text-primary);
            font-size: 1.05rem;
            line-height: 1.8;
        }}
        .risk-items {{
            padding: 16px;
        }}
        .risk-item {{
            background: var(--bg-dark);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 12px;
            overflow: hidden;
        }}
        .risk-item.risk-critical {{ border-left: 4px solid var(--critical); }}
        .risk-item.risk-high {{ border-left: 4px solid var(--high); }}
        .risk-item.risk-medium {{ border-left: 4px solid var(--medium); }}
        .risk-item.risk-low {{ border-left: 4px solid var(--low); }}
        .risk-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 14px 16px;
            background: var(--bg-card);
            border-bottom: 1px solid var(--border-color);
        }}
        .risk-badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .risk-badge-critical {{ background: var(--critical); color: white; }}
        .risk-badge-high {{ background: var(--high); color: white; }}
        .risk-badge-medium {{ background: var(--medium); color: #000; }}
        .risk-badge-low {{ background: var(--low); color: white; }}
        .risk-title {{
            font-weight: 600;
            font-size: 1.1rem;
            color: var(--text-primary);
            flex: 1;
        }}
        .risk-env {{
            font-size: 0.8rem;
            color: var(--text-muted);
            padding: 4px 8px;
            background: var(--bg-dark);
            border-radius: 4px;
        }}
        .risk-body {{
            padding: 16px;
        }}
        .risk-field {{
            margin-bottom: 12px;
        }}
        .risk-field:last-child {{
            margin-bottom: 0;
        }}
        .field-label {{
            font-weight: 600;
            color: var(--text-secondary);
            font-size: 0.9rem;
            display: block;
            margin-bottom: 6px;
        }}
        .field-value {{
            color: var(--text-primary);
            font-size: 1rem;
            line-height: 1.6;
        }}
        .attack-chain {{
            color: #f0c14b;
            font-style: italic;
        }}
        .remediation {{
            color: #7ee787;
        }}

        /* Additional Findings */
        .additional-findings {{
            margin-top: 24px;
            padding: 16px;
            background: var(--bg-dark);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--info);
            border-radius: 8px;
        }}
        .additional-findings h3 {{
            margin: 0 0 12px 0;
            color: var(--text-primary);
            font-size: 1.1rem;
        }}
        .additional-findings h3 .count {{
            font-weight: 400;
            color: var(--text-muted);
            font-size: 0.9rem;
        }}
        .additional-findings p {{
            color: var(--text-secondary);
            margin: 8px 0;
            line-height: 1.6;
        }}
        .additional-findings .add-hosts {{
            font-size: 0.9rem;
            color: var(--text-muted);
        }}

        /* Finding Cards */
        .finding-cards {{
            padding: 16px;
        }}
        .finding-card {{
            background: var(--bg-dark);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 12px;
            overflow: hidden;
        }}
        .finding-card.finding-critical {{ border-left: 4px solid var(--critical); }}
        .finding-card.finding-high {{ border-left: 4px solid var(--high); }}
        .finding-card.finding-medium {{ border-left: 4px solid var(--medium); }}
        .finding-card.finding-low {{ border-left: 4px solid var(--low); }}
        .finding-card.finding-info {{ border-left: 4px solid var(--info); }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 14px 16px;
            background: var(--bg-card);
            border-bottom: 1px solid var(--border-color);
            flex-wrap: wrap;
        }}
        .finding-title {{
            font-weight: 600;
            color: var(--text-primary);
            flex: 1;
            min-width: 200px;
        }}
        .cvss-badge {{
            padding: 4px 8px;
            background: rgba(248, 81, 73, 0.2);
            color: var(--critical);
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
        }}
        .cve-badge {{
            padding: 4px 8px;
            background: rgba(219, 109, 40, 0.2);
            color: var(--high);
            border-radius: 4px;
            font-size: 0.8rem;
            font-family: 'JetBrains Mono', monospace;
        }}
        .finding-body {{
            padding: 16px;
        }}
        .finding-meta {{
            display: flex;
            gap: 24px;
            margin-bottom: 12px;
            flex-wrap: wrap;
        }}
        .finding-meta span {{
            font-size: 0.9rem;
            color: var(--text-secondary);
        }}
        .finding-desc {{
            color: var(--text-primary);
            margin-bottom: 12px;
            line-height: 1.6;
        }}
        .finding-evidence {{
            background: var(--bg-card);
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 12px;
        }}
        .finding-evidence code {{
            display: block;
            margin-top: 8px;
            white-space: pre-wrap;
            word-break: break-all;
        }}
        .finding-remediation {{
            background: rgba(63, 185, 80, 0.1);
            padding: 12px;
            border-radius: 4px;
            border-left: 3px solid var(--success);
            margin-bottom: 12px;
        }}
        .finding-tags {{
            display: flex;
            gap: 6px;
            flex-wrap: wrap;
            margin-bottom: 8px;
        }}
        .tag {{
            padding: 3px 8px;
            background: var(--accent-subtle);
            color: var(--accent);
            border-radius: 4px;
            font-size: 0.75rem;
        }}
        .finding-refs {{
            font-size: 0.85rem;
            color: var(--text-muted);
        }}
        .finding-refs a {{
            margin-right: 6px;
        }}

        /* GAU Section */
        .gau-section {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-left: 4px solid #58a6ff;
            border-radius: 8px;
            margin-bottom: 24px;
            overflow: hidden;
        }}
        .gau-section h2 {{
            background: linear-gradient(90deg, rgba(88, 166, 255, 0.1), transparent);
        }}
        .gau-content {{
            padding: 20px;
        }}
        .gau-stats-row {{
            display: flex;
            gap: 24px;
            margin-bottom: 16px;
            flex-wrap: wrap;
        }}
        .gau-stat {{
            text-align: center;
            min-width: 80px;
        }}
        .gau-stat-number {{
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--accent);
            display: block;
        }}
        .gau-stat-label {{
            font-size: 0.8rem;
            color: var(--text-muted);
        }}
        .gau-categories {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 16px;
        }}
        .gau-cat-badge {{
            display: inline-block;
            padding: 4px 10px;
            border: 1px solid;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 500;
        }}
        .gau-samples {{
            background: var(--bg-dark);
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 16px;
        }}
        .gau-samples h4 {{
            font-size: 0.9rem;
            color: var(--text-secondary);
            margin-bottom: 10px;
            font-weight: 600;
        }}
        .gau-samples table {{
            width: 100%;
        }}
        .gau-samples td {{
            padding: 8px 10px;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.85rem;
        }}
        .gau-samples tr:last-child td {{
            border-bottom: none;
        }}
        .gau-type-badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.75rem;
            font-weight: 600;
            white-space: nowrap;
        }}
        .gau-url-cell a {{
            color: var(--accent);
            text-decoration: none;
            word-break: break-all;
        }}
        .gau-url-cell a:hover {{
            text-decoration: underline;
        }}
        .gau-footer {{
            text-align: right;
        }}
        .gau-link {{
            display: inline-block;
            padding: 8px 16px;
            background: var(--accent-subtle);
            color: var(--accent);
            border-radius: 6px;
            font-size: 0.9rem;
            font-weight: 500;
            text-decoration: none;
            transition: background 0.2s;
        }}
        .gau-link:hover {{
            background: rgba(88, 166, 255, 0.25);
            text-decoration: none;
        }}
        .gau-ai-filtered {{
            background: linear-gradient(135deg, rgba(163, 113, 247, 0.1), rgba(88, 166, 255, 0.05));
            border: 1px solid rgba(163, 113, 247, 0.3);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
        }}
        .gau-ai-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 12px;
            flex-wrap: wrap;
        }}
        .gau-ai-badge {{
            background: #a371f7;
            color: white;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
        }}
        .gau-ai-count {{
            color: var(--text-primary);
            font-weight: 600;
        }}
        .gau-ai-method {{
            color: var(--text-muted);
            font-size: 0.85rem;
        }}
        .gau-ai-filtered table {{
            width: 100%;
            background: var(--bg-dark);
            border-radius: 6px;
        }}
        .gau-ai-filtered td {{
            padding: 8px 12px;
            border-bottom: 1px solid var(--border-color);
        }}
        .gau-ai-filtered tr:last-child td {{
            border-bottom: none;
        }}
        .gau-more {{
            text-align: center;
            padding: 10px;
            color: var(--text-muted);
            font-size: 0.85rem;
        }}

        /* Footer */
        footer {{
            text-align: center;
            padding: 32px;
            color: var(--text-muted);
            font-size: 1rem;
        }}
        footer strong {{
            color: var(--accent);
        }}

        /* Empty State */
        .empty-state {{
            padding: 48px 24px;
            text-align: center;
            color: var(--text-secondary);
            font-size: 1rem;
        }}

        .server-cell {{
            font-size: 0.85rem;
            color: var(--text-muted);
        }}

        @media (max-width: 768px) {{
            .stats-grid {{ grid-template-columns: 1fr; }}
            .severity-grid {{ grid-template-columns: repeat(3, 1fr); }}
            .finding-header {{ flex-direction: column; align-items: flex-start; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>ReconDuctor Report</h1>
            <div class="domain">{domain}</div>
            <div class="meta">
                <span>Scan ID: {scan_result.get("scan_id", "N/A")}</span>
                <span>•</span>
                <span>Duration: {scan_result.get("duration_seconds", 0):.1f}s</span>
                <span>•</span>
                <span>{datetime.now().strftime("%Y-%m-%d %H:%M")}</span>
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="number">{stats.get("subdomains_discovered", len(subdomains))}</div>
                <div class="label">Subdomains</div>
            </div>
            <div class="stat-card">
                <div class="number">{stats.get("hosts_alive", len(hosts))}</div>
                <div class="label">Live Hosts</div>
            </div>
            <div class="stat-card">
                <div class="number">{stats.get("findings_total", len(findings))}</div>
                <div class="label">Findings</div>
            </div>
        </div>

        {self._generate_ai_impact_section(stats)}

        <div class="severity-section">
            <h3>Findings by Severity</h3>
            <div class="severity-grid">
                <div class="severity-card critical">
                    <div class="count">{critical}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="severity-card high">
                    <div class="count">{high}</div>
                    <div class="label">High</div>
                </div>
                <div class="severity-card medium">
                    <div class="count">{medium}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="severity-card low">
                    <div class="count">{low}</div>
                    <div class="label">Low</div>
                </div>
                <div class="severity-card info">
                    <div class="count">{info}</div>
                    <div class="label">Info</div>
                </div>
            </div>
        </div>

        <section>
            <h2>Vulnerability Findings <span class="count">{len(findings)}</span></h2>
            {f'<div class="finding-cards">{finding_cards}</div>' if findings else '<div class="empty-state">No vulnerabilities found</div>'}
        </section>

        <section>
            <h2>Live Hosts <span class="count">{len(hosts)}</span></h2>
            {f'<table><thead><tr><th>Hostname</th><th style="width:80px">Status</th><th>Title</th><th>Technologies</th><th>Server</th><th>CDN</th></tr></thead><tbody>{host_rows}</tbody></table>' if hosts else '<div class="empty-state">No live hosts found</div>'}
        </section>

        {self._generate_origin_ip_section(scan_result)}

        {self._generate_origin_scan_section(scan_result)}

        {self._generate_gau_section(scan_result)}

        <footer>
            Generated by <strong>ReconDuctor</strong> • For AI-prioritized risk analysis, see <code>triage_report.html</code>
        </footer>
    </div>
</body>
</html>"""

        output_path.write_text(html)

        logger.info(f"Exported HTML report to {output_path}")
        return output_path

    def export_triage_report(self, scan_result: dict[str, Any]) -> Optional[Path]:
        """Export AI-prioritized triage report as separate HTML file."""
        triage = self._load_triage_report()
        if not triage or not triage.get("risk_items"):
            logger.debug("No triage data available for triage report")
            return None

        output_path = self.output_dir / "triage_report.html"
        domain = scan_result.get("domain", "Unknown")
        risk_items = triage.get("risk_items", [])

        def escape_html(text: str) -> str:
            if not text:
                return ""
            return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;"))

        # Count by risk level
        critical_count = sum(1 for r in risk_items if r.get("risk_level") == "critical")
        high_count = sum(1 for r in risk_items if r.get("risk_level") == "high")
        medium_count = sum(1 for r in risk_items if r.get("risk_level") == "medium")
        low_count = sum(1 for r in risk_items if r.get("risk_level") == "low")

        # Generate risk item cards
        risk_cards = ""
        for item in risk_items:
            risk_level = item.get("risk_level", "medium")
            title = escape_html(item.get("title", "Unknown"))
            assets = item.get("affected_assets", [])
            assets_str = escape_html(", ".join(assets))
            env = item.get("environment", "unknown")
            impact = escape_html(item.get("business_impact", ""))
            technical = escape_html(item.get("technical_details", ""))
            remediation = escape_html(item.get("remediation", ""))
            attack_chain = escape_html(item.get("attack_chain_potential", "") or "")
            finding_count = item.get("finding_count", 1)

            # New fields
            evidence = escape_html(item.get("evidence", "") or "")
            exploit_availability = item.get("exploit_availability", "") or ""
            exploit_details = escape_html(item.get("exploit_details", "") or "")
            cve_ids = item.get("cve_ids", []) or []

            # Exploit availability badge styling
            exploit_badge_class = {
                "public_exploit": "exploit-public",
                "poc_available": "exploit-poc",
                "theoretical": "exploit-theoretical",
                "unknown": "exploit-unknown",
            }.get(exploit_availability, "exploit-unknown")
            exploit_badge_text = {
                "public_exploit": "Public Exploit",
                "poc_available": "PoC Available",
                "theoretical": "Theoretical",
                "unknown": "Unknown",
            }.get(exploit_availability, "")

            # CVE badges
            cve_badges = " ".join([f'<span class="cve-badge">{cve}</span>' for cve in cve_ids[:5]])

            risk_cards += f"""
            <div class="risk-item risk-{risk_level}">
                <div class="risk-header">
                    <span class="risk-badge risk-badge-{risk_level}">{risk_level.upper()}</span>
                    <span class="risk-title">{title}</span>
                    <span class="risk-meta">
                        <span class="risk-env">{env}</span>
                        <span class="risk-count">{finding_count} finding(s)</span>
                        {f'<span class="exploit-badge {exploit_badge_class}">{exploit_badge_text}</span>' if exploit_badge_text else ''}
                    </span>
                </div>
                <div class="risk-body">
                    {f'<div class="cve-list">{cve_badges}</div>' if cve_badges else ''}
                    <div class="risk-field">
                        <span class="field-label">Affected Assets:</span>
                        <span class="field-value"><code>{assets_str}</code></span>
                    </div>
                    {f'<div class="risk-field evidence-field"><span class="field-label">Evidence/PoC:</span><span class="field-value evidence"><code>{evidence}</code></span></div>' if evidence else ''}
                    {f'<div class="risk-field"><span class="field-label">Exploit Details:</span><span class="field-value exploit-details">{exploit_details}</span></div>' if exploit_details else ''}
                    <div class="risk-field">
                        <span class="field-label">Business Impact:</span>
                        <span class="field-value">{impact}</span>
                    </div>
                    {f'<div class="risk-field"><span class="field-label">Technical Details:</span><span class="field-value technical">{technical}</span></div>' if technical else ''}
                    {f'<div class="risk-field"><span class="field-label">Attack Chain:</span><span class="field-value attack-chain">{attack_chain}</span></div>' if attack_chain else ''}
                    <div class="risk-field">
                        <span class="field-label">Remediation:</span>
                        <span class="field-value remediation">{remediation}</span>
                    </div>
                </div>
            </div>"""

        exec_summary = escape_html(triage.get("executive_summary", ""))

        # Additional findings section
        additional_html = ""
        additional = triage.get("additional_findings")
        if additional and additional.get("count", 0) > 0:
            add_count = additional.get("count", 0)
            add_summary = escape_html(additional.get("summary", ""))
            add_hosts = additional.get("hosts", [])
            hosts_display = ", ".join(add_hosts[:15])
            if len(add_hosts) > 15:
                hosts_display += f" <em>...and {len(add_hosts) - 15} more</em>"
            additional_html = f"""
            <section class="additional-section">
                <h2>Additional Findings <span class="count">{add_count} items</span></h2>
                <div class="additional-content">
                    <p>{add_summary}</p>
                    {f'<p class="add-hosts"><strong>Affected Hosts:</strong> {hosts_display}</p>' if add_hosts else ''}
                </div>
            </section>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Risk Triage Report - {domain}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-dark: #0d1117;
            --bg-card: #161b22;
            --bg-card-hover: #1c2128;
            --border-color: #30363d;
            --text-primary: #f0f6fc;
            --text-secondary: #c9d1d9;
            --text-muted: #a0a8b0;
            --accent: #58a6ff;
            --critical: #f85149;
            --high: #db6d28;
            --medium: #d29922;
            --low: #58a6ff;
            --info: #8b949e;
            --success: #3fb950;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            line-height: 1.7;
            font-size: 16px;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}

        header {{
            text-align: center;
            padding: 48px 24px;
            background: linear-gradient(180deg, var(--bg-card) 0%, var(--bg-dark) 100%);
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 32px;
        }}
        header h1 {{
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 8px;
        }}
        header .domain {{
            font-size: 1.5rem;
            color: var(--accent);
            font-weight: 600;
            margin-bottom: 16px;
        }}

        .exec-summary {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--accent);
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 24px;
            font-size: 1.1rem;
            line-height: 1.8;
        }}

        .stats-row {{
            display: flex;
            gap: 16px;
            margin-bottom: 32px;
            flex-wrap: wrap;
        }}
        .stat-pill {{
            display: flex;
            align-items: center;
            gap: 8px;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            padding: 12px 20px;
            border-radius: 8px;
        }}
        .stat-pill .dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}
        .stat-pill .dot.critical {{ background: var(--critical); }}
        .stat-pill .dot.high {{ background: var(--high); }}
        .stat-pill .dot.medium {{ background: var(--medium); }}
        .stat-pill .dot.low {{ background: var(--low); }}
        .stat-pill .value {{
            font-weight: 700;
            font-size: 1.25rem;
        }}
        .stat-pill .label {{
            color: var(--text-muted);
            font-size: 0.9rem;
        }}

        section h2 {{
            font-size: 1.5rem;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        section h2 .count {{
            font-size: 1rem;
            font-weight: 400;
            color: var(--text-muted);
        }}

        .risk-item {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 16px;
            overflow: hidden;
        }}
        .risk-item.risk-critical {{ border-left: 4px solid var(--critical); }}
        .risk-item.risk-high {{ border-left: 4px solid var(--high); }}
        .risk-item.risk-medium {{ border-left: 4px solid var(--medium); }}
        .risk-item.risk-low {{ border-left: 4px solid var(--low); }}

        .risk-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 16px;
            background: var(--bg-card-hover);
            border-bottom: 1px solid var(--border-color);
            flex-wrap: wrap;
        }}
        .risk-badge {{
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .risk-badge-critical {{ background: var(--critical); color: white; }}
        .risk-badge-high {{ background: var(--high); color: white; }}
        .risk-badge-medium {{ background: var(--medium); color: #000; }}
        .risk-badge-low {{ background: var(--low); color: white; }}

        .risk-title {{
            font-weight: 600;
            font-size: 1.1rem;
            flex: 1;
        }}
        .risk-meta {{
            display: flex;
            gap: 8px;
        }}
        .risk-env, .risk-count {{
            font-size: 0.8rem;
            color: var(--text-muted);
            padding: 4px 8px;
            background: var(--bg-dark);
            border-radius: 4px;
        }}

        .risk-body {{
            padding: 20px;
        }}
        .risk-field {{
            margin-bottom: 16px;
        }}
        .risk-field:last-child {{
            margin-bottom: 0;
        }}
        .field-label {{
            font-weight: 600;
            color: var(--text-secondary);
            font-size: 0.9rem;
            display: block;
            margin-bottom: 6px;
        }}
        .field-value {{
            color: var(--text-primary);
            font-size: 1rem;
            line-height: 1.6;
        }}
        .field-value code {{
            font-family: 'JetBrains Mono', monospace;
            background: var(--bg-dark);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.9rem;
        }}
        .technical {{
            color: var(--text-secondary);
        }}
        .attack-chain {{
            color: #f0c14b;
            font-style: italic;
        }}
        .remediation {{
            color: #7ee787;
        }}

        /* Exploit availability badges */
        .exploit-badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .exploit-public {{
            background: rgba(248, 81, 73, 0.2);
            color: #f85149;
        }}
        .exploit-poc {{
            background: rgba(219, 109, 40, 0.2);
            color: #db6d28;
        }}
        .exploit-theoretical {{
            background: rgba(210, 153, 34, 0.2);
            color: #d29922;
        }}
        .exploit-unknown {{
            background: rgba(139, 148, 158, 0.2);
            color: #8b949e;
        }}

        /* CVE badges */
        .cve-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 16px;
        }}
        .cve-badge {{
            display: inline-block;
            padding: 4px 10px;
            background: rgba(219, 109, 40, 0.15);
            color: #db6d28;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85rem;
            font-weight: 500;
        }}

        /* Evidence field */
        .evidence-field {{
            background: var(--bg-dark);
            padding: 12px;
            border-radius: 6px;
            border-left: 3px solid var(--accent);
        }}
        .evidence {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            word-break: break-all;
        }}
        .evidence code {{
            background: transparent;
            padding: 0;
            color: #58a6ff;
        }}

        /* Exploit details */
        .exploit-details {{
            color: #f85149;
            font-weight: 500;
        }}

        .additional-section {{
            margin-top: 32px;
        }}
        .additional-content {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--info);
            padding: 20px;
            border-radius: 8px;
        }}
        .additional-content p {{
            margin-bottom: 12px;
        }}
        .add-hosts {{
            color: var(--text-muted);
            font-size: 0.9rem;
        }}

        footer {{
            margin-top: 48px;
            padding: 24px;
            text-align: center;
            color: var(--text-muted);
            border-top: 1px solid var(--border-color);
        }}
        footer code {{
            background: var(--bg-card);
            padding: 2px 6px;
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <header>
        <h1>Risk Triage Report</h1>
        <div class="domain">{domain}</div>
        <div class="meta">AI-Prioritized Vulnerability Analysis</div>
    </header>

    <div class="container">
        {f'<div class="exec-summary">{exec_summary}</div>' if exec_summary else ''}

        <div class="stats-row">
            <div class="stat-pill">
                <span class="dot critical"></span>
                <span class="value">{critical_count}</span>
                <span class="label">Critical</span>
            </div>
            <div class="stat-pill">
                <span class="dot high"></span>
                <span class="value">{high_count}</span>
                <span class="label">High</span>
            </div>
            <div class="stat-pill">
                <span class="dot medium"></span>
                <span class="value">{medium_count}</span>
                <span class="label">Medium</span>
            </div>
            <div class="stat-pill">
                <span class="dot low"></span>
                <span class="value">{low_count}</span>
                <span class="label">Low</span>
            </div>
        </div>

        <section>
            <h2>Prioritized Risk Items <span class="count">{len(risk_items)} items</span></h2>
            <div class="risk-items">
                {risk_cards}
            </div>
        </section>

        {additional_html}

        <footer>
            Generated by <strong>ReconDuctor AI Triage</strong> • For raw technical findings, see <code>report.html</code>
        </footer>
    </div>
</body>
</html>"""

        output_path.write_text(html)
        logger.info(f"Exported triage report to {output_path}")
        return output_path

    def export_non_http_subdomains_report(self, scan_result: dict[str, Any]) -> Optional[Path]:
        """Export report for non-HTTP subdomains (resolved via DNS but no HTTP response) with port info."""
        non_http_subdomains = scan_result.get("non_http_subdomains", [])
        non_http_ports = scan_result.get("non_http_subdomains_ports", {})

        if not non_http_subdomains:
            logger.debug("No non-HTTP subdomains to report")
            return None

        output_path = self.output_dir / "non_http_subdomains_report.html"
        domain = scan_result.get("domain", "Unknown")

        # Generate subdomain rows with status
        subdomain_rows = ""
        for sub in sorted(non_http_subdomains):
            ports = non_http_ports.get(sub, [])
            if ports:
                status = "has_ports"
                status_text = "Services Found"
                ports_str = ", ".join(str(p) for p in sorted(ports))
                port_badges = " ".join(f'<span class="port-badge">{p}</span>' for p in sorted(ports)[:10])
                if len(ports) > 10:
                    port_badges += f' <span class="more-ports">+{len(ports)-10} more</span>'
            else:
                status = "no_ports"
                status_text = "No Open Ports"
                ports_str = "-"
                port_badges = '<span class="no-ports">None detected</span>'

            subdomain_rows += f"""
            <tr class="subdomain-row {status}">
                <td class="subdomain-name"><code>{sub}</code></td>
                <td><span class="status-indicator {status}">{status_text}</span></td>
                <td class="ports-cell">{port_badges}</td>
            </tr>"""

        # Count stats
        with_ports = len([s for s in non_http_subdomains if s in non_http_ports and non_http_ports[s]])
        without_ports = len(non_http_subdomains) - with_ports

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Non-HTTP Subdomains Report - {domain}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-dark: #0d1117;
            --bg-card: #161b22;
            --bg-card-hover: #1c2128;
            --border-color: #30363d;
            --text-primary: #f0f6fc;
            --text-secondary: #c9d1d9;
            --text-muted: #a0a8b0;
            --accent: #58a6ff;
            --accent-subtle: #388bfd26;
            --success: #3fb950;
            --warning: #d29922;
            --error: #f85149;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            line-height: 1.7;
            font-size: 16px;
            -webkit-font-smoothing: antialiased;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 24px; }}

        header {{
            text-align: center;
            padding: 40px 24px;
            background: linear-gradient(180deg, var(--bg-card) 0%, var(--bg-dark) 100%);
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 32px;
        }}
        header h1 {{
            font-size: 1.75rem;
            font-weight: 700;
            margin-bottom: 8px;
            color: var(--warning);
        }}
        header .domain {{
            font-size: 1.25rem;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }}
        header .description {{
            color: var(--text-muted);
            font-size: 0.95rem;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .stat-card .number {{
            font-size: 2rem;
            font-weight: 700;
            line-height: 1.2;
        }}
        .stat-card .label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 4px;
        }}
        .stat-card.total .number {{ color: var(--accent); }}
        .stat-card.with-ports .number {{ color: var(--success); }}
        .stat-card.no-ports .number {{ color: var(--text-muted); }}

        section {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            margin-bottom: 24px;
            overflow: hidden;
        }}
        section h2 {{
            font-size: 1.1rem;
            font-weight: 600;
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        section h2 .count {{
            background: var(--accent-subtle);
            color: var(--accent);
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 0.85rem;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            text-align: left;
            padding: 12px 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            color: var(--text-secondary);
            background: var(--bg-dark);
            border-bottom: 1px solid var(--border-color);
        }}
        td {{
            padding: 14px 20px;
            border-bottom: 1px solid var(--border-color);
        }}
        tr:hover {{
            background: var(--bg-card-hover);
        }}
        tr:last-child td {{ border-bottom: none; }}

        .subdomain-name code {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            color: var(--text-primary);
        }}

        .status-indicator {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
        }}
        .status-indicator.has_ports {{
            background: rgba(63, 185, 80, 0.15);
            color: var(--success);
        }}
        .status-indicator.no_ports {{
            background: rgba(139, 148, 158, 0.15);
            color: var(--text-muted);
        }}

        .ports-cell {{
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }}
        .port-badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            font-weight: 500;
            background: rgba(88, 166, 255, 0.15);
            color: var(--accent);
        }}
        .more-ports {{
            color: var(--text-muted);
            font-size: 0.8rem;
        }}
        .no-ports {{
            color: var(--text-muted);
            font-size: 0.85rem;
            font-style: italic;
        }}

        .subdomain-row.has_ports {{
            border-left: 3px solid var(--success);
        }}
        .subdomain-row.no_ports {{
            border-left: 3px solid var(--border-color);
        }}

        footer {{
            text-align: center;
            padding: 24px;
            color: var(--text-muted);
            font-size: 0.9rem;
        }}

        @media (max-width: 768px) {{
            .stats-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Non-HTTP Subdomains Report</h1>
            <div class="domain">{domain}</div>
            <div class="description">
                Subdomains that resolved via DNS but did not respond to HTTP probing.
                These may be running other services (SSH, FTP, databases, etc).
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card total">
                <div class="number">{len(non_http_subdomains)}</div>
                <div class="label">Non-HTTP Subdomains</div>
            </div>
            <div class="stat-card with-ports">
                <div class="number">{with_ports}</div>
                <div class="label">With Open Ports</div>
            </div>
            <div class="stat-card no-ports">
                <div class="number">{without_ports}</div>
                <div class="label">No Open Ports</div>
            </div>
        </div>

        <section>
            <h2>Subdomain Details <span class="count">{len(non_http_subdomains)}</span></h2>
            <table>
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th style="width: 150px;">Status</th>
                        <th>Open Ports</th>
                    </tr>
                </thead>
                <tbody>
                    {subdomain_rows}
                </tbody>
            </table>
        </section>

        <footer>
            Generated by <strong>ReconDuctor</strong> - Non-HTTP Subdomains Analysis
        </footer>
    </div>
</body>
</html>"""

        output_path.write_text(html)
        logger.info(f"Exported non-HTTP subdomains report to {output_path}")
        return output_path


def export_gau_findings_html(
    gau_result: Any,  # GauResult
    output_path: Path,
    domain: str,
) -> Path:
    """
    Export GAU historical URL findings to HTML report.

    Args:
        gau_result: GauResult from gau_wrapper
        output_path: Path to save HTML file
        domain: Target domain

    Returns:
        Path to generated HTML file
    """
    def escape_html(text: str) -> str:
        if not text:
            return ""
        return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))

    # Generate categorized URL sections
    category_sections = ""
    category_labels = {
        "ssrf_candidates": ("SSRF Candidates", "#f85149", "URLs with redirect/URL parameters"),
        "lfi_candidates": ("LFI Candidates", "#db6d28", "URLs with file/path parameters"),
        "sqli_candidates": ("SQLi Candidates", "#d29922", "URLs with ID/query parameters"),
        "xss_candidates": ("XSS Candidates", "#a371f7", "URLs with input/output parameters"),
        "open_redirect": ("Open Redirect", "#f85149", "URLs with redirect parameters"),
        "rce_candidates": ("RCE Candidates", "#f85149", "URLs with command/exec parameters"),
        "api_endpoints": ("API Endpoints", "#58a6ff", "REST/GraphQL API URLs"),
        "auth_endpoints": ("Auth Endpoints", "#3fb950", "Login/authentication URLs"),
        "admin_paths": ("Admin Paths", "#d29922", "Admin panel URLs"),
        "debug_paths": ("Debug Paths", "#f85149", "Debug/test URLs"),
        "file_operations": ("File Operations", "#db6d28", "Upload/download URLs"),
        "param_urls": ("URLs with Params", "#8b949e", "All URLs with query parameters"),
    }

    for category, urls in gau_result.categorized_urls.items():
        if not urls:
            continue

        label, color, description = category_labels.get(
            category, (category.replace("_", " ").title(), "#8b949e", "")
        )

        url_rows = ""
        for url in urls[:100]:  # Limit per category
            status_badge = ""
            if url.validation_status:
                status_class = "status-2xx" if url.validation_status < 400 else "status-4xx"
                status_badge = f'<span class="status-badge {status_class}">{url.validation_status}</span>'

            params_str = ", ".join(list(url.params.keys())[:5])
            if len(url.params) > 5:
                params_str += f" (+{len(url.params) - 5})"

            url_rows += f"""
            <tr>
                <td class="url-cell"><a href="{escape_html(url.url)}" target="_blank">{escape_html(url.url[:120])}</a></td>
                <td class="params-cell"><code>{escape_html(params_str) or '-'}</code></td>
                <td class="status-cell">{status_badge}</td>
            </tr>"""

        category_sections += f"""
        <div class="category-section" style="border-left-color: {color}">
            <div class="category-header">
                <span class="category-name">{label}</span>
                <span class="category-count">{len(urls)}</span>
            </div>
            <p class="category-desc">{description}</p>
            <table>
                <thead>
                    <tr>
                        <th>URL</th>
                        <th style="width: 200px">Parameters</th>
                        <th style="width: 80px">Status</th>
                    </tr>
                </thead>
                <tbody>
                    {url_rows}
                </tbody>
            </table>
            {f'<div class="more-indicator">...and {len(urls) - 100} more URLs</div>' if len(urls) > 100 else ''}
        </div>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Historical URL Analysis - {domain}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-dark: #0d1117;
            --bg-card: #161b22;
            --bg-card-hover: #1c2128;
            --border-color: #30363d;
            --text-primary: #f0f6fc;
            --text-secondary: #c9d1d9;
            --text-muted: #a0a8b0;
            --accent: #58a6ff;
            --accent-subtle: #388bfd26;
            --success: #3fb950;
            --warning: #d29922;
            --error: #f85149;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-dark);
            color: var(--text-primary);
            line-height: 1.6;
            font-size: 15px;
            -webkit-font-smoothing: antialiased;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}

        header {{
            text-align: center;
            padding: 40px 24px;
            background: linear-gradient(180deg, var(--bg-card) 0%, var(--bg-dark) 100%);
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 32px;
        }}
        header h1 {{
            font-size: 1.75rem;
            font-weight: 700;
            margin-bottom: 8px;
            color: var(--accent);
        }}
        header .domain {{
            font-size: 1.25rem;
            color: var(--text-secondary);
            margin-bottom: 16px;
        }}
        header .description {{
            color: var(--text-muted);
            font-size: 0.9rem;
            max-width: 700px;
            margin: 0 auto;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 32px;
        }}
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .stat-card .number {{
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent);
        }}
        .stat-card .label {{
            color: var(--text-secondary);
            font-size: 0.85rem;
            margin-top: 4px;
        }}

        .category-section {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--accent);
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        .category-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 16px 20px;
            background: var(--bg-card-hover);
            border-bottom: 1px solid var(--border-color);
        }}
        .category-name {{
            font-weight: 600;
            font-size: 1.1rem;
        }}
        .category-count {{
            background: var(--accent-subtle);
            color: var(--accent);
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.9rem;
            font-weight: 600;
        }}
        .category-desc {{
            padding: 12px 20px;
            color: var(--text-muted);
            font-size: 0.9rem;
            border-bottom: 1px solid var(--border-color);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            text-align: left;
            padding: 12px 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.3px;
            color: var(--text-secondary);
            background: var(--bg-dark);
        }}
        td {{
            padding: 10px 20px;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.9rem;
        }}
        tr:hover {{
            background: var(--bg-card-hover);
        }}
        tr:last-child td {{
            border-bottom: none;
        }}

        .url-cell a {{
            color: var(--accent);
            text-decoration: none;
            word-break: break-all;
        }}
        .url-cell a:hover {{
            text-decoration: underline;
        }}
        .params-cell code {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.8rem;
            background: var(--bg-dark);
            padding: 2px 6px;
            border-radius: 4px;
            color: var(--text-secondary);
        }}
        .status-badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
        }}
        .status-2xx {{
            background: rgba(63, 185, 80, 0.2);
            color: var(--success);
        }}
        .status-4xx {{
            background: rgba(210, 153, 34, 0.2);
            color: var(--warning);
        }}

        .more-indicator {{
            padding: 12px 20px;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.9rem;
            background: var(--bg-dark);
            border-top: 1px solid var(--border-color);
        }}

        .warning-box {{
            background: rgba(210, 153, 34, 0.1);
            border: 1px solid var(--warning);
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 24px;
            color: var(--warning);
        }}
        .warning-box strong {{
            display: block;
            margin-bottom: 8px;
        }}

        footer {{
            text-align: center;
            padding: 24px;
            color: var(--text-muted);
            font-size: 0.9rem;
        }}

        @media (max-width: 768px) {{
            .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
        }}
    </style>
</head>
<body>
    <header>
        <h1>Historical URL Analysis (GAU)</h1>
        <div class="domain">{domain}</div>
        <div class="description">
            URLs discovered from Wayback Machine, Common Crawl, OTX, and URLScan.
            These represent historical attack surface that may still be active.
        </div>
    </header>

    <div class="container">
        <div class="warning-box">
            <strong>Security Testing Notes</strong>
            These URLs are categorized by potential vulnerability type based on parameter names.
            Always verify findings manually and ensure you have authorization before testing.
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="number">{gau_result.total_urls}</div>
                <div class="label">Total URLs Found</div>
            </div>
            <div class="stat-card">
                <div class="number">{gau_result.unique_urls}</div>
                <div class="label">Unique URLs</div>
            </div>
            <div class="stat-card">
                <div class="number">{gau_result.urls_with_params}</div>
                <div class="label">With Parameters</div>
            </div>
            <div class="stat-card">
                <div class="number">{len(gau_result.categorized_urls)}</div>
                <div class="label">Categories</div>
            </div>
        </div>

        {category_sections}

        <footer>
            Generated by <strong>ReconDuctor</strong> - Historical URL Mining powered by GAU
        </footer>
    </div>
</body>
</html>"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html)
    return output_path


def export_scan_results(
    scan_result: dict[str, Any],
    output_dir: Optional[Path] = None,
) -> dict[str, Path]:
    """
    Convenience function to export scan results.

    Args:
        scan_result: The scan result dictionary
        output_dir: Output directory (defaults to output/<domain>)

    Returns:
        Dictionary mapping report type to file path
    """
    domain = scan_result.get("domain", "unknown")

    if output_dir is None:
        output_dir = Path("output") / domain

    exporter = ReportExporter(output_dir)
    return exporter.export_all(scan_result)
