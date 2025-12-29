"""Main pipeline orchestrator for reconnaissance scans."""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional
from uuid import uuid4
from dataclasses import dataclass, field

from reconductor.core.config import Settings
from reconductor.core.checkpoint import CheckpointManager
from reconductor.core.database import Database
from reconductor.core.exporter import ReportExporter
from reconductor.core.logger import get_logger
from reconductor.core.rate_limiter import AdaptiveRateLimiter
from reconductor.core.scope import ScopeValidator
from reconductor.models.scan import Scan, ScanPhase, ScanStatus, ScanStats
from reconductor.modules.subdomain.passive import PassiveEnumerationPipeline
from reconductor.modules.subdomain.puredns_wrapper import PurednsWrapper
from reconductor.modules.subdomain.alterx_wrapper import AlterxWrapper, SmartPermutationGenerator
from reconductor.modules.validation.http_probe import HttpProber
from reconductor.modules.validation.dns_resolve import DnsResolver
from reconductor.modules.validation.port_scan import PortScanner
from reconductor.modules.scanning.nuclei_manager import NucleiManager
from reconductor.modules.scanning.takeover import TakeoverDetector
from reconductor.modules.scanning.subjack_wrapper import SubjackWrapper
from reconductor.modules.recon.gau_wrapper import GauWrapper
from reconductor.modules.recon.screenshot_capture import ScreenshotCapture, generate_screenshot_gallery_html
# GauTargetAgent removed - now using GauUrlFilterAgent for post-GAU filtering
from reconductor.utils.tempfiles import secure_temp_file

logger = get_logger(__name__)


@dataclass
class PhaseStats:
    """Track detailed statistics per phase and tool."""
    # Phase 1: Enumeration
    passive_total: int = 0
    subfinder_count: int = 0
    crtsh_count: int = 0
    shodan_count: int = 0  # Shodan SSL cert enumeration
    wayback_count: int = 0
    ai_wordlist_count: int = 0
    ai_wordlist_hits: int = 0  # AI prefixes that actually resolved
    ai_hit_rate: float = 0.0  # Percentage of AI prefixes that hit
    ai_unique_finds: int = 0  # Subdomains found ONLY via AI (not in passive)
    bruteforce_count: int = 0
    permutation_count: int = 0
    total_subdomains: int = 0

    # Phase 2: Validation
    dns_resolved: int = 0
    dns_failed: int = 0
    ports_scanned: int = 0
    open_ports: int = 0
    http_probed: int = 0
    http_alive: int = 0
    non_http_subdomains: int = 0  # Resolved but no HTTP response
    subjack_takeovers: int = 0  # Takeovers found by subjack

    # Phase 3: Scanning
    nuclei_targets: int = 0
    findings_critical: int = 0
    findings_high: int = 0
    findings_medium: int = 0
    findings_low: int = 0
    findings_info: int = 0

    # Phase 4: Analysis
    takeover_candidates: int = 0
    origin_ips_found: int = 0  # Origin IPs behind CDN
    cdn_hosts: int = 0  # Hosts behind CDN

    # Screenshots
    screenshots_captured: int = 0
    screenshots_failed: int = 0

    # GAU (Historical URL Mining)
    gau_targets_selected: int = 0
    gau_total_urls: int = 0
    gau_unique_urls: int = 0
    gau_urls_with_params: int = 0
    gau_categories: int = 0
    gau_validated_live: int = 0  # URLs that still return 200/30x


class Orchestrator:
    """
    Main pipeline controller for reconnaissance scans.

    Coordinates all phases of reconnaissance:
    1. Subdomain Enumeration (with AI wordlist generation)
    2. Live Host Validation
    3. Vulnerability Scanning (parallel workers)
    4. Analysis & Reporting
    """

    def __init__(
        self,
        settings: Settings,
        scope_validator: ScopeValidator,
        checkpoint_manager: Optional[CheckpointManager] = None,
        rate_limiter: Optional[AdaptiveRateLimiter] = None,
    ):
        """
        Initialize orchestrator.

        Args:
            settings: Application settings
            scope_validator: Scope validator for targets
            checkpoint_manager: Checkpoint manager for resume
            rate_limiter: Adaptive rate limiter
        """
        self.settings = settings
        self.scope = scope_validator
        self.checkpoint = checkpoint_manager
        self.rate_limiter = rate_limiter or AdaptiveRateLimiter(
            initial_rate=settings.rate_limit.initial_rate,
        )

        # Initialize modules
        self.passive_enum = PassiveEnumerationPipeline()
        self.puredns = PurednsWrapper(config=settings.puredns)
        self.alterx = AlterxWrapper()
        self.smart_permutation = SmartPermutationGenerator()
        self.http_prober = HttpProber(
            config=settings.http,
            rate_limiter=self.rate_limiter,
        )
        self.dns_resolver = DnsResolver()
        self.port_scanner = PortScanner(scope_validator=scope_validator)
        self.nuclei = NucleiManager(
            config=settings.nuclei,
            rate_limiter=self.rate_limiter,
            output_dir=settings.output_dir,
        )
        self.takeover = TakeoverDetector()
        self.subjack = SubjackWrapper()
        self.gau = GauWrapper()
        # GauUrlFilterAgent is instantiated per-scan in _run_gau_mining
        self.screenshot = ScreenshotCapture()

    def _export_phase_results(self, scan: Scan, phase: int) -> None:
        """
        Export results incrementally after each phase.

        This ensures data is saved even if the scan is interrupted.
        """
        import json

        output_dir = self.settings.output_dir
        if not output_dir:
            return

        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            if phase >= 1 and scan.subdomains:
                # Export subdomains
                subdomains_file = output_dir / "subdomains.txt"
                subdomains_file.write_text("\n".join(sorted(set(scan.subdomains))))
                logger.debug(f"Exported {len(scan.subdomains)} subdomains to {subdomains_file}")

            if phase >= 2 and scan.hosts:
                # Export live hosts (deduplicated)
                live_hosts_file = output_dir / "live_hosts.txt"
                live_urls = set()
                for h in scan.hosts:
                    url = h.get("url") or f"https://{h.get('hostname', '')}"
                    if url:
                        live_urls.add(url)
                live_hosts_file.write_text("\n".join(sorted(live_urls)))

                # Export hosts.json
                hosts_file = output_dir / "hosts.json"
                hosts_file.write_text(json.dumps(scan.hosts, indent=2, default=str))
                logger.debug(f"Exported {len(scan.hosts)} hosts")

            if phase >= 3 and scan.findings:
                # Export findings
                findings_file = output_dir / "findings.json"
                findings_file.write_text(json.dumps(scan.findings, indent=2, default=str))
                logger.debug(f"Exported {len(scan.findings)} findings")

        except Exception as e:
            logger.warning(f"Failed to export phase {phase} results: {e}")

    async def run_scan(
        self,
        domain: str,
        passive_only: bool = False,
        skip_nuclei: bool = False,
        skip_ai_wordlist: bool = False,
        ai_triage: bool = False,
        origin_scan: bool = True,
        rate_limit: Optional[int] = None,
        max_workers: Optional[int] = None,
        progress_callback: Optional[Callable[[int, str, str], None]] = None,
    ) -> dict[str, Any]:
        """
        Run a complete reconnaissance scan.

        Args:
            domain: Target domain
            passive_only: Only run passive enumeration
            skip_nuclei: Skip vulnerability scanning
            skip_ai_wordlist: Skip AI-powered wordlist generation
            ai_triage: Enable AI triage (filters GAU URLs, generates triage report)
            rate_limit: Override rate limit
            max_workers: Maximum parallel workers
            progress_callback: Progress update callback(phase, step, status, **kwargs)

        Returns:
            Scan results dictionary

        Note: GAU historical URL mining runs by default in Phase 2 (parallel with HTTP probing).
        """
        scan_id = str(uuid4())[:8]
        scan = Scan(
            scan_id=scan_id,
            domain=domain,
            config={
                "passive_only": passive_only,
                "skip_nuclei": skip_nuclei,
                "skip_ai_wordlist": skip_ai_wordlist,
                "ai_triage": ai_triage,
                "origin_scan": origin_scan,
                "rate_limit": rate_limit,
                "max_workers": max_workers,
            },
        )
        scan.start()

        logger.info(
            "Starting reconnaissance scan",
            scan_id=scan_id,
            domain=domain,
        )

        # Track detailed stats
        phase_stats = PhaseStats()

        try:
            # Phase 1: Subdomain Enumeration
            await self._run_phase1_enumeration(
                scan, passive_only, skip_ai_wordlist, progress_callback, phase_stats
            )

            if passive_only:
                scan.complete()
                result = self._build_result(scan, phase_stats)
                self._export_reports(result)
                return result

            # Phase 2: Live Host Validation
            await self._run_phase2_validation(scan, progress_callback, phase_stats)

            # Phase 3: Vulnerability Scanning (with parallel workers)
            if not skip_nuclei:
                await self._run_phase3_scanning(scan, max_workers, progress_callback, phase_stats)
            elif progress_callback:
                progress_callback(3, "nuclei_scan", "skip")

            # Phase 4: Analysis (Takeover + Origin IP Discovery + GAU AI Filter if --ai-triage)
            await self._run_phase4_analysis(scan, progress_callback, phase_stats)

            scan.complete()
            logger.info(
                "Scan completed successfully",
                scan_id=scan_id,
                duration=scan.duration_seconds,
            )

            # Export reports
            result = self._build_result(scan, phase_stats)
            self._export_reports(result)

            return result

        except Exception as e:
            scan.fail(str(e))
            logger.exception("Scan failed", scan_id=scan_id, error=str(e))
            raise

    async def _run_phase1_enumeration(
        self,
        scan: Scan,
        passive_only: bool,
        skip_ai_wordlist: bool,
        progress_callback: Optional[Callable],
        stats: PhaseStats,
    ) -> None:
        """Run Phase 1: Subdomain Enumeration with detailed tracking."""
        phase_start = time.time()

        # Step 1: Passive enumeration
        if progress_callback:
            progress_callback(1, "passive_enum", "start", message="Running passive enumeration...")

        passive_results = await self.passive_enum.enumerate(scan.domain)

        # Get per-source counts from pipeline
        source_counts = getattr(self.passive_enum, 'source_counts', {})
        stats.subfinder_count = source_counts.get('subfinder', 0)
        stats.crtsh_count = source_counts.get('crtsh', 0)
        stats.shodan_count = source_counts.get('shodan', 0)
        stats.wayback_count = source_counts.get('wayback', 0)
        stats.passive_total = len(passive_results)

        scan.add_subdomains([s.name for s in passive_results])

        # Build source summary for message - show all attempted sources
        sources = []
        # Always show subfinder (primary source)
        sources.append(f"subfinder:{stats.subfinder_count}")
        # Show crt.sh if it was attempted (key exists in source_counts)
        if 'crtsh' in source_counts:
            sources.append(f"crt.sh:{stats.crtsh_count}")
        # Show shodan if it was attempted
        if 'shodan' in source_counts:
            sources.append(f"shodan:{stats.shodan_count}")

        if progress_callback:
            progress_callback(
                1, "passive_enum", "complete",
                message=f"Passive: {stats.passive_total} ({', '.join(sources) if sources else 'combined'})",
                subdomains=len(scan.subdomains),
                subfinder=stats.subfinder_count,
                crtsh=stats.crtsh_count,
                shodan=stats.shodan_count,
            )

        logger.info(
            "Passive enumeration complete",
            total=stats.passive_total,
            subfinder=stats.subfinder_count,
            crtsh=stats.crtsh_count,
            shodan=stats.shodan_count,
        )

        # Step 2: AI Wordlist Generation (Claude Code integration)
        ai_wordlist = []
        if not skip_ai_wordlist:
            try:
                if progress_callback:
                    progress_callback(1, "ai_wordlist", "start", message="AI generating intelligent wordlist...")

                from reconductor.modules.ai.wordlist_agent import WordlistGeneratorAgent

                agent = WordlistGeneratorAgent()
                wordlist_result = await agent.generate(
                    scan.domain,
                    existing_subdomains=scan.subdomains[:50],
                    count=200,
                )

                # Use actual wordlist length, with LLM contribution noted separately
                ai_wordlist = wordlist_result.wordlist
                stats.ai_wordlist_count = len(ai_wordlist)
                llm_contribution = wordlist_result.stats.get("llm_generated_valid", 0)

                if progress_callback:
                    llm_msg = f" ({llm_contribution} from LLM)" if llm_contribution else " (LLM failed, using fallback)"
                    progress_callback(
                        1, "ai_wordlist", "complete",
                        message=f"AI: {stats.ai_wordlist_count} prefixes{llm_msg}",
                        ai_generated=stats.ai_wordlist_count,
                        llm_contribution=llm_contribution,
                    )

                logger.info(
                    "AI wordlist generation complete",
                    total=len(ai_wordlist),
                    from_llm=llm_contribution,
                )

            except Exception as e:
                logger.warning(f"AI wordlist generation failed: {e}")
                if progress_callback:
                    progress_callback(1, "ai_wordlist", "complete", message=f"AI skipped: {str(e)[:30]}")
        else:
            if progress_callback:
                progress_callback(1, "ai_wordlist", "skip")

        # Step 3: DNS Brute-force (if not passive only)
        # Store passive subdomains for AI impact calculation
        passive_subdomains_set = set(scan.subdomains)

        if not passive_only and PurednsWrapper.is_available():
            if progress_callback:
                progress_callback(1, "dns_bruteforce", "start", message="DNS brute-forcing...")

            # Combine base wordlist with AI-generated wordlist
            wordlist_path = self._get_wordlist(ai_wordlist)

            brute_result = await self.puredns.bruteforce(
                scan.domain,
                wordlist_path,
            )
            stats.bruteforce_count = len(brute_result.valid_subdomains)
            scan.add_subdomains(brute_result.valid_subdomains)

            # Calculate AI impact - which AI-generated prefixes actually resolved
            if ai_wordlist:
                ai_set = set(ai_wordlist)
                # Extract prefixes from resolved subdomains
                resolved_prefixes = set()
                for sub in brute_result.valid_subdomains:
                    # Remove domain suffix to get prefix
                    prefix = sub.replace(f".{scan.domain}", "").lower()
                    resolved_prefixes.add(prefix)

                # AI hits = intersection of AI wordlist and resolved prefixes
                ai_hits = ai_set & resolved_prefixes
                stats.ai_wordlist_hits = len(ai_hits)
                stats.ai_hit_rate = round(len(ai_hits) / len(ai_set) * 100, 1) if ai_set else 0.0

                # Unique finds = subdomains found via AI that weren't in passive
                ai_resolved_subs = {f"{p}.{scan.domain}" for p in ai_hits}
                unique_ai_finds = ai_resolved_subs - passive_subdomains_set
                stats.ai_unique_finds = len(unique_ai_finds)

                # Save successful AI predictions for feedback loop
                if ai_hits:
                    self._save_ai_feedback(scan.domain, list(ai_hits))

                logger.info(
                    "AI wordlist impact",
                    generated=len(ai_set),
                    hits=stats.ai_wordlist_hits,
                    hit_rate=f"{stats.ai_hit_rate}%",
                    unique_finds=stats.ai_unique_finds,
                )

            if progress_callback:
                ai_impact_msg = ""
                if stats.ai_wordlist_hits > 0:
                    ai_impact_msg = f" (AI: {stats.ai_wordlist_hits} hits, {stats.ai_hit_rate}%)"
                progress_callback(
                    1, "dns_bruteforce", "complete",
                    message=f"Brute-force: +{stats.bruteforce_count} subdomains{ai_impact_msg}",
                    subdomains=len(scan.subdomains),
                    bruteforce=stats.bruteforce_count,
                    ai_hits=stats.ai_wordlist_hits,
                    ai_hit_rate=stats.ai_hit_rate,
                )

            # Step 4: Permutation generation with smart pattern detection
            if AlterxWrapper.is_available() and len(scan.subdomains) > 5:
                if progress_callback:
                    progress_callback(1, "permutations", "start", message="Analyzing patterns & generating permutations...")

                # Analyze existing subdomains for naming patterns
                seed_subdomains = scan.subdomains[:100]
                smart_patterns = self.smart_permutation.generate_contextual_patterns(
                    scan.domain,
                    seed_subdomains,
                )

                # Create temp patterns file for alterx
                patterns_file = secure_temp_file(suffix="_patterns.yaml")
                patterns_file.write_text(smart_patterns)

                # Generate permutations with context-aware patterns
                permutations = await self.alterx.generate_permutations(
                    seed_subdomains,
                    patterns_file=patterns_file,
                )

                alterx_generated = len(permutations) if permutations else 0

                if permutations:
                    resolve_result = await self.puredns.resolve_list(permutations)
                    stats.permutation_count = len(resolve_result.resolved_subdomains)
                    scan.add_subdomains(resolve_result.resolved_subdomains)

                if progress_callback:
                    progress_callback(
                        1, "permutations", "complete",
                        message=f"Permutations: {alterx_generated} generated → +{stats.permutation_count} new",
                        subdomains=len(scan.subdomains),
                        permutations=stats.permutation_count,
                        alterx_generated=alterx_generated,
                    )
            else:
                if progress_callback:
                    progress_callback(1, "permutations", "skip")
        else:
            if progress_callback:
                progress_callback(1, "dns_bruteforce", "skip")
                progress_callback(1, "permutations", "skip")

        # Validate scope
        valid, rejected = self.scope.validate_batch(scan.subdomains)
        if rejected:
            logger.warning(f"Rejected {len(rejected)} out-of-scope subdomains")
            scan.subdomains = valid

        stats.total_subdomains = len(scan.subdomains)
        scan.stats.subdomains_discovered = stats.total_subdomains
        scan.update_phase(ScanPhase.ENUMERATION)

        duration = time.time() - phase_start
        scan.stats.record_phase_duration("enumeration", duration)

        # Export results incrementally (allows resume if interrupted)
        self._export_phase_results(scan, 1)

        # Log phase summary
        logger.info(
            "Phase 1 complete",
            total=stats.total_subdomains,
            passive=stats.passive_total,
            ai=stats.ai_wordlist_count,
            bruteforce=stats.bruteforce_count,
            permutations=stats.permutation_count,
            duration=f"{duration:.1f}s",
        )

    async def _run_phase2_validation(
        self,
        scan: Scan,
        progress_callback: Optional[Callable],
        stats: PhaseStats,
    ) -> None:
        """Run Phase 2: Live Host Validation with detailed tracking."""
        phase_start = time.time()

        # Step 1: DNS Resolution
        total_to_resolve = len(scan.subdomains)
        if progress_callback:
            progress_callback(2, "dns_resolve", "start", message=f"Resolving {total_to_resolve} subdomains...")

        dns_results = await self.dns_resolver.resolve(scan.subdomains)
        resolvable = [h for h, r in dns_results.items() if r.has_records]

        stats.dns_resolved = len(resolvable)
        stats.dns_failed = len(scan.subdomains) - stats.dns_resolved

        if progress_callback:
            progress_callback(
                2, "dns_resolve", "complete",
                message=f"DNS: {stats.dns_resolved}/{len(scan.subdomains)} resolved",
                dns_resolved=stats.dns_resolved,
                dns_failed=stats.dns_failed,
            )

        logger.info(
            "DNS resolution complete",
            resolved=stats.dns_resolved,
            failed=stats.dns_failed,
        )

        # Step 2: Port Scanning (discover additional web ports)
        port_scan_urls = []
        if PortScanner.is_available() and resolvable:
            total_to_scan = len(resolvable)
            if progress_callback:
                progress_callback(2, "port_scan", "start", message=f"Scanning {total_to_scan} hosts for web ports...")

            port_results = await self.port_scanner.scan_web_ports(resolvable)

            stats.ports_scanned = len(resolvable)
            stats.open_ports = sum(len(r.open_ports) for r in port_results.values())

            # Generate URLs from port scan results (non-standard ports)
            port_scan_urls = PortScanner.get_urls_from_results(port_results)

            if progress_callback:
                progress_callback(
                    2, "port_scan", "complete",
                    message=f"Ports: {stats.open_ports} open on {len(port_results)} hosts",
                    ports_scanned=stats.ports_scanned,
                    open_ports=stats.open_ports,
                )

            logger.info(
                "Port scan complete",
                hosts_scanned=stats.ports_scanned,
                open_ports=stats.open_ports,
                urls_generated=len(port_scan_urls),
            )
        else:
            if progress_callback:
                progress_callback(2, "port_scan", "skip", message="naabu not available")

        # Step 3: HTTP Probing + Subjack + GAU (ALL PARALLEL)
        probe_targets = list(set(resolvable + port_scan_urls))
        total_to_probe = len(probe_targets)

        # Create progress callback for parallel probing
        def http_progress(current: int, total: int) -> None:
            if progress_callback:
                progress_callback(2, "http_probe", "progress", current=current, total=total)

        if progress_callback:
            progress_callback(2, "http_probe", "start", message=f"Probing {total_to_probe} hosts + GAU (parallel)...")
            progress_callback(2, "http_probe", "progress", current=0, total=total_to_probe)

        # Define async tasks
        async def run_http_probe():
            """Run HTTP probing on targets."""
            return await self.http_prober.probe_parallel(
                probe_targets,
                progress_callback=http_progress,
            )

        async def run_subjack_scan():
            """Run subjack takeover detection on ALL DNS-resolved subdomains."""
            if not SubjackWrapper.is_available():
                logger.debug("subjack not available, skipping takeover detection")
                return []

            logger.info(f"Running subjack takeover scan on {len(resolvable)} subdomains")
            return await self.subjack.scan(resolvable, threads=50, timeout=10)

        async def run_gau_mining():
            """Run GAU historical URL mining in parallel."""
            if not GauWrapper.is_available():
                logger.debug("gau not available, skipping historical URL mining")
                return None

            logger.info(f"Running GAU on {scan.domain} (parallel with HTTP probing)")
            try:
                from reconductor.modules.recon.gau_wrapper import FAST_PROVIDERS
                result = await self.gau.fetch_urls(
                    domain=scan.domain,
                    include_subs=True,
                    providers=FAST_PROVIDERS,
                    threads=3,
                    timeout=60,
                )
                return result
            except Exception as e:
                logger.warning(f"GAU mining failed: {e}")
                return None

        # Run HTTP probing, subjack, and GAU in parallel
        hosts, takeover_findings, gau_result = await asyncio.gather(
            run_http_probe(),
            run_subjack_scan(),
            run_gau_mining(),
        )

        # Process HTTP probe results
        alive_hosts = [h for h in hosts if h.is_alive]
        scan.hosts = [h.to_dict() for h in alive_hosts]

        # Track non-HTTP subdomains (resolved via DNS but no HTTP response - may have other services)
        alive_hostnames = {h.hostname for h in alive_hosts}
        non_http_subdomains = [sub for sub in resolvable if sub not in alive_hostnames]
        scan.non_http_subdomains = non_http_subdomains  # Store for parallel port scan

        stats.http_probed = len(hosts)
        stats.http_alive = len(alive_hosts)
        stats.non_http_subdomains = len(non_http_subdomains)

        # Process subjack takeover findings
        stats.subjack_takeovers = len(takeover_findings)
        for finding in takeover_findings:
            scan.findings.append(finding.to_dict())
            scan.stats.add_finding(finding.severity.value)

        # Process GAU results (ran in parallel)
        if gau_result and gau_result.all_urls:
            stats.gau_total_urls = gau_result.total_urls
            stats.gau_unique_urls = gau_result.unique_urls
            stats.gau_urls_with_params = gau_result.urls_with_params
            stats.gau_categories = len(gau_result.categorized_urls)
            scan.gau_result = gau_result

            # Export GAU findings HTML
            from reconductor.core.exporter import export_gau_findings_html
            gau_html_path = self.settings.output_dir / "gau_findings.html"
            export_gau_findings_html(gau_result, gau_html_path, scan.domain)

            logger.info(
                "GAU mining complete (parallel)",
                total=stats.gau_total_urls,
                unique=stats.gau_unique_urls,
                with_params=stats.gau_urls_with_params,
            )

        scan.stats.hosts_validated = stats.http_probed
        scan.stats.hosts_alive = stats.http_alive
        scan.stats.subdomains_alive = stats.http_alive

        # Build completion message
        gau_msg = f", GAU:{stats.gau_unique_urls}" if stats.gau_unique_urls else ""
        takeover_msg = f", {stats.subjack_takeovers} takeovers" if stats.subjack_takeovers else ""

        if progress_callback:
            progress_callback(
                2, "http_probe", "complete",
                message=f"HTTP: {stats.http_alive}/{stats.http_probed} live{gau_msg}{takeover_msg}",
                live_hosts=stats.http_alive,
                http_probed=stats.http_probed,
                takeovers=stats.subjack_takeovers,
                gau_urls=stats.gau_unique_urls,
            )

        logger.info(
            "HTTP probing complete",
            probed=stats.http_probed,
            alive=stats.http_alive,
            takeovers=stats.subjack_takeovers,
            gau_urls=stats.gau_unique_urls,
        )

        # Step 4: Screenshot Capture (run after HTTP probing)
        if alive_hosts and ScreenshotCapture.is_available():
            await self._run_screenshot_capture(scan, alive_hosts, progress_callback, stats)
        else:
            if progress_callback:
                progress_callback(2, "screenshots", "skip", message="gowitness not available")

        scan.update_phase(ScanPhase.VALIDATION)

        duration = time.time() - phase_start
        scan.stats.record_phase_duration("validation", duration)

        # Export results incrementally (allows resume if interrupted)
        self._export_phase_results(scan, 2)

        # Log phase summary
        logger.info(
            "Phase 2 complete",
            dns_resolved=stats.dns_resolved,
            http_alive=stats.http_alive,
            screenshots=stats.screenshots_captured,
            duration=f"{duration:.1f}s",
        )

    async def _run_phase3_scanning(
        self,
        scan: Scan,
        max_workers: Optional[int],
        progress_callback: Optional[Callable],
        stats: PhaseStats,
    ) -> None:
        """Run Phase 3: Vulnerability Scanning with PARALLEL WORKERS."""
        phase_start = time.time()

        if not scan.hosts:
            logger.info("No live hosts to scan")
            if progress_callback:
                progress_callback(3, "nuclei_scan", "skip", message="No live hosts to scan")
            return

        from reconductor.modules.scanning.nuclei_manager import split_into_batches
        from reconductor.models.host import Host

        # Filter hosts worth scanning:
        # - Skip 404 (Not Found) - no content to scan
        # - Skip 500+ (Server errors) - unreliable targets
        # - Keep 401/403 - may have auth bypass or path traversal vulns
        scannable_hosts = []
        skipped_404 = 0
        skipped_5xx = 0
        for h in scan.hosts:
            status = h.get("status_code", 0)
            if status == 404:
                skipped_404 += 1
            elif status >= 500:
                skipped_5xx += 1
            else:
                scannable_hosts.append(h)

        if skipped_404 or skipped_5xx:
            logger.info(
                f"Filtered hosts for Nuclei: skipped {skipped_404} 404s, {skipped_5xx} 5xx errors"
            )

        stats.nuclei_targets = len(scannable_hosts)

        if not scannable_hosts:
            logger.info("No scannable hosts after filtering (all 404/5xx)")
            if progress_callback:
                progress_callback(3, "nuclei_scan", "skip", message="No scannable hosts (all 404/5xx)")
            return

        # Convert host dicts to Host objects
        host_objects = []
        for h in scannable_hosts:
            # Get IPs from the correct fields
            ipv4 = h.get("ipv4_addresses", [])
            if not ipv4 and h.get("primary_ip"):
                ipv4 = [h["primary_ip"]]

            host = Host(
                hostname=h.get("hostname", ""),
                url=h.get("url"),
                ipv4_addresses=ipv4,
                status_code=h.get("status_code"),
            )
            host_objects.append(host)

        # Build status message with filter info
        filter_info = ""
        if skipped_404 or skipped_5xx:
            skipped_parts = []
            if skipped_404:
                skipped_parts.append(f"{skipped_404} 404s")
            if skipped_5xx:
                skipped_parts.append(f"{skipped_5xx} 5xx")
            filter_info = f" (skipped {', '.join(skipped_parts)})"

        if progress_callback:
            progress_callback(
                3, "nuclei_scan", "start",
                message=f"Nuclei: {stats.nuclei_targets} targets{filter_info}",
                nuclei_targets=stats.nuclei_targets,
            )
            progress_callback(3, "nuclei_scan", "progress", current=0, total=stats.nuclei_targets)

        logger.info(f"Starting Nuclei scan: {stats.nuclei_targets} targets{filter_info}")

        # Create progress callback for nuclei
        def nuclei_progress(current: int, total: int) -> None:
            if progress_callback:
                progress_callback(3, "nuclei_scan", "progress", current=current, total=total)

        # Run Nuclei AND non-HTTP subdomain port scan in PARALLEL
        # This scans non-HTTP subdomains for other services while nuclei runs
        async def run_nuclei():
            return await self.nuclei.scan_parallel(
                hosts=host_objects,
                max_workers=max_workers,
                progress_callback=nuclei_progress,
                standalone=False,
            )

        async def scan_non_http_subdomains():
            """Scan non-HTTP subdomains for open ports (other services)."""
            if not hasattr(scan, 'non_http_subdomains') or not scan.non_http_subdomains:
                return {}

            if not PortScanner.is_available():
                logger.debug("naabu not available, skipping non-HTTP subdomain port scan")
                return {}

            logger.info(f"Scanning {len(scan.non_http_subdomains)} non-HTTP subdomains for open ports")

            # Scan all ports (not just web ports) on non-HTTP subdomains
            port_results = await self.port_scanner.scan_all_ports(scan.non_http_subdomains)

            # Convert results to dict format
            ports_map = {}
            for hostname, result in port_results.items():
                if result.open_ports:
                    ports_map[hostname] = result.open_ports
                    logger.debug(f"Found ports on {hostname}: {result.open_ports}")

            return ports_map

        # Run both in parallel
        nuclei_task = run_nuclei()
        non_http_scan_task = scan_non_http_subdomains()

        findings, non_http_ports = await asyncio.gather(nuclei_task, non_http_scan_task)

        # Store non-HTTP subdomain port results
        scan.non_http_subdomains_ports = non_http_ports
        if non_http_ports:
            logger.info(f"Found open ports on {len(non_http_ports)} non-HTTP subdomains")

        # Count findings by severity
        for finding in findings:
            scan.findings.append(finding.to_dict())
            scan.stats.add_finding(finding.severity.value)

            sev = finding.severity.value.lower()
            if sev == "critical":
                stats.findings_critical += 1
            elif sev == "high":
                stats.findings_high += 1
            elif sev == "medium":
                stats.findings_medium += 1
            elif sev == "low":
                stats.findings_low += 1
            else:
                stats.findings_info += 1

        total_findings = len(findings)

        if progress_callback:
            progress_callback(
                3, "nuclei_scan", "complete",
                message=f"Nuclei: {total_findings} findings (C:{stats.findings_critical} H:{stats.findings_high} M:{stats.findings_medium})",
                findings=total_findings,
                critical=stats.findings_critical,
                high=stats.findings_high,
                medium=stats.findings_medium,
            )

        logger.info(
            "Nuclei scan complete",
            findings=total_findings,
            critical=stats.findings_critical,
            high=stats.findings_high,
        )

        scan.update_phase(ScanPhase.SCANNING)

        duration = time.time() - phase_start
        scan.stats.record_phase_duration("scanning", duration)

        # Export results incrementally (allows resume if interrupted)
        self._export_phase_results(scan, 3)

        # Log phase summary
        logger.info(
            "Phase 3 complete",
            findings=total_findings,
            duration=f"{duration:.1f}s",
        )

    async def _run_phase4_analysis(
        self,
        scan: Scan,
        progress_callback: Optional[Callable],
        stats: PhaseStats,
    ) -> None:
        """Run Phase 4: Analysis (Takeover + Origin IP Discovery + GAU AI Filter)."""
        phase_start = time.time()

        # Step 1: Subdomain Takeover Detection
        if progress_callback:
            progress_callback(4, "takeover_check", "start", message="Checking subdomain takeovers...")

        # Initialize takeover detector
        await self.takeover.initialize()

        # Check for subdomain takeovers
        from reconductor.models.subdomain import Subdomain
        subdomains = []
        for host in scan.hosts:
            sub = Subdomain.from_name(host.get("hostname", ""))
            if "cname" in host:
                sub.cname_chain = host["cname"]
            subdomains.append(sub)

        takeover_findings = await self.takeover.check_subdomains(subdomains)

        stats.takeover_candidates = len(takeover_findings)

        for finding in takeover_findings:
            scan.findings.append(finding.to_dict())
            scan.stats.takeover_candidates += 1

        if progress_callback:
            progress_callback(
                4, "takeover_check", "complete",
                message=f"Takeover: {stats.takeover_candidates} candidates",
                findings=scan.stats.findings_total,
                takeovers=stats.takeover_candidates,
            )

        # Step 2: Origin IP Discovery (Cloudflare/CDN bypass)
        await self._run_origin_ip_discovery(scan, progress_callback, stats)

        # Step 3: GAU AI Filtering (only if --ai-triage is enabled AND GAU found URLs in Phase 2)
        # Note: GAU runs in Phase 2 in parallel. This step just does AI filtering for triage.
        ai_triage_enabled = scan.config.get("ai_triage", False)
        if ai_triage_enabled and scan.gau_result and scan.gau_result.all_urls:
            await self._run_gau_ai_filter(scan, progress_callback, stats)
        elif scan.gau_result and scan.gau_result.unique_urls > 0:
            # Auto-validate top high-value URLs without AI filtering
            await self._validate_top_gau_urls(scan, progress_callback, stats)
        else:
            if progress_callback:
                progress_callback(4, "gau_filter", "skip", message="No GAU URLs found")

        scan.update_phase(ScanPhase.ANALYSIS)

        duration = time.time() - phase_start
        scan.stats.record_phase_duration("analysis", duration)

        logger.info(
            "Phase 4 complete",
            takeover_candidates=stats.takeover_candidates,
            origin_ips=stats.origin_ips_found,
            gau_urls=stats.gau_unique_urls,
            duration=f"{duration:.1f}s",
        )

    async def _run_origin_ip_discovery(
        self,
        scan: Scan,
        progress_callback: Optional[Callable],
        stats: PhaseStats,
    ) -> None:
        """
        Comprehensive origin IP discovery behind CDN/WAF.

        Techniques:
        - DNS-based: SPF records, MX records, AAAA records
        - Subdomain analysis: Non-CDN IPs from enumerated subdomains
        - Shodan: SSL Certificate CN, Favicon hash matching
        - HTTP validation: Response comparison with CDN baseline
        """
        try:
            from reconductor.modules.recon.origin_discovery import OriginDiscovery
            from reconductor.core.config import get_api_keys
        except ImportError:
            logger.debug("Origin discovery module not available")
            return

        # Load API keys from config/environment
        api_keys = get_api_keys()
        shodan_key = api_keys.get_shodan()
        securitytrails_key = api_keys.get_securitytrails()

        # Check if any hosts are behind CDN (from httpx detection in Phase 2)
        cdn_hosts_detected = []
        cdn_provider_detected = None
        if scan.hosts:
            for host in scan.hosts:
                if host.get("cdn_detected") or host.get("cdn"):
                    cdn_hosts_detected.append(host.get("hostname", ""))
                    if host.get("cdn_name") or host.get("cdn_provider"):
                        cdn_provider_detected = host.get("cdn_name") or host.get("cdn_provider")

        # Skip if no CDN detected by httpx
        if not cdn_hosts_detected:
            if progress_callback:
                progress_callback(4, "origin_discovery", "skip", message="No CDN detected (httpx)")
            logger.debug("No CDN detected by httpx, skipping origin discovery")
            return

        if progress_callback:
            cdn_msg = f"CDN detected ({cdn_provider_detected or 'unknown'}), discovering origin IPs..."
            progress_callback(4, "origin_discovery", "start", message=cdn_msg)

        # Build subdomain -> IP mapping from scan data
        subdomains = []
        resolved_ips = {}

        # Get subdomains from scan
        if hasattr(scan, 'subdomains') and scan.subdomains:
            subdomains = [s.name if hasattr(s, 'name') else s for s in scan.subdomains]

        # Get resolved IPs from hosts
        if scan.hosts:
            for host in scan.hosts:
                hostname = host.get("hostname", "")
                ip = host.get("ip") or host.get("a_records", [None])[0] if host.get("a_records") else None
                if hostname and ip:
                    resolved_ips[hostname] = ip

        # Get target URL for baseline
        target_url = f"https://{scan.domain}"
        if scan.hosts:
            host = scan.hosts[0]
            target_url = host.get("url") or f"https://{host.get('hostname', scan.domain)}"

        # Run comprehensive discovery
        discovery = OriginDiscovery(
            shodan_api_key=shodan_key,
            securitytrails_api_key=securitytrails_key,
            validate_candidates=True,
            max_validation_candidates=10,
            use_checkhost=True,
        )

        result = await discovery.discover(
            domain=scan.domain,
            subdomains=subdomains,
            resolved_ips=resolved_ips,
            target_url=target_url,
        )

        # Update stats
        confirmed_count = len(result.confirmed_origins)
        candidate_count = len(result.candidates)
        stats.origin_ips_found = confirmed_count + candidate_count
        stats.cdn_hosts = len(result.cdn_ips)

        # Store results in scan
        scan.extra = scan.extra or {}

        if result.confirmed_origins or result.candidates:
            scan.extra["origin_discovery"] = result.to_dict()

            # Also store flat list for backwards compatibility
            scan.extra["origin_ips"] = [
                {
                    "ip": c.ip,
                    "confidence": c.confidence_level,
                    "validation_score": c.validation_score if c.is_validated else None,
                    "sources": c.sources,
                    "hostnames": c.hostnames,
                    "evidence": c.evidence,
                }
                for c in result.confirmed_origins + result.candidates
            ]

            # Log confirmed origins
            for origin in result.confirmed_origins:
                logger.warning(
                    f"CONFIRMED origin IP: {origin.ip} (score: {origin.validation_score:.2f})",
                    sources=origin.sources,
                    hostnames=origin.hostnames,
                )

        # Build status message
        if not result.is_behind_cdn:
            status_msg = "Not behind CDN"
        elif confirmed_count > 0:
            status_msg = f"CONFIRMED: {confirmed_count} origin IPs"
        elif candidate_count > 0:
            status_msg = f"Found {candidate_count} candidates (unconfirmed)"
        else:
            status_msg = "No origin IPs found"

        if progress_callback:
            progress_callback(
                4, "origin_discovery", "complete",
                message=status_msg,
                origin_ips=stats.origin_ips_found,
                cdn_hosts=stats.cdn_hosts,
                confirmed=confirmed_count,
                candidates=candidate_count,
            )

        logger.info(
            "Origin IP discovery complete",
            is_cdn=result.is_behind_cdn,
            cdn_provider=result.cdn_provider,
            confirmed=confirmed_count,
            candidates=candidate_count,
        )

        # Step 2b: Origin Scanning (nuclei directly against origin IPs, bypassing WAF)
        origin_scan_enabled = scan.config.get("origin_scan", True)  # Enabled by default
        all_origin_ips = [c.ip for c in result.confirmed_origins + result.candidates]

        if origin_scan_enabled and all_origin_ips and result.is_behind_cdn:
            await self._run_origin_nuclei_scan(
                scan, progress_callback, stats, all_origin_ips, result.cdn_provider
            )

    async def _run_origin_nuclei_scan(
        self,
        scan: Scan,
        progress_callback: Optional[Callable],
        stats: PhaseStats,
        origin_ips: list[str],
        cdn_provider: str,
    ) -> None:
        """
        Run aggressive nuclei scan against origin IPs, bypassing CDN/WAF.

        This scan finds vulnerabilities that are hidden behind the CDN:
        - Version disclosure (nginx, PHP, etc.)
        - Path traversal bypasses
        - Misconfigurations
        - CVEs that WAF would block
        """
        try:
            from reconductor.modules.scanning.origin_scanner import OriginScanner
        except ImportError:
            logger.debug("Origin scanner not available")
            return

        if progress_callback:
            progress_callback(
                4, "origin_scan", "start",
                message=f"Scanning {len(origin_ips)} origin IPs (bypassing {cdn_provider})..."
            )

        try:
            scanner = OriginScanner(
                domain=scan.domain,
                rate_limit=150,
                concurrency=25,
            )

            scan_result = await scanner.scan(origin_ips)

            # Store results
            scan.extra = scan.extra or {}
            scan.extra["origin_scan"] = scan_result.to_dict()

            # Add findings to main findings list
            for finding in scan_result.findings:
                scan.findings.append({
                    "template_id": finding.template_id,
                    "name": finding.name,
                    "severity": finding.severity,
                    "host": finding.matched_at,
                    "source": "origin_scan",
                    "origin_ip": finding.ip,
                    "tags": finding.tags,
                    "reference": finding.reference,
                    "description": finding.description,
                })

            # Update stats
            summary = scan_result.to_dict().get("summary", {})
            origin_findings = len(scan_result.findings)

            # Log version disclosure
            if scan_result.version_info:
                unique_versions = set(scan_result.version_info.values())
                logger.warning(
                    f"Origin version disclosure: {', '.join(unique_versions)}",
                    hidden_by=cdn_provider,
                )

            if progress_callback:
                progress_callback(
                    4, "origin_scan", "complete",
                    message=f"Origin scan: {origin_findings} findings "
                            f"(C:{summary.get('critical', 0)} H:{summary.get('high', 0)} "
                            f"M:{summary.get('medium', 0)})",
                    findings=origin_findings,
                )

            logger.info(
                "Origin nuclei scan complete",
                findings=origin_findings,
                critical=summary.get("critical", 0),
                high=summary.get("high", 0),
                medium=summary.get("medium", 0),
                versions=list(set(scan_result.version_info.values())),
            )

        except Exception as e:
            logger.warning(f"Origin scan failed: {e}")
            if progress_callback:
                progress_callback(4, "origin_scan", "error", message=str(e))

    def _save_ai_feedback(self, domain: str, successful_prefixes: list[str]) -> None:
        """Save successful AI predictions for feedback loop."""
        try:
            feedback_dir = self.settings.output_dir / domain / "ai_feedback"
            feedback_dir.mkdir(parents=True, exist_ok=True)
            feedback_file = feedback_dir / "successful_prefixes.txt"

            # Append to existing file
            existing = set()
            if feedback_file.exists():
                existing = set(feedback_file.read_text().strip().split("\n"))

            combined = existing | set(successful_prefixes)
            feedback_file.write_text("\n".join(sorted(combined)))

            logger.debug(f"Saved {len(successful_prefixes)} AI predictions to feedback file")
        except Exception as e:
            logger.debug(f"Failed to save AI feedback: {e}")

    async def _run_screenshot_capture(
        self,
        scan: Scan,
        alive_hosts: list,
        progress_callback: Optional[Callable],
        stats: PhaseStats,
    ) -> None:
        """Capture screenshots of live hosts using gowitness."""
        # Create screenshots directory
        screenshot_dir = self.settings.output_dir / "screenshots"
        screenshot_dir.mkdir(parents=True, exist_ok=True)

        # Get URLs from alive hosts
        urls = []
        for host in alive_hosts:
            url = host.url or f"https://{host.hostname}"
            urls.append(url)

        if not urls:
            logger.debug("No URLs to screenshot")
            return

        if progress_callback:
            progress_callback(
                2, "screenshots", "start",
                message=f"Capturing screenshots for {len(urls)} hosts...",
            )

        logger.info(f"Starting screenshot capture for {len(urls)} hosts")

        try:
            result = await self.screenshot.capture_batch(
                targets=urls,
                output_dir=screenshot_dir,
                threads=8,
                timeout=30,
                delay=2,
            )

            stats.screenshots_captured = result.successful
            stats.screenshots_failed = result.failed

            # Generate screenshot gallery HTML
            if result.screenshots:
                gallery_path = self.settings.output_dir / "screenshots_gallery.html"
                generate_screenshot_gallery_html(
                    results=result.screenshots,
                    output_path=gallery_path,
                    title=f"Screenshots - {scan.domain}",
                )
                logger.info(f"Screenshot gallery saved to {gallery_path}")

            if progress_callback:
                progress_callback(
                    2, "screenshots", "complete",
                    message=f"Screenshots: {stats.screenshots_captured}/{len(urls)} captured",
                    screenshots_captured=stats.screenshots_captured,
                    screenshots_failed=stats.screenshots_failed,
                )

            logger.info(
                "Screenshot capture complete",
                captured=stats.screenshots_captured,
                failed=stats.screenshots_failed,
            )

        except Exception as e:
            logger.warning(f"Screenshot capture failed: {e}")
            if progress_callback:
                progress_callback(2, "screenshots", "complete", message=f"Screenshots failed: {str(e)[:30]}")

    async def _run_gau_ai_filter(
        self,
        scan: Scan,
        progress_callback: Optional[Callable],
        stats: PhaseStats,
    ) -> None:
        """Filter GAU URLs with AI for triage.

        Note: GAU already ran in Phase 2 in parallel. This step only does AI filtering
        to identify high-value URLs for the triage report.
        """
        if not scan.gau_result or not scan.gau_result.all_urls:
            if progress_callback:
                progress_callback(4, "gau_filter", "skip", message="No GAU URLs to filter")
            return

        if progress_callback:
            progress_callback(
                4, "gau_filter", "start",
                message=f"AI filtering {scan.gau_result.unique_urls} GAU URLs...",
            )

        try:
            from reconductor.modules.ai.gau_filter_agent import GauUrlFilterAgent

            filter_agent = GauUrlFilterAgent(max_urls=100)
            raw_urls = [u.url for u in scan.gau_result.all_urls]
            filter_result = await filter_agent.filter_urls(scan.domain, raw_urls)

            # Update stats
            stats.gau_targets_selected = len(filter_result.filtered_urls)  # "high-value URLs selected"

            # Store filtered high-value URLs for triage report
            scan.gau_result.high_value_urls = filter_result.filtered_urls
            scan.gau_result.filter_stats = filter_result.stats

            # Validate high-value URLs
            if filter_result.filtered_urls:
                logger.info(f"Validating {len(filter_result.filtered_urls)} high-value URLs...")
                high_value_gau_urls = [u for u in scan.gau_result.all_urls if u.url in set(filter_result.filtered_urls)][:100]
                if high_value_gau_urls:
                    validated = await self.gau.validate_urls(high_value_gau_urls, max_concurrent=20, timeout=10)
                    live_count = sum(1 for u in validated if u.validation_status and u.validation_status < 400)
                    stats.gau_validated_live = live_count
                    logger.info(f"Validation: {live_count}/{len(high_value_gau_urls)} URLs still accessible")

            method = filter_result.stats.get("method", "unknown")
            completion_msg = f"AI filtered: {len(filter_result.filtered_urls)} high-value URLs ({method})"

            if progress_callback:
                progress_callback(
                    4, "gau_filter", "complete",
                    message=completion_msg,
                    gau_high_value=len(filter_result.filtered_urls),
                )

            logger.info(
                "GAU AI filtering complete",
                high_value=len(filter_result.filtered_urls),
                method=method,
            )

            # Re-export GAU HTML with validation status
            from reconductor.core.exporter import export_gau_findings_html
            gau_html_path = self.settings.output_dir / "gau_findings.html"
            export_gau_findings_html(scan.gau_result, gau_html_path, scan.domain)

        except Exception as e:
            logger.warning(f"GAU AI filtering failed: {e}")
            if progress_callback:
                progress_callback(4, "gau_filter", "complete", message=f"AI filter failed: {str(e)[:30]}")

    async def _validate_top_gau_urls(
        self,
        scan: Scan,
        progress_callback: Optional[Callable],
        stats: PhaseStats,
    ) -> None:
        """
        Auto-validate top high-value GAU URLs without AI filtering.

        Selects URLs based on heuristics:
        - URLs with query parameters (injection points)
        - Interesting file extensions (.json, .xml, .config, .sql, .bak, etc.)
        - Sensitive paths (/api/, /admin/, /debug/, /graphql, etc.)

        This runs when --ai-triage is NOT enabled, to still provide status codes.
        """
        if not scan.gau_result or not scan.gau_result.all_urls:
            return

        if progress_callback:
            progress_callback(
                4, "gau_validate", "start",
                message=f"Validating top GAU URLs from {scan.gau_result.unique_urls} total...",
            )

        # High-value patterns for selection
        INTERESTING_EXTENSIONS = {
            '.json', '.xml', '.yaml', '.yml', '.config', '.conf', '.cfg',
            '.sql', '.db', '.sqlite', '.bak', '.backup', '.old', '.orig',
            '.log', '.txt', '.env', '.ini', '.properties', '.key', '.pem',
            '.csv', '.xls', '.xlsx', '.doc', '.docx', '.pdf',
            '.zip', '.tar', '.gz', '.rar', '.7z',
            '.php', '.asp', '.aspx', '.jsp', '.cgi',
        }

        INTERESTING_PATHS = {
            '/api/', '/graphql', '/admin', '/debug', '/internal',
            '/swagger', '/docs', '/console', '/manage', '/config',
            '/backup', '/test', '/dev', '/staging', '/wp-admin',
            '/phpinfo', '/elmah', '/trace', '/actuator', '/.git',
            '/.env', '/server-status', '/status', '/health', '/metrics',
        }

        def score_url(gau_url) -> int:
            """Score URL by security interest - higher is more interesting."""
            score = 0
            url_lower = gau_url.url.lower()
            path_lower = gau_url.path.lower()

            # URLs with params are high value (injection points)
            if gau_url.has_params:
                score += 10
                score += min(gau_url.param_count * 2, 10)  # More params = more interesting

            # Interesting file extensions
            for ext in INTERESTING_EXTENSIONS:
                if path_lower.endswith(ext):
                    score += 8
                    break

            # Interesting paths
            for pattern in INTERESTING_PATHS:
                if pattern in url_lower:
                    score += 7
                    break

            # Authentication/session endpoints
            auth_patterns = ['login', 'auth', 'token', 'session', 'oauth', 'sso', 'password', 'register']
            for pattern in auth_patterns:
                if pattern in url_lower:
                    score += 5
                    break

            return score

        try:
            # Score and sort all URLs
            scored_urls = [(url, score_url(url)) for url in scan.gau_result.all_urls]
            scored_urls.sort(key=lambda x: x[1], reverse=True)

            # Take top 75 high-value URLs (those with score > 0)
            top_urls = [url for url, score in scored_urls if score > 0][:75]

            # If we don't have enough high-value URLs, add some URLs with params
            if len(top_urls) < 50:
                param_urls = [u for u in scan.gau_result.all_urls if u.has_params and u not in top_urls]
                top_urls.extend(param_urls[:50 - len(top_urls)])

            if not top_urls:
                if progress_callback:
                    progress_callback(
                        4, "gau_validate", "complete",
                        message=f"GAU: {scan.gau_result.unique_urls} URLs (no high-value URLs to validate)",
                    )
                return

            logger.info(f"Validating {len(top_urls)} high-value URLs (heuristic selection)...")

            # Validate URLs
            validated = await self.gau.validate_urls(top_urls, max_concurrent=20, timeout=10)
            live_count = sum(1 for u in validated if u.validation_status and u.validation_status < 400)

            stats.gau_validated_live = live_count
            stats.gau_targets_selected = len(top_urls)

            # Store high-value URLs
            scan.gau_result.high_value_urls = [u.url for u in top_urls]

            if progress_callback:
                progress_callback(
                    4, "gau_validate", "complete",
                    message=f"GAU: {live_count}/{len(top_urls)} high-value URLs live (of {scan.gau_result.unique_urls} total)",
                    gau_high_value=len(top_urls),
                )

            logger.info(
                "GAU URL validation complete",
                validated=len(top_urls),
                live=live_count,
                total=scan.gau_result.unique_urls,
            )

            # Re-export GAU HTML with validation status
            from reconductor.core.exporter import export_gau_findings_html
            gau_html_path = self.settings.output_dir / "gau_findings.html"
            export_gau_findings_html(scan.gau_result, gau_html_path, scan.domain)

        except Exception as e:
            logger.warning(f"GAU URL validation failed: {e}")
            if progress_callback:
                progress_callback(
                    4, "gau_validate", "complete",
                    message=f"GAU: {scan.gau_result.unique_urls} URLs (validation failed: {str(e)[:30]})",
                )

    def _get_wordlist(self, ai_wordlist: list[str] = None) -> Path:
        """
        Get the wordlist path for brute-forcing.

        Combines base wordlist with AI-generated wordlist.
        """
        # Start with base wordlist
        base_wordlist = []

        # Check for custom wordlist
        custom = self.settings.wordlists_dir / "subdomains.txt"
        if custom.exists():
            base_wordlist = custom.read_text().strip().split("\n")
        else:
            # Use built-in wordlist
            from reconductor.modules.ai.wordlist_generator import get_base_wordlist
            base_wordlist = get_base_wordlist()

        # Combine with AI wordlist
        combined = set(base_wordlist)
        if ai_wordlist:
            combined.update(ai_wordlist)

        # Write to temp file
        temp_path = secure_temp_file(suffix="_wordlist.txt")
        temp_path.write_text("\n".join(sorted(combined)))
        return temp_path

    def _export_reports(self, result: dict[str, Any]) -> None:
        """Export all report formats to the output directory."""
        try:
            output_dir = self.settings.output_dir
            if output_dir is None:
                output_dir = Path("output") / result.get("domain", "unknown")

            exporter = ReportExporter(output_dir)
            exported = exporter.export_all(result)

            # Export non-HTTP subdomains report if there are any
            if result.get("non_http_subdomains"):
                non_http_report = exporter.export_non_http_subdomains_report(result)
                if non_http_report:
                    exported["non_http_subdomains_report"] = non_http_report

            logger.info(
                "Reports exported successfully",
                output_dir=str(output_dir),
                files=list(exported.keys()),
            )
        except Exception as e:
            logger.error(f"Failed to export reports: {e}")

    def _build_result(self, scan: Scan, stats: PhaseStats) -> dict[str, Any]:
        """Build the final result dictionary with detailed stats."""
        result = {
            "scan_id": scan.scan_id,
            "domain": scan.domain,
            "status": scan.status.value,
            "phase": scan.phase.value,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "duration_seconds": scan.duration_seconds,
            "subdomains": scan.subdomains,
            "hosts": scan.hosts,
            "findings": scan.findings,
            "stats": {
                # Phase 1 detailed
                "subdomains_discovered": stats.total_subdomains,
                "passive_total": stats.passive_total,
                "subfinder_count": stats.subfinder_count,
                "crtsh_count": stats.crtsh_count,
                "shodan_count": stats.shodan_count,
                "wayback_count": stats.wayback_count,
                "ai_wordlist_count": stats.ai_wordlist_count,
                "ai_wordlist_hits": stats.ai_wordlist_hits,
                "ai_hit_rate": stats.ai_hit_rate,
                "ai_unique_finds": stats.ai_unique_finds,
                "bruteforce_count": stats.bruteforce_count,
                "permutation_count": stats.permutation_count,

                # Phase 2 detailed
                "dns_resolved": stats.dns_resolved,
                "dns_failed": stats.dns_failed,
                "ports_scanned": stats.ports_scanned,
                "open_ports": stats.open_ports,
                "http_probed": stats.http_probed,
                "hosts_alive": stats.http_alive,
                "subdomains_alive": stats.http_alive,
                "subjack_takeovers": stats.subjack_takeovers,

                # Phase 3 detailed
                "nuclei_targets": stats.nuclei_targets,
                "findings_total": scan.stats.findings_total,
                "findings_critical": stats.findings_critical,
                "findings_high": stats.findings_high,
                "findings_medium": stats.findings_medium,
                "findings_low": stats.findings_low,
                "findings_info": stats.findings_info,

                # Phase 4
                "takeover_candidates": stats.takeover_candidates,
                "origin_ips_found": stats.origin_ips_found,
                "cdn_hosts": stats.cdn_hosts,

                # Screenshots
                "screenshots_captured": stats.screenshots_captured,
                "screenshots_failed": stats.screenshots_failed,

                # GAU (Historical URL Mining)
                "gau_targets_selected": stats.gau_targets_selected,
                "gau_total_urls": stats.gau_total_urls,
                "gau_unique_urls": stats.gau_unique_urls,
                "gau_urls_with_params": stats.gau_urls_with_params,
                "gau_categories": stats.gau_categories,
                "gau_validated_live": stats.gau_validated_live,

                # Timing
                "phase_durations": scan.stats.phase_durations,
                "duration_seconds": scan.duration_seconds,
            },
            "errors": scan.errors,
        }

        # Include origin IPs if found
        if hasattr(scan, 'extra') and scan.extra and "origin_ips" in scan.extra:
            result["origin_ips"] = scan.extra["origin_ips"]

        # Include non-HTTP subdomains data
        if scan.non_http_subdomains:
            result["non_http_subdomains"] = scan.non_http_subdomains
            result["non_http_subdomains_ports"] = scan.non_http_subdomains_ports or {}

        # Include GAU result for detailed report generation
        if scan.gau_result:
            result["gau_result"] = scan.gau_result

        return result


async def run_quick_scan(domain: str) -> dict[str, Any]:
    """
    Run a quick passive-only scan.

    Args:
        domain: Target domain

    Returns:
        Scan results
    """
    from reconductor.core.scope import create_scope_validator

    settings = Settings()
    scope = create_scope_validator([domain])
    orchestrator = Orchestrator(settings=settings, scope_validator=scope)

    return await orchestrator.run_scan(domain, passive_only=True)
