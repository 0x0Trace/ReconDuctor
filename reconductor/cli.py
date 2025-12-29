"""Rich CLI interface for ReconDuctor."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress_bar import ProgressBar

from reconductor import __version__
from reconductor.core.config import Settings, load_settings
from reconductor.core.database import Database
from reconductor.core.checkpoint import CheckpointManager
from reconductor.core.logger import setup_logging, get_logger
from reconductor.core.scope import ScopeValidator, ScopeConfig

app = typer.Typer(
    name="reconductor",
    help="Subdomain reconnaissance toolkit",
    add_completion=False,
)
console = Console()
logger = get_logger(__name__)


class ScanProgress:
    """Manages scan progress display with Rich Live."""

    PHASES = {
        1: ("Subdomain Enumeration", [
            "passive_enum",
            "ai_wordlist",
            "dns_bruteforce",
            "permutations",
        ]),
        2: ("Live Host Validation", [
            "dns_resolve",
            "port_scan",
            "http_probe",
            "screenshots",
        ]),
        3: ("Vulnerability Scanning", [
            "nuclei_scan",
        ]),
        4: ("Analysis", [
            "takeover_check",
            "origin_discovery",
            "gau_mining",
        ]),
    }

    STEP_LABELS = {
        "passive_enum": "Passive",
        "ai_wordlist": "AI Wordlist",
        "dns_bruteforce": "Brute-force",
        "permutations": "Permutations",
        "dns_resolve": "DNS",
        "port_scan": "Ports",
        "http_probe": "HTTP",
        "screenshots": "Screenshots",
        "nuclei_scan": "Nuclei",
        "takeover_check": "Takeover",
        "origin_discovery": "CDN Bypass",
        "gau_mining": "GAU URLs",
    }

    # Total steps for progress calculation
    TOTAL_STEPS = 10  # All steps across all phases

    def __init__(self, domain: str):
        self.domain = domain
        self.current_phase = 0
        self.current_step = ""
        self.step_status: dict[str, str] = {}
        self.step_results: dict[str, str] = {}  # Store per-step results
        self.step_progress: dict[str, tuple[int, int]] = {}  # current, total for running steps
        self.start_time = time.time()  # Track elapsed time

        # Detailed statistics
        self.stats: dict[str, int] = {
            # Phase 1
            "subdomains": 0,
            "subfinder": 0,
            "crtsh": 0,
            "shodan": 0,
            "ai_generated": 0,
            "bruteforce": 0,
            "permutations": 0,
            # Phase 2
            "dns_resolved": 0,
            "dns_failed": 0,
            "ports_scanned": 0,
            "open_ports": 0,
            "http_probed": 0,
            "live_hosts": 0,
            # Phase 3
            "nuclei_targets": 0,
            "findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            # Phase 4
            "takeovers": 0,
            "origin_ips": 0,
            "cdn_hosts": 0,
        }
        self.messages: list[str] = []

        # Initialize all steps as pending
        for phase_num, (_, steps) in self.PHASES.items():
            for step in steps:
                self.step_status[step] = "pending"
                self.step_results[step] = ""

    def set_phase(self, phase: int, step: str) -> None:
        """Set current phase and step."""
        self.current_phase = phase
        self.current_step = step
        self.step_status[step] = "running"

    def complete_step(self, step: str, result: str = "") -> None:
        """Mark a step as complete with optional result."""
        self.step_status[step] = "done"
        if result:
            self.step_results[step] = result

    def skip_step(self, step: str) -> None:
        """Mark a step as skipped."""
        self.step_status[step] = "skipped"

    def update_stat(self, key: str, value: int) -> None:
        """Update a statistic."""
        self.stats[key] = value

    def add_message(self, msg: str) -> None:
        """Add a status message."""
        self.messages.append(msg)
        if len(self.messages) > 6:
            self.messages.pop(0)

    def update_step_progress(self, step: str, current: int, total: int) -> None:
        """Update progress for a running step."""
        self.step_progress[step] = (current, total)

    def clear_step_progress(self, step: str) -> None:
        """Clear progress for a completed step."""
        if step in self.step_progress:
            del self.step_progress[step]

    def get_elapsed_time(self) -> str:
        """Get formatted elapsed time."""
        elapsed = time.time() - self.start_time
        if elapsed < 60:
            return f"{elapsed:.0f}s"
        elif elapsed < 3600:
            mins = int(elapsed // 60)
            secs = int(elapsed % 60)
            return f"{mins}m {secs}s"
        else:
            hours = int(elapsed // 3600)
            mins = int((elapsed % 3600) // 60)
            return f"{hours}h {mins}m"

    def get_overall_progress(self) -> tuple[int, int, float]:
        """Get overall progress as (completed, total, percentage)."""
        completed = sum(1 for s in self.step_status.values() if s in ("done", "skipped"))
        total = self.TOTAL_STEPS
        pct = (completed / total * 100) if total > 0 else 0
        return completed, total, pct

    def __rich__(self) -> Table:
        """Make ScanProgress a Rich renderable for auto-refresh."""
        return self.render()

    def render(self) -> Table:
        """Render the progress display - clean, professional layout."""
        main = Table.grid(padding=0)
        main.add_column()

        # === HEADER BAR ===
        completed, total, pct = self.get_overall_progress()
        elapsed = self.get_elapsed_time()

        header_table = Table.grid(padding=0, expand=True)
        header_table.add_column(ratio=1)
        header_table.add_column(justify="right")

        left = Text()
        left.append("RECONDUCTOR", style="bold blue")
        left.append(f" v{__version__} ", style="dim")
        left.append("| ", style="dim")
        left.append(self.domain, style="bold white")

        right = Text()
        right.append(f"{pct:.0f}%", style="bold cyan")
        right.append(f" [{completed}/{total}]", style="dim")
        right.append("  ", style="")
        right.append(elapsed, style="bold yellow")

        header_table.add_row(left, right)
        main.add_row(Panel(header_table, border_style="blue", padding=(0, 1)))

        # === PHASES TABLE ===
        phase_table = Table(
            show_header=True,
            header_style="bold",
            border_style="dim",
            box=None,
            padding=(0, 2),
            expand=True,
        )
        phase_table.add_column("PHASE", style="cyan", width=24)
        phase_table.add_column("STATUS", width=10)
        phase_table.add_column("DETAILS", ratio=1)

        for phase_num, (phase_name, steps) in self.PHASES.items():
            phase_done = all(self.step_status.get(s) in ("done", "skipped") for s in steps)
            phase_running = any(self.step_status.get(s) == "running" for s in steps)

            # Phase name
            phase_label = f"{phase_num}. {phase_name}"

            # Status indicator
            if phase_done:
                status = Text("DONE", style="bold green")
            elif phase_running:
                status = Text("RUNNING", style="bold yellow")
            else:
                status = Text("PENDING", style="dim")

            # Build step details
            details = Text()
            first_step = True
            for step in steps:
                if not first_step:
                    details.append("  ", style="dim")
                first_step = False

                step_label = self.STEP_LABELS.get(step, step)
                step_stat = self.step_status.get(step, "pending")
                step_result = self.step_results.get(step, "")
                step_prog = self.step_progress.get(step)

                if step_stat == "done":
                    details.append(step_label, style="green")
                    if step_result:
                        details.append(f":{step_result}", style="bold white")
                elif step_stat == "running":
                    details.append(step_label, style="yellow")
                    if step_prog:
                        current, prog_total = step_prog
                        prog_pct = (current / prog_total * 100) if prog_total > 0 else 0
                        details.append(f" {current}/{prog_total}", style="bold cyan")
                        details.append(f" ({prog_pct:.0f}%)", style="dim")
                    else:
                        details.append("...", style="dim")
                elif step_stat == "skipped":
                    details.append(step_label, style="dim")
                    details.append(":skip", style="dim")
                else:
                    details.append(step_label, style="dim")

            phase_table.add_row(phase_label, status, details)

        main.add_row(Panel(phase_table, title="[bold]Progress[/bold]", border_style="cyan", padding=(0, 0)))

        # === RUNNING STEP PROGRESS BAR ===
        for step, (current, total) in self.step_progress.items():
            if self.step_status.get(step) == "running" and total > 0:
                step_label = self.STEP_LABELS.get(step, step)
                pct = current / total

                bar_table = Table.grid(padding=0, expand=True)
                bar_table.add_column(width=14)
                bar_table.add_column(ratio=1)
                bar_table.add_column(width=16, justify="right")

                bar = ProgressBar(total=total, completed=current, width=None)

                bar_table.add_row(
                    Text(f"  {step_label}", style="yellow"),
                    bar,
                    Text(f"{current:,}/{total:,} ({pct*100:.0f}%)", style="dim"),
                )
                main.add_row(bar_table)
                break  # Only show one progress bar at a time

        # === STATISTICS ===
        stats_table = Table.grid(padding=(0, 3), expand=True)
        stats_table.add_column(width=20)
        stats_table.add_column(width=12)
        stats_table.add_column(width=20)
        stats_table.add_column(width=12)

        # Build findings summary
        findings_parts = []
        if self.stats["critical"] > 0:
            findings_parts.append(f"[red]C:{self.stats['critical']}[/red]")
        if self.stats["high"] > 0:
            findings_parts.append(f"[orange3]H:{self.stats['high']}[/orange3]")
        if self.stats["medium"] > 0:
            findings_parts.append(f"[yellow]M:{self.stats['medium']}[/yellow]")
        findings_str = " ".join(findings_parts) if findings_parts else "-"

        stats_table.add_row(
            Text("Subdomains", style="dim"),
            Text(f"{self.stats['subdomains']:,}", style="bold cyan"),
            Text("Live Hosts", style="dim"),
            Text(f"{self.stats['live_hosts']:,}", style="bold green"),
        )
        stats_table.add_row(
            Text("Findings", style="dim"),
            Text.from_markup(findings_str),
            Text("Targets", style="dim"),
            Text(str(self.stats["nuclei_targets"]) if self.stats["nuclei_targets"] > 0 else "-", style="white"),
        )

        main.add_row(Panel(stats_table, title="[bold]Stats[/bold]", border_style="green", padding=(0, 1)))

        # === ACTIVITY LOG ===
        if self.messages:
            # Show last 4 messages
            recent = self.messages[-4:]
            activity = Text()
            first_msg = True
            for msg in recent:
                if not first_msg:
                    activity.append("\n")
                first_msg = False
                activity.append(msg, style="dim")
            main.add_row(Panel(activity, title="[bold]Activity[/bold]", border_style="dim", padding=(0, 1)))

        return main


def _show_banner() -> None:
    """Display the ReconDuctor banner with tool information."""
    banner = r"""
[bold cyan]
  ____                       ____             _
 |  _ \ ___  ___ ___  _ __  |  _ \ _   _  ___| |_ ___  _ __
 | |_) / _ \/ __/ _ \| '_ \ | | | | | | |/ __| __/ _ \| '__|
 |  _ <  __/ (_| (_) | | | || |_| | |_| | (__| || (_) | |
 |_| \_\___|\___\___/|_| |_||____/ \__,_|\___|\__\___/|_|
[/bold cyan]"""
    console.print(banner)
    console.print(f"  [bold blue]ReconDuctor[/bold blue] v{__version__}")
    console.print()
    console.print("  [bold]Usage:[/bold]")
    console.print("    [green]reconductor scan example.com[/green]")
    console.print("    [green]reconductor scan example.com --ai[/green]")
    console.print("    [green]reconductor list-scans[/green]")
    console.print()
    console.print("  [dim]Run[/dim] [bold]reconductor --help[/bold] [dim]for all options[/dim]")
    console.print()


def version_callback(value: bool) -> None:
    """Show version and exit."""
    if value:
        console.print(f"[bold blue]ReconDuctor[/bold blue] v{__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        None, "--version", "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version",
    ),
    debug: bool = typer.Option(
        False, "--debug", "-d",
        help="Enable debug mode",
    ),
) -> None:
    """ReconDuctor - Subdomain reconnaissance toolkit."""
    # Setup logging - quiet mode for CLI unless debug
    log_level = "DEBUG" if debug else "WARNING"
    setup_logging(level=log_level)

    # Show banner when no command is provided
    if ctx.invoked_subcommand is None:
        _show_banner()


@app.command()
def scan(
    domain: str = typer.Argument(..., help="Target domain to scan"),
    output_dir: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output directory",
    ),
    phase: int = typer.Option(
        0, "--phase", "-p",
        help="Start from specific phase (0=all)",
    ),
    passive_only: bool = typer.Option(
        False, "--passive-only",
        help="Only run passive enumeration",
    ),
    no_nuclei: bool = typer.Option(
        False, "--no-nuclei",
        help="Skip vulnerability scanning",
    ),
    no_origin_scan: bool = typer.Option(
        False, "--no-origin-scan",
        help="Skip origin IP nuclei scanning (WAF bypass scan)",
    ),
    use_ai: bool = typer.Option(
        False, "--ai",
        help="Enable AI-powered subdomain wordlist generation. Uses Claude (haiku) to generate targeted subdomain prefixes based on CT logs, Wayback data, and detected patterns. Improves bruteforce discovery.",
    ),
    ai_triage: bool = typer.Option(
        False, "--ai-triage",
        help="Enable AI-powered vulnerability triage. Uses Claude (sonnet) to analyze findings, prioritize by risk, identify attack chains, and generate executive summary. Also filters GAU URLs to high-value targets. Creates triage_report.html.",
    ),
    rate_limit: int = typer.Option(
        30, "--rate-limit", "-r",
        help="Requests per second",
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q",
        help="Minimal output",
    ),
) -> None:
    """Run a full reconnaissance scan on a domain."""
    asyncio.run(_run_scan(
        domain=domain,
        output_dir=output_dir,
        phase=phase,
        passive_only=passive_only,
        no_nuclei=no_nuclei,
        no_origin_scan=no_origin_scan,
        use_ai=use_ai,
        ai_triage=ai_triage,
        rate_limit=rate_limit,
        quiet=quiet,
    ))


async def _run_scan(
    domain: str,
    output_dir: Optional[Path],
    phase: int,
    passive_only: bool,
    no_nuclei: bool,
    no_origin_scan: bool,
    use_ai: bool,
    ai_triage: bool,
    rate_limit: int,
    quiet: bool,
) -> None:
    """Execute the reconnaissance scan."""
    from reconductor.core.orchestrator import Orchestrator
    from reconductor.modules.ai.finding_analyzer import FindingAnalyzer

    # Setup output directory
    if output_dir is None:
        output_dir = Path(f"output/{domain}")
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load settings
    settings = Settings()
    settings.output_dir = output_dir

    # Create scope validator
    scope = ScopeValidator(ScopeConfig(allowed_domains=[domain]))

    # Initialize database
    db = Database(output_dir / "scan.db")
    await db.connect()

    # Create checkpoint manager
    checkpoint = CheckpointManager(db)

    # Create orchestrator
    orchestrator = Orchestrator(
        settings=settings,
        scope_validator=scope,
        checkpoint_manager=checkpoint,
    )

    # Create progress tracker
    progress = ScanProgress(domain)

    try:
        if quiet:
            # Simple quiet mode
            console.print(f"[cyan]Scanning {domain}...[/cyan]")
            result = await orchestrator.run_scan(
                domain=domain,
                passive_only=passive_only,
                skip_nuclei=no_nuclei,
                skip_ai_wordlist=not use_ai,  # Skip AI unless --ai flag is used
                ai_triage=ai_triage,  # AI triage filters GAU URLs
                origin_scan=not no_origin_scan,  # Origin IP scanning (WAF bypass)
                rate_limit=rate_limit,
            )
        else:
            # Rich live display - pass progress object for auto-refresh of timer
            with Live(progress, console=console, refresh_per_second=2) as live:
                def update_progress(phase_num: int, step: str, status: str, **kwargs):
                    """Callback to update progress display."""
                    if status == "start":
                        progress.set_phase(phase_num, step)
                        if "message" in kwargs:
                            progress.add_message(kwargs["message"])
                        # Update nuclei_targets when nuclei scan starts
                        if step == "nuclei_scan" and "nuclei_targets" in kwargs:
                            progress.update_stat("nuclei_targets", kwargs["nuclei_targets"])

                    elif status == "progress":
                        # Update step-level progress (e.g., DNS: 50/100)
                        current = kwargs.get("current", 0)
                        total = kwargs.get("total", 0)
                        if total > 0:
                            progress.update_step_progress(step, current, total)

                    elif status == "complete":
                        # Clear step progress
                        progress.clear_step_progress(step)

                        # Build result string for step AND update stats immediately
                        result_str = ""
                        if step == "passive_enum":
                            result_str = str(kwargs.get("subdomains", 0))
                            progress.update_stat("subdomains", kwargs.get("subdomains", 0))
                        elif step == "ai_wordlist":
                            result_str = str(kwargs.get("ai_generated", 0))
                        elif step == "dns_bruteforce":
                            result_str = f"+{kwargs.get('bruteforce', 0)}"
                        elif step == "permutations":
                            generated = kwargs.get('alterx_generated', 0)
                            resolved = kwargs.get('permutations', 0)
                            result_str = f"{generated} → +{resolved}"
                        elif step == "dns_resolve":
                            result_str = f"{kwargs.get('dns_resolved', 0)}"
                        elif step == "port_scan":
                            result_str = f"{kwargs.get('open_ports', 0)} ports"
                        elif step == "http_probe":
                            live_count = kwargs.get("live_hosts", 0)
                            result_str = f"{live_count} live"
                            # Explicitly update live_hosts stat for Stats panel
                            progress.update_stat("live_hosts", live_count)
                        elif step == "nuclei_scan":
                            c = kwargs.get("critical", 0)
                            h = kwargs.get("high", 0)
                            m = kwargs.get("medium", 0)
                            result_str = f"{kwargs.get('findings', 0)} (C:{c} H:{h} M:{m})"
                        elif step == "takeover_check":
                            result_str = str(kwargs.get("takeovers", 0))
                        elif step == "origin_discovery":
                            result_str = str(kwargs.get("origin_ips", 0))

                        progress.complete_step(step, result_str)
                        if "message" in kwargs:
                            progress.add_message(kwargs["message"])

                    elif status == "skip":
                        progress.skip_step(step)

                    # Update all stats from kwargs
                    for key in ["subdomains", "subfinder", "crtsh", "shodan", "ai_generated",
                                "bruteforce", "permutations", "alterx_generated", "dns_resolved", "dns_failed",
                                "http_probed", "live_hosts", "nuclei_targets",
                                "findings", "critical", "high", "medium", "takeovers",
                                "origin_ips", "cdn_hosts"]:
                        if key in kwargs:
                            progress.update_stat(key, kwargs[key])

                    live.update(progress.render())

                result = await orchestrator.run_scan(
                    domain=domain,
                    passive_only=passive_only,
                    skip_nuclei=no_nuclei,
                    skip_ai_wordlist=not use_ai,  # Skip AI unless --ai flag is used
                    ai_triage=ai_triage,  # AI triage filters GAU URLs
                    origin_scan=not no_origin_scan,  # Origin IP scanning (WAF bypass)
                    rate_limit=rate_limit,
                    progress_callback=update_progress,
                )

        # Display final results
        _display_results(result, output_dir)

        # Run AI triage if requested and findings exist
        if ai_triage:
            await _run_ai_triage(domain, output_dir, quiet)

    finally:
        await db.close()


def _display_results(result: dict, output_dir: Path) -> None:
    """Display scan results with detailed breakdown."""
    console.print()

    stats = result.get("stats", {})

    # Phase-by-phase summary table
    summary = Table(title="[bold]Scan Complete[/bold]", border_style="green", show_header=False)
    summary.add_column("Section", style="cyan", width=50)
    summary.add_column("Details", style="white", width=40)

    # Phase 1 summary
    p1_details = []
    if stats.get("passive_total"):
        p1_details.append(f"Passive: {stats['passive_total']}")
    if stats.get("ai_wordlist_count"):
        p1_details.append(f"AI: +{stats['ai_wordlist_count']}")
    if stats.get("bruteforce_count"):
        p1_details.append(f"Brute: +{stats['bruteforce_count']}")
    if stats.get("permutation_count"):
        p1_details.append(f"Perms: +{stats['permutation_count']}")

    summary.add_row(
        f"[bold]Phase 1:[/bold] Subdomain Enumeration",
        f"[bold green]{stats.get('subdomains_discovered', 0)}[/bold green] total ({', '.join(p1_details)})"
    )

    # Phase 2 summary
    summary.add_row(
        f"[bold]Phase 2:[/bold] Live Host Validation",
        f"DNS: {stats.get('dns_resolved', 0)} → HTTP: [bold green]{stats.get('hosts_alive', 0)}[/bold green] live"
    )

    # Phase 3 summary
    findings_str = f"[bold]{stats.get('findings_total', 0)}[/bold]"
    if stats.get("findings_critical", 0) > 0:
        findings_str += f" [red](C:{stats['findings_critical']})[/red]"
    if stats.get("findings_high", 0) > 0:
        findings_str += f" [orange3](H:{stats['findings_high']})[/orange3]"
    if stats.get("findings_medium", 0) > 0:
        findings_str += f" [yellow](M:{stats['findings_medium']})[/yellow]"

    targets_info = f"{stats.get('nuclei_targets', 0)} targets" if stats.get("nuclei_targets") else "skipped"
    summary.add_row(
        f"[bold]Phase 3:[/bold] Vulnerability Scanning",
        f"{findings_str} findings ({targets_info})"
    )

    # Phase 4 summary
    p4_details = []
    if stats.get("takeover_candidates", 0) > 0:
        p4_details.append(f"{stats['takeover_candidates']} takeovers")
    if stats.get("origin_ips_found", 0) > 0:
        p4_details.append(f"[bold magenta]{stats['origin_ips_found']} origin IPs[/bold magenta]")

    summary.add_row(
        f"[bold]Phase 4:[/bold] Analysis",
        ", ".join(p4_details) if p4_details else "No issues found"
    )

    # Duration
    duration = stats.get("duration_seconds", 0)
    if duration:
        mins, secs = divmod(int(duration), 60)
        summary.add_row(
            "[bold]Total Duration[/bold]",
            f"[cyan]{mins}m {secs}s[/cyan]" if mins else f"[cyan]{secs}s[/cyan]"
        )

    console.print(summary)

    # Show origin IPs if found (Cloudflare bypass)
    origin_ips = result.get("origin_ips", [])
    if origin_ips:
        console.print()
        origin_table = Table(title="[bold magenta]Origin IPs Discovered (CDN Bypass)[/bold magenta]", border_style="magenta")
        origin_table.add_column("IP", style="bold white")
        origin_table.add_column("Hostname", style="cyan")
        origin_table.add_column("Confidence", style="yellow")
        origin_table.add_column("Evidence", style="dim")

        for origin in origin_ips[:10]:
            conf_style = {"high": "green", "medium": "yellow", "low": "dim"}.get(origin.get("confidence", "low"), "dim")
            # Handle evidence as dict or string
            evidence = origin.get("evidence", "")
            if isinstance(evidence, dict):
                # Join dict values into a single string
                evidence = ", ".join(str(v)[:30] for v in evidence.values() if v)[:60]
            elif isinstance(evidence, str) and len(evidence) > 40:
                evidence = evidence[:40] + "..."
            origin_table.add_row(
                origin.get("ip", ""),
                origin.get("hostname", "") or "-",
                f"[{conf_style}]{origin.get('confidence', 'low').upper()}[/{conf_style}]",
                evidence,
            )

        if len(origin_ips) > 10:
            origin_table.add_row(f"... and {len(origin_ips) - 10} more", "", "", "")

        console.print(origin_table)
        console.print("[dim]Tip: Test origin IPs with: curl -H 'Host: domain.com' http://IP[/dim]")

    # Show output files
    console.print()
    console.print(Panel.fit(
        f"[bold]{output_dir}[/bold]\n"
        "├── subdomains.txt\n"
        "├── live_hosts.txt\n"
        "├── hosts.json\n"
        "├── findings.json\n"
        "├── scan_info.json\n"
        "├── [bold cyan]report.html[/bold cyan] ← Open in browser\n"
        "└── [bold yellow]targets/[/bold yellow] ← Pentester action files\n"
        "    ├── fuzz_urls.txt\n"
        "    ├── sqli_candidates.txt\n"
        "    ├── ssrf_candidates.txt\n"
        "    ├── origin_ips.txt\n"
        "    └── [bold]next_steps.md[/bold] ← Start here",
        title="[green]Reports Saved[/green]",
        border_style="green",
    ))


async def _run_ai_triage(domain: str, output_dir: Path, quiet: bool) -> None:
    """Run AI-powered finding triage and generate prioritized report."""
    import json
    from reconductor.modules.ai.finding_analyzer import FindingAnalyzer
    from reconductor.models.finding import Finding

    findings_file = output_dir / "findings.json"

    if not findings_file.exists():
        if not quiet:
            console.print("[yellow]No findings to triage[/yellow]")
        return

    try:
        findings_data = json.loads(findings_file.read_text())
    except json.JSONDecodeError:
        console.print("[red]Error reading findings.json[/red]")
        return

    if not findings_data:
        if not quiet:
            console.print("[yellow]No findings to triage[/yellow]")
        return

    # Convert to Finding objects using the model's from_dict method
    findings = []
    for f in findings_data:
        try:
            finding = Finding.from_dict(f)
            findings.append(finding)
        except Exception as e:
            # Try minimal construction if from_dict fails
            try:
                findings.append(Finding(
                    target=f.get("target") or f.get("host") or f.get("matched_at") or "unknown",
                    title=f.get("template_name") or f.get("title") or f.get("name") or "Unknown",
                    template_id=f.get("template_id"),
                    severity=f.get("severity", "info"),
                    matched_at=f.get("matched_at"),
                    description=f.get("description"),
                ))
            except Exception:
                continue

    if not findings:
        if not quiet:
            console.print("[yellow]No valid findings to triage[/yellow]")
        return

    # Run triage
    if not quiet:
        console.print()
        console.print("[cyan]Running AI triage analysis...[/cyan]")

    analyzer = FindingAnalyzer()

    with console.status("[cyan]Analyzing findings with AI...[/cyan]", spinner="dots"):
        report = await analyzer.analyze(findings, domain=domain)

    # Save triage report
    triage_json_path = output_dir / "triage_report.json"
    triage_text_path = output_dir / "triage_report.txt"

    triage_json_path.write_text(json.dumps(report.to_dict(), indent=2))
    triage_text_path.write_text(report.to_text())

    # Display triage results
    console.print()
    console.print(Panel.fit(
        f"[bold]AI TRIAGE COMPLETE[/bold]\n\n"
        f"{report.total_findings} findings → {report.total_risk_items} prioritized risk items",
        title="[magenta]Risk Prioritization[/magenta]",
        border_style="magenta",
    ))

    if report.executive_summary:
        console.print()
        console.print(Panel(
            report.executive_summary,
            title="[bold]Executive Summary[/bold]",
            border_style="blue",
        ))

    # Display risk items table
    if report.risk_items:
        console.print()
        risk_table = Table(title="[bold]Prioritized Risk Items[/bold]", border_style="magenta")
        risk_table.add_column("#", style="bold", width=3)
        risk_table.add_column("Risk", style="bold", width=8)
        risk_table.add_column("Title", style="white", width=40)
        risk_table.add_column("Assets", style="cyan", width=20)
        risk_table.add_column("Env", style="dim", width=12)

        for item in report.risk_items[:10]:
            # Risk level styling
            risk_style = {
                "critical": "[bold red]CRITICAL[/bold red]",
                "high": "[orange3]HIGH[/orange3]",
                "medium": "[yellow]MEDIUM[/yellow]",
                "low": "[green]LOW[/green]",
            }.get(item.risk_level, item.risk_level)

            # Truncate assets
            assets_str = ", ".join(item.affected_assets[:2])
            if len(item.affected_assets) > 2:
                assets_str += f" +{len(item.affected_assets) - 2}"

            risk_table.add_row(
                str(item.rank),
                risk_style,
                item.title[:40] + "..." if len(item.title) > 40 else item.title,
                assets_str,
                item.environment,
            )

        if len(report.risk_items) > 10:
            risk_table.add_row("...", "", f"{len(report.risk_items) - 10} more items", "", "")

        console.print(risk_table)

    # Generate HTML triage report
    from reconductor.core.exporter import ReportExporter

    # Load scan result for exporter context
    scan_result = {"domain": domain, "findings": findings_data}
    exporter = ReportExporter(output_dir)
    triage_html_path = exporter.export_triage_report(scan_result)

    # Show triage output files
    console.print()
    console.print(f"[dim]Triage report saved to:[/dim]")
    if triage_html_path:
        console.print(f"  [cyan]{triage_html_path}[/cyan] (HTML report)")
    console.print(f"  [cyan]{triage_text_path}[/cyan] (text summary)")
    console.print(f"  [cyan]{triage_json_path}[/cyan] (machine-readable)")


@app.command()
def triage(
    domain: str = typer.Argument(..., help="Domain to triage (must have existing scan)"),
    output_dir: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output directory containing scan results",
    ),
) -> None:
    """Run AI-powered triage on existing scan findings.

    Analyzes vulnerability findings and generates a risk-prioritized report.
    Groups related issues, identifies attack chains, and provides remediation priorities.

    If GAU data exists from the scan, high-value URLs are included in the triage report.

    Example:
        reconductor triage example.com
        reconductor triage example.com -o ./custom-output
    """
    if output_dir is None:
        output_dir = Path(f"output/{domain}")

    if not output_dir.exists():
        console.print(f"[red]Scan directory not found: {output_dir}[/red]")
        console.print("[dim]Run a scan first: reconductor scan {domain}[/dim]")
        raise typer.Exit(1)

    findings_file = output_dir / "findings.json"
    if not findings_file.exists():
        console.print(f"[red]No findings.json found in {output_dir}[/red]")
        console.print("[dim]Make sure the scan completed with nuclei scanning enabled[/dim]")
        raise typer.Exit(1)

    asyncio.run(_run_ai_triage(domain, output_dir, quiet=False))


@app.command()
def gau(
    domain: str = typer.Argument(..., help="Target domain to mine URLs for"),
    output_dir: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output directory (defaults to output/<domain>)",
    ),
    use_ai: bool = typer.Option(
        False, "--ai",
        help="Use AI to filter and rank high-value URLs",
    ),
) -> None:
    """Run GAU historical URL mining standalone.

    Fetches historical URLs from Wayback Machine, Common Crawl, OTX, and URLScan
    for the target domain and all its subdomains.

    Use this if GAU was missed during Phase 2 or to run it independently.

    Example:
        reconductor gau example.com
        reconductor gau example.com --ai
    """
    if output_dir is None:
        output_dir = Path(f"output/{domain}")

    output_dir.mkdir(parents=True, exist_ok=True)

    asyncio.run(_run_gau_standalone(domain, output_dir, use_ai))


@app.command(name="list-scans")
def list_scans() -> None:
    """List all scans with their status and statistics."""
    output_path = Path("output")
    if not output_path.exists():
        console.print("[yellow]No scans found[/yellow]")
        return

    table = Table(title="[bold]Scans[/bold]")
    table.add_column("Domain", style="cyan")
    table.add_column("Subdomains", style="green", justify="right")
    table.add_column("Live Hosts", style="bold green", justify="right")
    table.add_column("Findings", style="red", justify="right")
    table.add_column("Phase", style="blue")
    table.add_column("Date", style="dim")

    scans_found = []

    for scan_dir in sorted(output_path.iterdir()):
        if scan_dir.is_dir():
            # Check what files exist to determine phase
            subdomains_file = scan_dir / "subdomains.txt"
            live_hosts_file = scan_dir / "live_hosts.txt"
            findings_file = scan_dir / "findings.json"
            scan_info_file = scan_dir / "scan_info.json"

            has_subdomains = subdomains_file.exists() and subdomains_file.stat().st_size > 0
            has_live_hosts = live_hosts_file.exists() and live_hosts_file.stat().st_size > 0
            has_findings = findings_file.exists()

            if not has_subdomains:
                continue  # Skip empty directories

            # Count subdomains
            subdomains_count = 0
            if has_subdomains:
                subdomains_count = len(subdomains_file.read_text().strip().split("\n"))

            # Count live hosts (unique URLs only)
            live_count = 0
            if has_live_hosts:
                live_urls = live_hosts_file.read_text().strip().split("\n")
                live_count = len(set(url.strip() for url in live_urls if url.strip()))

            # Count findings (check both final and partial files)
            findings_count = 0
            partial_findings_file = scan_dir / ".nuclei_findings_partial.json"
            if has_findings:
                import json
                try:
                    findings_data = json.loads(findings_file.read_text())
                    findings_count = len(findings_data)
                except Exception:
                    pass
            elif partial_findings_file.exists():
                # Check partial findings for incomplete scans
                import json
                try:
                    findings_data = json.loads(partial_findings_file.read_text())
                    findings_count = len(findings_data)
                except Exception:
                    pass

            # Check for resumable nuclei progress
            nuclei_progress_file = scan_dir / ".nuclei_progress.txt"
            has_nuclei_progress = nuclei_progress_file.exists() and nuclei_progress_file.stat().st_size > 0
            nuclei_scanned = 0
            if has_nuclei_progress:
                # Count unique URLs (progress file may have duplicates from batches)
                progress_urls = nuclei_progress_file.read_text().strip().split("\n")
                nuclei_scanned = len(set(url.strip() for url in progress_urls if url.strip()))

            # Determine phase status
            if has_findings and findings_count >= 0 and not has_nuclei_progress:
                phase_status = "complete"
                phase_num = 4
            elif has_nuclei_progress:
                phase_status = "nuclei_partial"
                phase_num = 3
            elif has_live_hosts:
                phase_status = "validation"
                phase_num = 2
            else:
                phase_status = "enumeration"
                phase_num = 1

            # Get date from scan_info or file mtime
            date_str = ""
            if scan_info_file.exists():
                try:
                    data = json.loads(scan_info_file.read_text())
                    completed = data.get("completed_at", "")
                    if completed:
                        date_str = completed[:10]
                    else:
                        date_str = data.get("started_at", "")[:10]
                except Exception:
                    pass

            if not date_str:
                # Use file modification time
                import datetime
                mtime = subdomains_file.stat().st_mtime
                date_str = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d")

            scans_found.append({
                "domain": scan_dir.name,
                "subdomains": subdomains_count,
                "live": live_count,
                "findings": findings_count,
                "phase_status": phase_status,
                "phase_num": phase_num,
                "date": date_str,
                "nuclei_scanned": nuclei_scanned,
            })

    if not scans_found:
        console.print("[yellow]No scans found[/yellow]")
        return

    # Sort by date descending
    scans_found.sort(key=lambda x: x["date"], reverse=True)

    for scan in scans_found:
        # Format findings with severity colors
        findings_str = str(scan["findings"]) if scan["findings"] > 0 else "-"
        if scan["findings"] > 0:
            findings_str = f"[red]{scan['findings']}[/red]"

        # Live hosts
        live_str = str(scan["live"]) if scan["live"] > 0 else "-"

        # Phase indicator
        if scan["phase_status"] == "complete":
            phase = "[green]Complete[/green]"
        elif scan["phase_status"] == "nuclei_partial":
            phase = f"[yellow]Nuclei[/yellow] ({scan['nuclei_scanned']}/{scan['live']} done)"
        elif scan["phase_status"] == "validation":
            phase = "[yellow]Phase 2[/yellow] (no nuclei)"
        else:
            phase = "[cyan]Phase 1[/cyan] (enum only)"

        table.add_row(
            scan["domain"],
            str(scan["subdomains"]),
            live_str,
            findings_str,
            phase,
            scan["date"],
        )

    console.print(table)
    console.print()

    # Show helpful hints based on what scans exist
    incomplete = [s for s in scans_found if s["phase_status"] != "complete"]
    if incomplete:
        console.print("[yellow]Incomplete scans:[/yellow]")
        for scan in incomplete[:3]:
            if scan["phase_status"] == "enumeration":
                console.print(f"  [cyan]{scan['domain']}[/cyan] → needs validation + nuclei")
            elif scan["phase_status"] == "nuclei_partial":
                remaining = scan["live"] - scan["nuclei_scanned"]
                console.print(f"  [cyan]{scan['domain']}[/cyan] → {remaining} hosts remaining")
            else:
                console.print(f"  [cyan]{scan['domain']}[/cyan] → needs nuclei scan")
        console.print()
        console.print("[dim]Run:[/dim] reconductor continue <domain>")


@app.command(name="continue")
def continue_scan(
    domain: str = typer.Argument(..., help="Domain to continue scanning"),
    no_nuclei: bool = typer.Option(
        False, "--no-nuclei",
        help="Skip vulnerability scanning",
    ),
    ai_triage: bool = typer.Option(
        False, "--ai-triage",
        help="Enable AI-powered vulnerability triage. Analyzes findings, prioritizes by risk, filters GAU URLs, and creates triage_report.html.",
    ),
) -> None:
    """
    Continue a scan from where it left off.

    If you ran --passive-only, this will run validation (HTTP probe) and Nuclei.
    If you ran --no-nuclei, this will run just Nuclei.

    Note: GAU historical URL mining runs automatically during validation.

    Examples:

      reconductor continue example.com

      reconductor continue example.com --no-nuclei
    """
    output_dir = Path(f"output/{domain}")

    if not output_dir.exists():
        console.print(f"[red]No scan found for {domain}[/red]")
        console.print("[dim]Run 'reconductor list-scans' to see available domains[/dim]")
        raise typer.Exit(1)

    # Check what we have
    subdomains_file = output_dir / "subdomains.txt"
    live_hosts_file = output_dir / "live_hosts.txt"
    findings_file = output_dir / "findings.json"

    has_subdomains = subdomains_file.exists() and subdomains_file.stat().st_size > 0
    has_live_hosts = live_hosts_file.exists() and live_hosts_file.stat().st_size > 0
    has_findings = findings_file.exists()

    if not has_subdomains:
        console.print(f"[red]No subdomains found for {domain}[/red]")
        console.print("[dim]Run a full scan first: reconductor scan {domain}[/dim]")
        raise typer.Exit(1)

    subdomains = subdomains_file.read_text().strip().split("\n")
    subdomains = [s for s in subdomains if s.strip()]

    console.print(f"[cyan]Continuing scan for {domain}[/cyan]")
    console.print(f"  Subdomains: [green]{len(subdomains)}[/green]")

    if has_live_hosts:
        live_hosts = live_hosts_file.read_text().strip().split("\n")
        live_hosts = [h for h in live_hosts if h.strip()]
        # Show unique count (file may have duplicates)
        unique_count = len(set(live_hosts))
        console.print(f"  Live hosts: [green]{unique_count}[/green]")

        if has_findings and not no_nuclei:
            console.print(f"[yellow]Scan appears complete. Use --no-nuclei to re-run validation only.[/yellow]")
            raise typer.Exit(0)

        if no_nuclei:
            console.print("[yellow]Nothing to do (--no-nuclei specified and validation complete)[/yellow]")
            raise typer.Exit(0)

        # Run Phase 3 only (nuclei scanning)
        console.print("\n[bold]Running Phase 3: Vulnerability Scanning[/bold]")
        asyncio.run(_continue_nuclei_only(domain, live_hosts, output_dir, ai_triage))
    else:
        # Run Phase 2 + 3 (GAU runs in parallel with validation)
        console.print(f"  Live hosts: [dim]not yet probed[/dim]")
        console.print("\n[bold]Running Phase 2: Validation (+ GAU) + Phase 3: Scanning[/bold]")
        asyncio.run(_continue_from_subdomains(domain, subdomains, no_nuclei, output_dir, ai_triage))


async def _continue_from_subdomains(
    domain: str,
    subdomains: list[str],
    no_nuclei: bool,
    output_dir: Path,
    ai_triage: bool = False,
) -> None:
    """Continue scan from subdomains - run validation and optionally nuclei."""
    import asyncio
    from reconductor.modules.validation.http_probe import HttpProber
    from reconductor.modules.scanning.nuclei_manager import NucleiManager
    from reconductor.modules.scanning.subjack_wrapper import SubjackWrapper
    from reconductor.models.host import Host
    from reconductor.core.exporter import ReportExporter

    # Phase 2: HTTP Probing + Subjack (parallel)
    console.print(f"\n[cyan]Phase 2: HTTP Probing + Takeover Detection[/cyan]")

    prober = HttpProber()
    subjack = SubjackWrapper()
    last_pct = -1

    def probe_progress(current: int, total: int):
        nonlocal last_pct
        pct = int((current / total) * 100) if total > 0 else 0
        bucket = (pct // 5) * 5
        if bucket != last_pct:
            last_pct = bucket
            console.print(f"  [cyan]HTTP probe: {pct}%[/cyan] | {current}/{total} hosts")

    async def run_http_probe():
        return await prober.probe_parallel(subdomains, progress_callback=probe_progress)

    async def run_subjack_scan():
        if not SubjackWrapper.is_available():
            console.print("  [dim]subjack not available, skipping takeover detection[/dim]")
            return []
        console.print(f"  [dim]Running subjack on {len(subdomains)} subdomains...[/dim]")
        return await subjack.scan(subdomains, threads=50, timeout=10)

    # Run HTTP probing and subjack in parallel
    hosts, takeover_findings = await asyncio.gather(run_http_probe(), run_subjack_scan())

    alive_hosts = [h for h in hosts if h.is_alive]
    console.print(f"\n[green]Found {len(alive_hosts)} live hosts[/green]")

    # Report takeover findings
    if takeover_findings:
        console.print(f"[red]Found {len(takeover_findings)} subdomain takeover(s)![/red]")
        for tf in takeover_findings:
            console.print(f"  [red]• {tf.target}[/red] → {tf.vulnerable_service}")

    # Save live hosts (deduplicated)
    live_hosts_file = output_dir / "live_hosts.txt"
    live_urls = sorted(set(h.url or f"https://{h.hostname}" for h in alive_hosts))
    live_hosts_file.write_text("\n".join(live_urls))

    # Save hosts.json
    import json
    hosts_file = output_dir / "hosts.json"
    hosts_file.write_text(json.dumps([h.to_dict() for h in alive_hosts], indent=2, default=str))

    console.print(f"[blue]Saved {len(alive_hosts)} live hosts to {live_hosts_file}[/blue]")

    # Initialize all_findings with takeover findings
    all_findings = list(takeover_findings)

    if not alive_hosts:
        console.print("[yellow]No live hosts to scan with Nuclei[/yellow]")
        # Still save takeover findings if any
        if all_findings:
            findings_file = output_dir / "findings.json"
            findings_file.write_text(json.dumps([f.to_dict() for f in all_findings], indent=2, default=str))
            _generate_html_report(domain, subdomains, [], all_findings, output_dir)
        return

    # Phase 3: Nuclei (if not skipped)
    if no_nuclei:
        console.print("[dim]Skipping Nuclei scan (--no-nuclei)[/dim]")
        # Still save takeover findings if any
        if all_findings:
            findings_file = output_dir / "findings.json"
            findings_file.write_text(json.dumps([f.to_dict() for f in all_findings], indent=2, default=str))
            _generate_html_report(domain, subdomains, alive_hosts, all_findings, output_dir)
        return

    console.print(f"\n[cyan]Phase 3: Nuclei Scanning[/cyan]")

    # Create Host objects for worker pool
    host_objects = []
    for h in alive_hosts:
        host_objects.append(Host(
            hostname=h.hostname,
            url=h.url,
            ipv4_addresses=h.ipv4_addresses or [],
        ))

    manager = NucleiManager(output_dir=output_dir)

    nuclei_findings = await manager.scan_batched(hosts=host_objects)
    console.print(f"\n[green]Found {len(nuclei_findings)} Nuclei findings[/green]")

    # Combine all findings
    all_findings.extend(nuclei_findings)

    # Save all findings (takeover + nuclei)
    findings_file = output_dir / "findings.json"
    findings_file.write_text(json.dumps([f.to_dict() for f in all_findings], indent=2, default=str))

    # Display findings summary
    if all_findings:
        _display_findings_table(all_findings)

    # Generate HTML report
    _generate_html_report(domain, subdomains, alive_hosts, all_findings, output_dir)

    # Note: GAU runs during validation (Phase 2) in parallel with HTTP probing
    # AI filtering of GAU URLs happens during triage if --ai-triage is enabled

    # Run AI triage if requested
    if ai_triage and all_findings:
        console.print("\n[cyan]Running AI-powered triage...[/cyan]")
        await _run_ai_triage(domain, output_dir, quiet=False)

    console.print(f"\n[blue]Results saved to {output_dir}[/blue]")


async def _continue_nuclei_only(
    domain: str,
    live_hosts: list[str],
    output_dir: Path,
    ai_triage: bool = False,
) -> None:
    """Continue scan with nuclei only (validation already done)."""
    from reconductor.modules.scanning.nuclei_manager import NucleiManager
    from reconductor.models.host import Host
    from reconductor.core.exporter import ReportExporter
    import json

    # Create manager with output_dir for resume support
    manager = NucleiManager(output_dir=output_dir)

    console.print(f"\n[cyan]Phase 3: Nuclei Scanning[/cyan]")

    # Deduplicate live_hosts (file may have duplicates)
    unique_hosts = list(dict.fromkeys(url.strip() for url in live_hosts if url.strip()))

    # Check for resumable progress - calculate remaining based on unique hosts
    resume_info = manager.get_resume_info()
    if resume_info["can_resume"]:
        already_scanned = manager.load_scanned_hosts()
        # Calculate actual remaining by filtering (same as scan_parallel does)
        remaining = sum(1 for url in unique_hosts if manager._normalize_url(url) not in already_scanned)
        console.print(f"  [yellow]Resuming:[/yellow] {resume_info['scanned_hosts']} done, {remaining} remaining")

    # Create Host objects from deduplicated list
    host_objects = []
    for url in unique_hosts:
        hostname = url.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        host_objects.append(Host(hostname=hostname, url=url, ipv4_addresses=[]))

    findings = await manager.scan_batched(hosts=host_objects)
    console.print(f"\n[green]Found {len(findings)} findings[/green]")

    # Save findings
    findings_file = output_dir / "findings.json"
    findings_file.write_text(json.dumps([f.to_dict() for f in findings], indent=2, default=str))

    if findings:
        _display_findings_table(findings)

    # Generate HTML report - load subdomains and hosts from existing files
    subdomains = []
    subdomains_file = output_dir / "subdomains.txt"
    if subdomains_file.exists():
        subdomains = [s for s in subdomains_file.read_text().strip().split("\n") if s]

    # Load hosts from hosts.json if available
    hosts_data = []
    hosts_file = output_dir / "hosts.json"
    if hosts_file.exists():
        try:
            hosts_data = json.loads(hosts_file.read_text())
        except Exception:
            pass

    _generate_html_report(domain, subdomains, hosts_data, findings, output_dir)

    # Run AI triage if requested
    if ai_triage and findings:
        console.print("\n[cyan]Running AI-powered triage...[/cyan]")
        await _run_ai_triage(domain, output_dir, quiet=False)

    console.print(f"\n[blue]Results saved to {output_dir}[/blue]")


async def _run_gau_standalone(
    domain: str,
    output_dir: Path,
    use_ai: bool,
) -> None:
    """Run GAU standalone - same as Phase 2 but independently."""
    from reconductor.modules.recon.gau_wrapper import GauWrapper, FAST_PROVIDERS
    from reconductor.core.exporter import export_gau_findings_html

    if not GauWrapper.is_available():
        console.print("[red]gau tool not found in PATH[/red]")
        console.print("[dim]Install: go install github.com/lc/gau/v2/cmd/gau@latest[/dim]")
        raise typer.Exit(1)

    console.print(f"[cyan]Mining historical URLs for {domain}...[/cyan]")
    console.print("[dim]Sources: OTX, URLScan (with --subs)[/dim]")
    console.print()

    gau = GauWrapper()

    with console.status("[bold green]Fetching URLs from archives..."):
        result = await gau.fetch_urls(
            domain=domain,
            include_subs=True,  # --subs flag
            providers=FAST_PROVIDERS,
            threads=5,
            timeout=90,
        )

    if result.errors:
        for error in result.errors:
            console.print(f"[yellow]Warning: {error}[/yellow]")

    console.print(f"\n[green]Found {result.unique_urls} unique URLs[/green]")
    console.print(f"  Total: {result.total_urls}")
    console.print(f"  With params: {result.urls_with_params}")
    console.print(f"  Categories: {len(result.categorized_urls)}")

    if not result.all_urls:
        console.print("[yellow]No URLs found in archives[/yellow]")
        return

    # AI filtering if requested
    if use_ai and result.unique_urls > 0:
        console.print(f"\n[cyan]Running AI filter on {result.unique_urls} URLs...[/cyan]")

        try:
            from reconductor.modules.ai.gau_filter_agent import GauUrlFilterAgent

            filter_agent = GauUrlFilterAgent(max_urls=100)
            raw_urls = [u.url for u in result.all_urls]

            with console.status("[bold magenta]AI analyzing URLs..."):
                filter_result = await filter_agent.filter_urls(domain, raw_urls)

            method = filter_result.stats.get("method", "unknown")
            console.print(f"[green]AI selected {len(filter_result.filtered_urls)} high-value URLs[/green]")
            console.print(f"  Method: {method}")

            # Store filtered URLs for export
            result.high_value_urls = filter_result.filtered_urls
            result.filter_stats = filter_result.stats

            # Show top URLs
            if filter_result.filtered_urls:
                console.print("\n[bold]Top high-value URLs:[/bold]")
                for url in filter_result.filtered_urls[:10]:
                    console.print(f"  [cyan]•[/cyan] {url[:80]}{'...' if len(url) > 80 else ''}")
                if len(filter_result.filtered_urls) > 10:
                    console.print(f"  [dim]... and {len(filter_result.filtered_urls) - 10} more[/dim]")

        except Exception as e:
            console.print(f"[yellow]AI filter failed: {e}[/yellow]")

    # Export results
    gau_html_path = output_dir / "gau_findings.html"
    export_gau_findings_html(result, gau_html_path, domain)

    console.print(f"\n[blue]Saved: {gau_html_path}[/blue]")


async def _run_gau_phase(
    domain: str,
    hosts: list,
    output_dir: Path,
) -> None:
    """Run GAU historical URL mining on AI-selected targets."""
    from reconductor.modules.ai.gau_target_agent import GauTargetAgent
    from reconductor.modules.recon.gau_wrapper import GauWrapper, GauResult
    from reconductor.core.exporter import export_gau_findings_html

    if not GauWrapper.is_available():
        console.print("[dim]gau not available, skipping historical URL mining[/dim]")
        return

    console.print(f"\n[cyan]Phase 4: GAU Historical URL Mining[/cyan]")

    # Convert hosts to dict format if needed
    host_dicts = []
    for h in hosts:
        if isinstance(h, dict):
            host_dicts.append(h)
        elif hasattr(h, 'to_dict'):
            host_dicts.append(h.to_dict())
        elif hasattr(h, 'hostname'):
            host_dicts.append({'hostname': h.hostname, 'status_code': getattr(h, 'status_code', 200)})

    if not host_dicts:
        console.print("[dim]No hosts for GAU target selection[/dim]")
        return

    # Step 1: AI selects high-value targets
    console.print(f"  [dim]AI selecting targets from {len(host_dicts)} hosts...[/dim]")
    agent = GauTargetAgent(max_targets=30)
    selection = await agent.select_targets(domain, host_dicts)

    if not selection.selected_targets:
        console.print("[dim]No high-value targets identified for GAU[/dim]")
        return

    console.print(f"  [green]Selected {len(selection.selected_targets)} targets[/green]")
    for t in selection.selected_targets[:5]:
        console.print(f"    • {t}")
    if len(selection.selected_targets) > 5:
        console.print(f"    [dim]... and {len(selection.selected_targets) - 5} more[/dim]")

    # Step 2: Run GAU on selected targets
    console.print(f"  [dim]Mining historical URLs...[/dim]")
    gau = GauWrapper()
    combined_result = GauResult(domain=domain)

    for target in selection.selected_targets:
        try:
            result = await gau.fetch_urls(
                domain=target,
                include_subs=False,
                threads=3,
                timeout=60,
                dedupe_params=True,
            )
            combined_result.total_urls += result.total_urls
            combined_result.unique_urls += result.unique_urls
            combined_result.urls_with_params += result.urls_with_params
            combined_result.all_urls.extend(result.all_urls)

            for category, urls in result.categorized_urls.items():
                if category not in combined_result.categorized_urls:
                    combined_result.categorized_urls[category] = []
                combined_result.categorized_urls[category].extend(urls)

        except Exception as e:
            console.print(f"    [dim]Failed: {target} ({str(e)[:30]})[/dim]")

    # Export results
    if combined_result.unique_urls > 0:
        # Validate high-value URLs (check if they still return 200/30x)
        high_value = gau.get_high_value_urls(combined_result, limit=100)
        if high_value:
            console.print(f"  [dim]Validating {len(high_value)} high-value URLs...[/dim]")
            validated = await gau.validate_urls(high_value, max_concurrent=20, timeout=10)
            live_count = sum(1 for u in validated if u.validation_status and u.validation_status < 400)
            console.print(f"  [green]{live_count}/{len(high_value)} high-value URLs still accessible[/green]")

        gau_path = output_dir / "gau_findings.html"
        export_gau_findings_html(combined_result, gau_path, domain)
        console.print(f"  [green]Found {combined_result.unique_urls} URLs ({combined_result.urls_with_params} with params)[/green]")
        console.print(f"  [blue]Saved to {gau_path}[/blue]")
    else:
        console.print("[yellow]No historical URLs found in archives (Wayback/CommonCrawl/OTX/URLScan)[/yellow]")
        console.print("[dim]This is normal for newer or less-crawled domains[/dim]")


def _generate_html_report(
    domain: str,
    subdomains: list,
    hosts: list,
    findings: list,
    output_dir: Path,
) -> None:
    """Generate HTML report from scan data."""
    from reconductor.core.exporter import ReportExporter

    # Count findings by severity
    critical = high = medium = low = info_count = 0
    for f in findings:
        sev = getattr(f, 'severity', None)
        if sev:
            sev_val = sev.value if hasattr(sev, 'value') else str(sev)
        else:
            sev_val = f.get('severity', 'info') if isinstance(f, dict) else 'info'
        sev_val = sev_val.lower()
        if sev_val == 'critical':
            critical += 1
        elif sev_val == 'high':
            high += 1
        elif sev_val == 'medium':
            medium += 1
        elif sev_val == 'low':
            low += 1
        else:
            info_count += 1

    # Convert findings to dicts if they're objects
    findings_data = []
    for f in findings:
        if hasattr(f, 'to_dict'):
            findings_data.append(f.to_dict())
        elif isinstance(f, dict):
            findings_data.append(f)

    # Convert hosts to dicts if they're objects
    hosts_data = []
    for h in hosts:
        if hasattr(h, 'to_dict'):
            hosts_data.append(h.to_dict())
        elif isinstance(h, dict):
            hosts_data.append(h)

    # Build scan result structure for exporter
    scan_result = {
        "domain": domain,
        "scan_id": "continued",
        "subdomains": subdomains,
        "hosts": hosts_data,
        "findings": findings_data,
        "stats": {
            "subdomains_discovered": len(subdomains),
            "hosts_alive": len(hosts_data),
            "findings_total": len(findings_data),
            "findings_critical": critical,
            "findings_high": high,
            "findings_medium": medium,
            "findings_low": low,
            "findings_info": info_count,
        },
        "duration_seconds": 0,
    }

    exporter = ReportExporter(output_dir)
    exporter.export_html_report(scan_result)
    exporter.export_findings_summary(scan_result)
    console.print(f"[green]Generated report.html[/green]")


def _display_findings_table(findings: list) -> None:
    """Display findings in a table."""
    table = Table(title="Findings")
    table.add_column("Severity", style="bold")
    table.add_column("Template", style="cyan")
    table.add_column("Location", style="yellow")

    for finding in findings[:20]:
        severity_color = {
            "critical": "red",
            "high": "orange3",
            "medium": "yellow",
            "low": "blue",
            "info": "white",
        }.get(finding.severity.value, "white")

        # Use matched_at (full URL with path) if available, otherwise target
        location = finding.matched_at or finding.target
        # Truncate long URLs but keep the path visible
        if len(location) > 70:
            location = location[:67] + "..."

        table.add_row(
            f"[{severity_color}]{finding.severity.value.upper()}[/{severity_color}]",
            finding.template_id or "unknown",
            location,
        )

    if len(findings) > 20:
        table.add_row("...", f"and {len(findings) - 20} more", "")

    console.print(table)


@app.command(name="nuclei-scan")
def nuclei_scan_domain(
    domain: str = typer.Argument(..., help="Domain from previous scan"),
    severity: str = typer.Option(
        "critical,high,medium",
        "--severity", "-s",
        help="Severity levels",
    ),
    rate_limit: int = typer.Option(
        150, "--rate-limit", "-r",
        help="Requests per second",
    ),
) -> None:
    """Run Nuclei scan on a previously enumerated domain."""
    output_dir = Path(f"output/{domain}")

    if not output_dir.exists():
        console.print(f"[red]No scan found for {domain}[/red]")
        console.print("[dim]Run 'reconductor list-scans' to see available domains[/dim]")
        raise typer.Exit(1)

    live_hosts_file = output_dir / "live_hosts.txt"
    if not live_hosts_file.exists():
        console.print(f"[red]No live hosts file found for {domain}[/red]")
        console.print("[dim]Run 'reconductor continue {domain}' to probe subdomains first[/dim]")
        raise typer.Exit(1)

    targets = live_hosts_file.read_text().strip().split("\n")
    targets = [t for t in targets if t.strip()]

    if not targets:
        console.print(f"[yellow]No live hosts found for {domain}[/yellow]")
        raise typer.Exit(0)

    console.print(f"[cyan]Running Nuclei on {len(targets)} live hosts from {domain}[/cyan]")
    asyncio.run(_nuclei_scan_domain(domain, targets, severity, rate_limit, output_dir))


async def _nuclei_scan_domain(
    domain: str,
    targets: list[str],
    severity: str,
    rate_limit: int,
    output_dir: Path,
) -> None:
    """Run Nuclei scan on domain's live hosts."""
    from reconductor.modules.scanning.nuclei_manager import NucleiManager
    from reconductor.models.host import Host

    manager = NucleiManager()
    severity_list = [s.strip() for s in severity.split(",")]

    with console.status(f"[bold green]Scanning {len(targets)} targets..."):
        findings = await manager.scan(
            targets,
            severity=severity_list,
            rate_limit=rate_limit,
        )

    console.print(f"[green]Found {len(findings)} findings[/green]")

    # Display results
    if findings:
        table = Table(title="Findings")
        table.add_column("Severity", style="bold")
        table.add_column("Template", style="cyan")
        table.add_column("Target", style="yellow")

        for finding in findings[:20]:
            severity_color = {
                "critical": "red",
                "high": "orange3",
                "medium": "yellow",
                "low": "blue",
                "info": "white",
            }.get(finding.severity.value, "white")

            table.add_row(
                f"[{severity_color}]{finding.severity.value.upper()}[/{severity_color}]",
                finding.template_id or "unknown",
                finding.target[:60],
            )

        if len(findings) > 20:
            table.add_row("...", f"and {len(findings) - 20} more", "")

        console.print(table)

        # Save findings
        import json
        findings_file = output_dir / "findings.json"
        findings_data = [f.to_dict() for f in findings]
        findings_file.write_text(json.dumps(findings_data, indent=2, default=str))
        console.print(f"\n[blue]Findings saved to {findings_file}[/blue]")


@app.command()
def enumerate(
    domain: str = typer.Argument(..., help="Target domain"),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output file",
    ),
    all_sources: bool = typer.Option(
        True, "--all/--no-all",
        help="Use all enumeration sources",
    ),
) -> None:
    """Run subdomain enumeration only."""
    console.print(f"[cyan]Enumerating subdomains for {domain}...[/cyan]")
    asyncio.run(_enumerate(domain, output, all_sources))


async def _enumerate(
    domain: str,
    output: Optional[Path],
    all_sources: bool,
) -> None:
    """Run subdomain enumeration."""
    from reconductor.modules.subdomain.passive import PassiveEnumerationPipeline

    pipeline = PassiveEnumerationPipeline()

    with console.status("[bold green]Enumerating subdomains..."):
        subdomains = await pipeline.enumerate(domain)

    console.print(f"[green]Found {len(subdomains)} subdomains[/green]")

    for sub in subdomains[:20]:
        console.print(f"  {sub.name}")

    if len(subdomains) > 20:
        console.print(f"  ... and {len(subdomains) - 20} more")

    if output:
        output.write_text("\n".join(s.name for s in subdomains))
        console.print(f"[blue]Saved to {output}[/blue]")


@app.command()
def probe(
    targets_file: Path = typer.Argument(..., help="File containing targets"),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output file",
    ),
    threads: int = typer.Option(
        50, "--threads", "-t",
        help="Number of threads",
    ),
) -> None:
    """Probe targets for HTTP availability."""
    if not targets_file.exists():
        console.print(f"[red]File not found: {targets_file}[/red]")
        raise typer.Exit(1)

    targets = targets_file.read_text().strip().split("\n")
    console.print(f"[cyan]Probing {len(targets)} targets...[/cyan]")
    asyncio.run(_probe(targets, output, threads))


async def _probe(
    targets: list[str],
    output: Optional[Path],
    threads: int,
) -> None:
    """Run HTTP probing."""
    from reconductor.modules.validation.http_probe import HttpProber

    prober = HttpProber()

    with console.status("[bold green]Probing targets..."):
        hosts = await prober.probe(targets, threads=threads)

    alive = [h for h in hosts if h.is_alive]
    console.print(f"[green]Found {len(alive)} live hosts[/green]")

    table = Table(title="Live Hosts")
    table.add_column("Host", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Title", style="yellow")

    for host in alive[:20]:
        table.add_row(
            host.hostname,
            str(host.status_code),
            (host.title or "")[:50],
        )

    console.print(table)


@app.command()
def nuclei(
    targets_file: Path = typer.Argument(..., help="File containing targets"),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output file",
    ),
    severity: str = typer.Option(
        "critical,high,medium",
        "--severity", "-s",
        help="Severity levels",
    ),
    rate_limit: int = typer.Option(
        150, "--rate-limit", "-r",
        help="Requests per second",
    ),
) -> None:
    """Run Nuclei vulnerability scan."""
    if not targets_file.exists():
        console.print(f"[red]File not found: {targets_file}[/red]")
        raise typer.Exit(1)

    targets = targets_file.read_text().strip().split("\n")
    console.print(f"[cyan]Scanning {len(targets)} targets with Nuclei...[/cyan]")
    asyncio.run(_nuclei_scan(targets, output, severity, rate_limit))


async def _nuclei_scan(
    targets: list[str],
    output: Optional[Path],
    severity: str,
    rate_limit: int,
) -> None:
    """Run Nuclei scan."""
    from reconductor.modules.scanning.nuclei_manager import NucleiManager

    manager = NucleiManager()
    severity_list = [s.strip() for s in severity.split(",")]

    with console.status("[bold green]Running Nuclei scan..."):
        findings = await manager.scan(
            targets,
            severity=severity_list,
            rate_limit=rate_limit,
        )

    console.print(f"[green]Found {len(findings)} findings[/green]")

    table = Table(title="Findings")
    table.add_column("Severity", style="bold")
    table.add_column("Template", style="cyan")
    table.add_column("Target", style="yellow")

    for finding in findings[:20]:
        severity_color = {
            "critical": "red",
            "high": "orange3",
            "medium": "yellow",
            "low": "blue",
            "info": "white",
        }.get(finding.severity.value, "white")

        table.add_row(
            f"[{severity_color}]{finding.severity.value.upper()}[/{severity_color}]",
            finding.template_id or "unknown",
            finding.target[:50],
        )

    console.print(table)


@app.command()
def check_tools() -> None:
    """Check availability of required tools."""
    from reconductor.utils.executor import get_executor

    tools = [
        "subfinder",
        "puredns",
        "httpx",
        "dnsx",
        "nuclei",
        "naabu",
        "alterx",
        "claude",  # Claude Code CLI
    ]

    executor = get_executor()

    table = Table(title="Tool Availability")
    table.add_column("Tool", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Path")

    for tool in tools:
        available = executor.check_tool_available(tool)
        path = executor.get_tool_path(tool) or ""

        if available:
            status = "[green]✓ OK[/green]"
        else:
            status = "[red]✗ MISSING[/red]"

        table.add_row(tool, status, path)

    console.print(table)


@app.command()
def ai_wordlist(
    domain: str = typer.Argument(..., help="Target domain"),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output file",
    ),
    count: int = typer.Option(
        200, "--count", "-n",
        help="Number of words to generate",
    ),
) -> None:
    """Generate AI-powered wordlist for a domain."""
    console.print(f"[cyan]Generating intelligent wordlist for {domain}...[/cyan]")
    asyncio.run(_ai_wordlist(domain, output, count))


async def _ai_wordlist(
    domain: str,
    output: Optional[Path],
    count: int,
) -> None:
    """Generate AI wordlist."""
    from reconductor.modules.ai.wordlist_agent import WordlistGeneratorAgent

    agent = WordlistGeneratorAgent()

    with console.status("[bold magenta]Claude is analyzing domain and generating wordlist..."):
        result = await agent.generate(domain, count=count)

    console.print(f"\n[green]Generated {len(result.wordlist)} words[/green]")
    llm_count = result.stats.get("llm_generated_valid", 0)
    intel_count = result.stats.get("from_intelligence", 0)
    base_count = result.stats.get("base_wordlist_count", 0)
    console.print(f"  [dim]From LLM:[/dim] [magenta]{llm_count}[/magenta]")
    console.print(f"  [dim]From Intelligence:[/dim] [cyan]{intel_count}[/cyan]")
    console.print(f"  [dim]From Base:[/dim] [dim]{base_count}[/dim]")

    console.print("\n[bold]Sample words:[/bold]")
    for word in result.wordlist[:20]:
        console.print(f"  {word}")
    if len(result.wordlist) > 20:
        console.print(f"  [dim]... and {len(result.wordlist) - 20} more[/dim]")

    if output:
        output.write_text("\n".join(result.wordlist))
        console.print(f"\n[blue]Saved to {output}[/blue]")


@app.command(name="origin-ips")
def origin_ips(
    domain: str = typer.Argument(..., help="Target domain"),
    target_url: Optional[str] = typer.Option(
        None, "--url", "-u",
        help="Target URL for baseline response and favicon hash",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Output file for results (JSON)",
    ),
    no_validate: bool = typer.Option(
        False, "--no-validate",
        help="Skip HTTP validation of candidates",
    ),
    no_checkhost: bool = typer.Option(
        False, "--no-checkhost",
        help="Skip check-host.net CDN validation",
    ),
    scan: bool = typer.Option(
        False, "--scan", "-s",
        help="Run aggressive nuclei scan against discovered origins (bypasses WAF)",
    ),
    scan_rate: int = typer.Option(
        150, "--scan-rate",
        help="Rate limit for nuclei scan (requests/sec)",
    ),
) -> None:
    """
    Find origin IPs behind CDN/WAF.

    Comprehensive origin IP discovery using multiple techniques:

    1. DNS-based: SPF records, MX records, AAAA records
    2. Subdomain analysis: Find non-CDN IPs from subdomains
    3. Shodan: SSL Certificate CN, Favicon hash matching
    4. SecurityTrails: Historical DNS records (pre-CDN IPs)
    5. check-host.net: Additional CDN validation (free)
    6. HTTP validation: Confirm by comparing responses
    7. Nuclei scan: Aggressive scanning bypassing WAF (--scan)

    API keys can be configured via:
      - Environment: SHODAN_API_KEY, SECURITYTRAILS_API_KEY
      - Config file: reconductor config set-key <name>

    Examples:

      reconductor origin-ips example.com

      reconductor origin-ips example.com --url https://example.com

      reconductor origin-ips example.com --scan

      reconductor origin-ips example.com --scan --scan-rate 200
    """
    asyncio.run(_origin_ips(domain, target_url, output, not no_validate, not no_checkhost, scan, scan_rate))


async def _origin_ips(
    domain: str,
    target_url: Optional[str],
    output: Optional[Path],
    validate: bool,
    use_checkhost: bool = True,
    run_scan: bool = False,
    scan_rate: int = 150,
) -> None:
    """Find origin IPs using comprehensive discovery."""
    import json

    try:
        from reconductor.modules.recon.origin_discovery import OriginDiscovery
        from reconductor.core.config import get_api_keys
    except ImportError as e:
        console.print(f"[red]Error importing origin discovery module: {e}[/red]")
        raise typer.Exit(1)

    # Load API keys from config/environment
    api_keys = get_api_keys()
    shodan_key = api_keys.get_shodan()
    securitytrails_key = api_keys.get_securitytrails()

    console.print(f"[cyan]Discovering origin IPs for {domain}...[/cyan]")
    methods = ["DNS (SPF/MX/AAAA)", "Subdomain analysis"]
    if shodan_key:
        methods.append("Shodan (SSL/Favicon)")
    if securitytrails_key:
        methods.append("SecurityTrails (Historical DNS)")
    if use_checkhost:
        methods.append("check-host.net (CDN validation)")
    if validate:
        methods.append("HTTP validation")
    console.print(f"[dim]Methods: {', '.join(methods)}[/dim]")

    # Show API key status
    if not shodan_key and not securitytrails_key:
        console.print("[dim]Tip: Configure API keys for better results: reconductor config set-key <name>[/dim]")
    console.print()

    # Set target URL if not provided
    if not target_url:
        target_url = f"https://{domain}"

    discovery = OriginDiscovery(
        shodan_api_key=shodan_key,
        securitytrails_api_key=securitytrails_key,
        validate_candidates=validate,
        max_validation_candidates=10,
        use_checkhost=use_checkhost,
    )

    with console.status("[bold green]Running discovery..."):
        result = await discovery.discover(
            domain=domain,
            target_url=target_url,
        )

    # Check CDN status
    if not result.is_behind_cdn:
        console.print(f"[yellow]{domain} is not behind a CDN[/yellow]")
        console.print(f"[dim]Resolved IPs: {', '.join(result.cdn_ips)}[/dim]")
        raise typer.Exit(0)

    console.print(f"[bold]CDN detected:[/bold] {result.cdn_provider or 'Unknown'}")
    console.print(f"[dim]CDN IPs: {', '.join(result.cdn_ips[:3])}{'...' if len(result.cdn_ips) > 3 else ''}[/dim]")
    console.print()

    # Display confirmed origins
    if result.confirmed_origins:
        console.print(Panel.fit(
            f"[bold green]CONFIRMED ORIGIN IPs: {len(result.confirmed_origins)}[/bold green]",
            border_style="green",
        ))

        table = Table(border_style="green")
        table.add_column("IP Address", style="bold white")
        table.add_column("Score", style="green")
        table.add_column("Sources", style="cyan")
        table.add_column("Hostnames", style="dim")

        for origin in result.confirmed_origins:
            score_pct = f"{origin.validation_score * 100:.0f}%"
            sources = ", ".join(origin.sources[:3])
            if len(origin.sources) > 3:
                sources += f" +{len(origin.sources) - 3}"
            hostnames = ", ".join(origin.hostnames[:2]) if origin.hostnames else "-"

            table.add_row(origin.ip, score_pct, sources, hostnames)

        console.print(table)
        console.print()

    # Display candidates
    if result.candidates:
        console.print(f"[bold yellow]Unconfirmed candidates: {len(result.candidates)}[/bold yellow]")

        table = Table(border_style="yellow")
        table.add_column("IP Address", style="white")
        table.add_column("Confidence", style="yellow")
        table.add_column("Sources", style="cyan")
        table.add_column("Hostnames", style="dim")

        for candidate in result.candidates[:10]:
            conf_style = {"high": "green", "medium": "yellow", "low": "dim"}.get(candidate.confidence_level, "dim")
            sources = ", ".join(candidate.sources[:3])
            hostnames = ", ".join(candidate.hostnames[:2]) if candidate.hostnames else "-"

            table.add_row(
                candidate.ip,
                f"[{conf_style}]{candidate.confidence_level.upper()}[/{conf_style}]",
                sources,
                hostnames,
            )

        if len(result.candidates) > 10:
            console.print(f"[dim]... and {len(result.candidates) - 10} more candidates[/dim]")

        console.print(table)
        console.print()

    if not result.confirmed_origins and not result.candidates:
        console.print("[yellow]No origin IPs found[/yellow]")
        console.print("\n[dim]Tips:[/dim]")
        console.print("  - Set SHODAN_API_KEY for additional techniques")
        console.print("  - Try providing --url for baseline comparison")
        console.print("  - Run a full scan first to enumerate subdomains")
        raise typer.Exit(0)

    # Show reverse DNS and co-hosted domains for top candidates
    all_candidates = result.confirmed_origins + result.candidates
    candidates_with_data = [
        c for c in all_candidates[:5]
        if c.reverse_dns_hostnames or c.co_hosted_domains or c.open_ports
    ]

    if candidates_with_data:
        console.print("[bold]Shodan Reverse IP Lookup:[/bold]")
        for candidate in candidates_with_data:
            console.print(f"\n  [cyan]{candidate.ip}[/cyan]")

            if candidate.open_ports:
                ports_str = ", ".join(str(p) for p in candidate.open_ports[:15])
                if len(candidate.open_ports) > 15:
                    ports_str += f" (+{len(candidate.open_ports) - 15} more)"
                console.print(f"    [dim]Open ports:[/dim] {ports_str}")

            if candidate.reverse_dns_hostnames:
                hostnames_str = ", ".join(candidate.reverse_dns_hostnames[:5])
                if len(candidate.reverse_dns_hostnames) > 5:
                    hostnames_str += f" (+{len(candidate.reverse_dns_hostnames) - 5} more)"
                console.print(f"    [dim]Reverse DNS:[/dim] {hostnames_str}")

            if candidate.co_hosted_domains:
                console.print(f"    [yellow]Co-hosted domains ({len(candidate.co_hosted_domains)}):[/yellow]")
                for domain_name in candidate.co_hosted_domains[:10]:
                    console.print(f"      - {domain_name}")
                if len(candidate.co_hosted_domains) > 10:
                    console.print(f"      [dim]... and {len(candidate.co_hosted_domains) - 10} more[/dim]")

        console.print()

    # Show verification commands
    console.print("[bold]Verification commands:[/bold]")
    best_ip = result.confirmed_origins[0].ip if result.confirmed_origins else result.candidates[0].ip
    console.print(f"  [cyan]curl -I -H 'Host: {domain}' https://{best_ip} -k[/cyan]")
    console.print(f"  [cyan]curl -H 'Host: {domain}' https://{best_ip} -k | head -50[/cyan]")

    # Run aggressive nuclei scan against origins if requested
    scan_result = None
    if run_scan:
        all_ips = [c.ip for c in result.confirmed_origins + result.candidates]
        if all_ips:
            console.print()
            console.print(Panel.fit(
                f"[bold yellow]ORIGIN SCANNING (WAF BYPASS)[/bold yellow]\n"
                f"Scanning {len(all_ips)} origin IPs with aggressive nuclei templates",
                border_style="yellow",
            ))

            try:
                from reconductor.modules.scanning.origin_scanner import OriginScanner

                scanner = OriginScanner(
                    domain=domain,
                    rate_limit=scan_rate,
                )

                with console.status("[bold green]Running nuclei scan against origin IPs..."):
                    scan_result = await scanner.scan(all_ips)

                # Display version info
                if scan_result.version_info:
                    console.print("\n[bold]Detected Versions (hidden by CDN):[/bold]")
                    displayed = set()
                    for key, value in scan_result.version_info.items():
                        if value not in displayed:
                            console.print(f"  [cyan]{value}[/cyan]")
                            displayed.add(value)

                # Display findings
                if scan_result.findings:
                    console.print(f"\n[bold red]Vulnerabilities Found: {len(scan_result.findings)}[/bold red]")

                    # Group by severity
                    by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
                    for f in scan_result.findings:
                        by_severity.get(f.severity, by_severity["info"]).append(f)

                    for sev in ["critical", "high", "medium", "low", "info"]:
                        findings = by_severity[sev]
                        if findings:
                            sev_colors = {
                                "critical": "red bold",
                                "high": "red",
                                "medium": "yellow",
                                "low": "blue",
                                "info": "dim",
                            }
                            console.print(f"\n  [{sev_colors[sev]}]{sev.upper()} ({len(findings)}):[/{sev_colors[sev]}]")
                            for f in findings[:10]:
                                console.print(f"    - {f.name}")
                                console.print(f"      [dim]{f.matched_at}[/dim]")
                            if len(findings) > 10:
                                console.print(f"    [dim]... and {len(findings) - 10} more[/dim]")
                else:
                    console.print("\n[green]No vulnerabilities found in origin scan.[/green]")

                console.print(f"\n[dim]Scan stats: {scan_result.scan_stats}[/dim]")

            except ImportError as e:
                console.print(f"[red]Origin scanner not available: {e}[/red]")
            except Exception as e:
                console.print(f"[red]Origin scan failed: {e}[/red]")

    # Save to file if requested
    if output:
        output_data = result.to_dict()
        if scan_result:
            output_data["scan_result"] = scan_result.to_dict()
        output.write_text(json.dumps(output_data, indent=2))
        console.print(f"\n[blue]Results saved to {output}[/blue]")


# =============================================================================
# CONFIG COMMANDS
# =============================================================================

@app.command(name="config")
def config_cmd(
    action: str = typer.Argument(..., help="Action: set-key, delete-key, list-keys, show, import"),
    key_name: Optional[str] = typer.Argument(None, help="API key name (shodan, securitytrails, censys_id, censys_secret)"),
) -> None:
    """
    Manage API keys and configuration.

    Actions:
      set-key <name>     Set an API key (prompts for value securely)
      delete-key <name>  Delete an API key
      list-keys          List configured API keys (shows which are set)
      show               Show config file location and status
      import             Import API keys from native tool configs (e.g., shodan init)

    Examples:
      reconductor config set-key shodan
      reconductor config set-key securitytrails
      reconductor config list-keys
      reconductor config import
      reconductor config delete-key shodan
    """
    from getpass import getpass
    from reconductor.core.config import (
        CONFIG_FILE,
        CONFIG_DIR,
        save_api_key,
        delete_api_key,
        list_api_keys,
        get_api_keys,
    )

    if action == "set-key":
        if not key_name:
            console.print("[red]Error: Key name required[/red]")
            console.print("Valid keys: shodan, securitytrails, censys_id, censys_secret")
            raise typer.Exit(1)

        valid_keys = {"shodan", "securitytrails", "censys_id", "censys_secret"}
        if key_name not in valid_keys:
            console.print(f"[red]Invalid key name: {key_name}[/red]")
            console.print(f"Valid keys: {', '.join(valid_keys)}")
            raise typer.Exit(1)

        # Prompt for key value securely (hidden input)
        console.print(f"[cyan]Enter API key for {key_name}:[/cyan]")
        key_value = getpass(prompt="  > ")

        if not key_value.strip():
            console.print("[red]Error: API key cannot be empty[/red]")
            raise typer.Exit(1)

        try:
            save_api_key(key_name, key_value.strip())
            console.print(f"[green]API key '{key_name}' saved successfully[/green]")
            console.print(f"[dim]Config file: {CONFIG_FILE}[/dim]")
        except Exception as e:
            console.print(f"[red]Error saving API key: {e}[/red]")
            raise typer.Exit(1)

    elif action == "delete-key":
        if not key_name:
            console.print("[red]Error: Key name required[/red]")
            raise typer.Exit(1)

        if delete_api_key(key_name):
            console.print(f"[green]API key '{key_name}' deleted[/green]")
        else:
            console.print(f"[yellow]API key '{key_name}' not found in config[/yellow]")

    elif action == "list-keys":
        keys_status = list_api_keys()
        keys_config = get_api_keys()

        console.print("[bold]API Keys Status:[/bold]")
        console.print()

        table = Table(border_style="dim")
        table.add_column("Service", style="cyan")
        table.add_column("Config File", style="white")
        table.add_column("Environment", style="white")
        table.add_column("Status", style="white")

        # Check both config file and environment
        import os
        env_keys = {
            "shodan": bool(os.environ.get("SHODAN_API_KEY")),
            "securitytrails": bool(os.environ.get("SECURITYTRAILS_API_KEY")),
            "censys": bool(os.environ.get("CENSYS_API_ID")),
        }

        for key, is_set in keys_status.items():
            in_env = env_keys.get(key, False)
            in_config = is_set and not in_env  # Simplified check

            config_status = "[green]Set[/green]" if is_set else "[dim]Not set[/dim]"
            env_status = "[green]Set[/green]" if in_env else "[dim]Not set[/dim]"

            if is_set:
                status = "[green]Ready[/green]"
            else:
                status = "[yellow]Missing[/yellow]"

            table.add_row(key.capitalize(), config_status, env_status, status)

        console.print(table)
        console.print()
        console.print(f"[dim]Config file: {CONFIG_FILE}[/dim]")
        console.print(f"[dim]Environment variables override config file values[/dim]")

    elif action == "show":
        console.print("[bold]Configuration:[/bold]")
        console.print()
        console.print(f"  Config directory: {CONFIG_DIR}")
        console.print(f"  Config file: {CONFIG_FILE}")
        console.print(f"  File exists: {CONFIG_FILE.exists()}")

        if CONFIG_FILE.exists():
            import stat
            mode = CONFIG_FILE.stat().st_mode
            perms = stat.filemode(mode)
            console.print(f"  Permissions: {perms}")

            # Show config content (without sensitive values)
            import yaml
            try:
                with open(CONFIG_FILE, "r") as f:
                    config = yaml.safe_load(f) or {}
                api_keys = config.get("api_keys", {})
                if api_keys:
                    console.print()
                    console.print("  [cyan]Configured keys:[/cyan]")
                    for key in api_keys:
                        console.print(f"    - {key}: [dim]***[/dim]")
            except Exception as e:
                console.print(f"  [red]Error reading config: {e}[/red]")
    elif action == "import":
        # Import API keys from native tool configurations
        console.print("[bold]Importing API keys from native tool configs...[/bold]")
        console.print()

        imported = []
        skipped = []

        # Native tool config locations
        native_configs = {
            "shodan": [
                Path.home() / ".config" / "shodan" / "api_key",
                Path.home() / ".shodan" / "api_key",
            ],
        }

        for key_name, paths in native_configs.items():
            for path in paths:
                if path.exists():
                    try:
                        key_value = path.read_text().strip()
                        if key_value:
                            # Check if already in config
                            existing_keys = get_api_keys()
                            existing_value = None
                            if key_name == "shodan":
                                existing_value = existing_keys.get_shodan()

                            if existing_value == key_value:
                                skipped.append((key_name, str(path), "already configured"))
                            else:
                                save_api_key(key_name, key_value)
                                imported.append((key_name, str(path)))
                            break
                    except Exception as e:
                        console.print(f"  [yellow]Warning: Could not read {path}: {e}[/yellow]")

        if imported:
            console.print("[green]Imported keys:[/green]")
            for key_name, source_path in imported:
                console.print(f"  [cyan]{key_name}[/cyan] from {source_path}")

        if skipped:
            console.print()
            console.print("[dim]Skipped (already configured):[/dim]")
            for key_name, source_path, reason in skipped:
                console.print(f"  [dim]{key_name} from {source_path}[/dim]")

        if not imported and not skipped:
            console.print("[yellow]No native tool configs found to import.[/yellow]")
            console.print()
            console.print("[dim]Checked locations:[/dim]")
            for key_name, paths in native_configs.items():
                for path in paths:
                    console.print(f"  [dim]{key_name}: {path}[/dim]")
        else:
            console.print()
            console.print(f"[dim]Config saved to: {CONFIG_FILE}[/dim]")

    else:
        console.print(f"[red]Unknown action: {action}[/red]")
        console.print("Valid actions: set-key, delete-key, list-keys, show, import")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
