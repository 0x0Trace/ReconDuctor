#!/usr/bin/env python3
"""
=============================================================================
 RECON ORCHESTRATOR - n8n Workflow Controller
=============================================================================
 Orchestrates the multi-phase reconnaissance automation pipeline:
   - Phase 1: Subdomain Enumeration (subfinder, shodan SSL)
   - Phase 2: Live Host Validation (httpx, dnsx)
   - Phase 3: Vulnerability Scanning (nuclei parallel workers)

 Webhook Endpoints:
   - Phase 1: POST /webhook/recon-phase1  -> triggers Phase 2 automatically
   - Phase 3: POST /webhook/recon-phase3-parallel (Parent-Child workers)

 Output Files Location: /tmp/recon/{domain}/
=============================================================================
"""

import requests
import time
import os
import sys
import json
from datetime import datetime

# ============================================================================
# CONFIGURATION
# ============================================================================

N8N_BASE_URL = "http://localhost:5678"
WEBHOOK_PHASE1 = f"{N8N_BASE_URL}/webhook/recon-phase1"
WEBHOOK_PHASE3 = f"{N8N_BASE_URL}/webhook/recon-phase3-parallel"
RECON_OUTPUT_DIR = "/tmp/recon"

# Polling settings for waiting on results
POLL_INTERVAL = 10  # seconds between checks
PHASE2_TIMEOUT = 600  # 10 minutes max for Phase 2 (large domains)
PHASE3_TIMEOUT = 900  # 15 minutes for parallel scan (much faster than sequential)

# ANSI Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def print_banner():
    """Print the tool banner."""
    banner = rf"""
{Colors.CYAN}{Colors.BOLD}
  =======================================================================
  ||      ____                        ____             __              ||
  ||     / __ \___  _________  ____  / __ \__  _______/ /_____  _____  ||
  ||    / /_/ / _ \/ ___/ __ \/ __ \/ / / / / / / ___/ __/ __ \/ ___/  ||
  ||   / _, _/  __/ /__/ /_/ / / / / /_/ / /_/ / /__/ /_/ /_/ / /      ||
  ||  /_/ |_|\___/\___/\____/_/ /_/_____/\____/\___/\__/\____/_/       ||
  ||                                                                   ||
  ||            n8n Workflow Automation Pipeline Controller            ||
  ||                    [v2.0 - Parallel Workers]                      ||
  =======================================================================
{Colors.END}"""
    print(banner)


def print_step(step_num, message):
    """Print a step indicator."""
    print(f"\n{Colors.BLUE}{Colors.BOLD}[Step {step_num}]{Colors.END} {message}")


def print_success(message):
    """Print a success message."""
    print(f"{Colors.GREEN}[+]{Colors.END} {message}")


def print_error(message):
    """Print an error message."""
    print(f"{Colors.RED}[-] ERROR:{Colors.END} {message}")


def print_warning(message):
    """Print a warning message."""
    print(f"{Colors.YELLOW}[!]{Colors.END} {message}")


def print_info(message):
    """Print an info message."""
    print(f"{Colors.CYAN}[i]{Colors.END} {message}")


def validate_domain(domain):
    """
    Basic domain validation.
    Returns cleaned domain or None if invalid.
    """
    domain = domain.lower().strip()

    # Remove protocol if present
    if domain.startswith("http://"):
        domain = domain[7:]
    elif domain.startswith("https://"):
        domain = domain[8:]

    # Remove trailing slash and path
    domain = domain.split("/")[0]

    # Basic validation
    if not domain or "." not in domain:
        return None

    # Check for invalid characters
    valid_chars = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    if not all(c in valid_chars for c in domain):
        return None

    return domain


def check_n8n_health():
    """Check if n8n instance is running and accessible."""
    try:
        # Try the health endpoint first
        response = requests.get(f"{N8N_BASE_URL}/healthz", timeout=5)
        if response.status_code == 200:
            return True
    except Exception:
        pass

    # Fallback: try base endpoint (404/405 is still "alive")
    try:
        response = requests.get(N8N_BASE_URL, timeout=5)
        return response.status_code in [200, 404, 405]
    except requests.exceptions.ConnectionError:
        return False
    except Exception:
        return False


def trigger_phase1(domain):
    """
    Trigger Phase 1 webhook (Subdomain Enumeration).
    Phase 1 automatically chains to Phase 2.

    Returns: (success: bool, response_data: dict or error_message: str)
    """
    payload = {"domain": domain}
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(
            WEBHOOK_PHASE1,
            json=payload,
            headers=headers,
            timeout=30
        )

        if response.status_code == 200:
            try:
                data = response.json()
                return True, data
            except json.JSONDecodeError:
                return True, {"status": "success", "message": response.text}
        else:
            return False, f"HTTP {response.status_code}: {response.text}"

    except requests.exceptions.ConnectionError:
        return False, "Connection refused - is n8n running?"
    except requests.exceptions.Timeout:
        return False, "Request timed out"
    except Exception as e:
        return False, str(e)


def trigger_phase3(domain):
    """
    Trigger Phase 3 Parallel webhook (Vulnerability Scanning with Workers).
    Uses Parent-Child architecture - 6-9x faster than sequential.

    Returns: (success: bool, response_data: dict or error_message: str)
    """
    payload = {"domain": domain}
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(
            WEBHOOK_PHASE3,
            json=payload,
            headers=headers,
            timeout=30
        )

        if response.status_code == 200:
            try:
                data = response.json()
                return True, data
            except json.JSONDecodeError:
                return True, {"status": "success", "message": response.text}
        else:
            return False, f"HTTP {response.status_code}: {response.text}"

    except requests.exceptions.ConnectionError:
        return False, "Connection refused - is n8n running?"
    except requests.exceptions.Timeout:
        return False, "Request timed out"
    except Exception as e:
        return False, str(e)


def wait_for_phase2_completion(domain, timeout=PHASE2_TIMEOUT):
    """
    Wait for Phase 2 to complete by checking for output files.

    Returns: (success: bool, file_paths: dict or error_message: str)
    """
    output_dir = f"{RECON_OUTPUT_DIR}/{domain}"
    phase2_html = f"{output_dir}/phase2_report.html"
    phase2_json = f"{output_dir}/phase2_data.json"
    phase2_summary = f"{output_dir}/phase2_summary.txt"

    start_time = time.time()
    last_check_size = 0
    stable_count = 0

    print_info("Waiting for Phase 2 completion...")
    print_info("Phase 1 -> Phase 2 chain is running in background...")

    while time.time() - start_time < timeout:
        if os.path.exists(output_dir):
            if os.path.exists(phase2_html):
                current_size = os.path.getsize(phase2_html)

                if current_size > 0 and current_size == last_check_size:
                    stable_count += 1
                    if stable_count >= 2:
                        if os.path.exists(phase2_json):
                            return True, {
                                "html": phase2_html,
                                "json": phase2_json,
                                "summary": phase2_summary if os.path.exists(phase2_summary) else None,
                                "directory": output_dir
                            }
                else:
                    stable_count = 0
                    last_check_size = current_size

        elapsed = int(time.time() - start_time)
        print(f"\r{Colors.CYAN}  [..] Running: {elapsed}s{Colors.END}", end="", flush=True)
        time.sleep(POLL_INTERVAL)

    print()
    return False, f"Timeout after {timeout}s - Phase 2 may still be running"


def wait_for_phase3_completion(domain, timeout=PHASE3_TIMEOUT):
    """
    Wait for Phase 3 to complete by checking for output files.

    Returns: (success: bool, file_paths: dict or error_message: str)
    """
    output_dir = f"{RECON_OUTPUT_DIR}/{domain}"
    phase3_html = f"{output_dir}/phase3_report.html"
    phase3_json = f"{output_dir}/phase3_data.json"
    phase3_summary = f"{output_dir}/phase3_summary.txt"

    start_time = time.time()
    last_check_size = 0
    stable_count = 0

    print_info("Waiting for Phase 3 completion...")
    print_info("Parallel nuclei workers scanning...")

    while time.time() - start_time < timeout:
        if os.path.exists(phase3_html):
            current_size = os.path.getsize(phase3_html)

            if current_size > 0 and current_size == last_check_size:
                stable_count += 1
                if stable_count >= 2:
                    if os.path.exists(phase3_json):
                        return True, {
                            "html": phase3_html,
                            "json": phase3_json,
                            "summary": phase3_summary if os.path.exists(phase3_summary) else None,
                            "directory": output_dir
                        }
            else:
                stable_count = 0
                last_check_size = current_size

        elapsed = int(time.time() - start_time)
        print(f"\r{Colors.CYAN}  [..] Running: {elapsed}s{Colors.END}", end="", flush=True)
        time.sleep(POLL_INTERVAL)

    print()
    return False, f"Timeout after {timeout}s - Phase 3 may still be running"


def print_results_summary(domain, phase2_files, phase3_files=None):
    """Print a summary of generated files."""

    print(f"\n{Colors.GREEN}{Colors.BOLD}")
    print("=" * 70)
    print("                     RECONNAISSANCE COMPLETE")
    print("=" * 70)
    print(f"{Colors.END}")

    print(f"{Colors.CYAN}Target Domain:{Colors.END} {domain}")
    print(f"{Colors.CYAN}Output Directory:{Colors.END} {RECON_OUTPUT_DIR}/{domain}/")
    print()

    # Phase 2 files
    print(f"{Colors.YELLOW}{Colors.BOLD}Phase 2 - Live Host Validation:{Colors.END}")
    if phase2_files:
        print(f"  - HTML Report:  {phase2_files.get('html', 'N/A')}")
        print(f"  - JSON Data:    {phase2_files.get('json', 'N/A')}")
        if phase2_files.get('summary'):
            print(f"  - Summary:      {phase2_files.get('summary')}")
    else:
        print(f"  {Colors.RED}Files not found{Colors.END}")

    # Phase 3 files (if nuclei was run)
    if phase3_files:
        print()
        print(f"{Colors.YELLOW}{Colors.BOLD}Phase 3 - Vulnerability Scanning (Parallel):{Colors.END}")
        print(f"  - HTML Report:  {phase3_files.get('html', 'N/A')}")
        print(f"  - JSON Data:    {phase3_files.get('json', 'N/A')}")
        if phase3_files.get('summary'):
            print(f"  - Summary:      {phase3_files.get('summary')}")

    print()
    print(f"{Colors.CYAN}View HTML reports in browser:{Colors.END}")
    if phase2_files and phase2_files.get('html'):
        print(f"  firefox {phase2_files.get('html')}")
    if phase3_files and phase3_files.get('html'):
        print(f"  firefox {phase3_files.get('html')}")
    print()


def get_user_input(prompt, valid_options=None, default=None, allow_empty=False):
    """Get user input with validation."""
    while True:
        if default:
            user_input = input(f"{prompt} [{default}]: ").strip()
            if not user_input:
                user_input = default
        else:
            user_input = input(f"{prompt}: ").strip()

        if valid_options:
            lowered = user_input.lower()
            if lowered in [opt.lower() for opt in valid_options]:
                return lowered
            print_warning(f"Please enter one of: {', '.join(valid_options)}")
        else:
            if user_input or allow_empty:
                return user_input
            print_warning("Input cannot be empty")


def check_phase2_exists(domain):
    """
    Check if Phase 2 data exists for a domain.
    Returns: (exists: bool, file_paths: dict or None)
    """
    output_dir = f"{RECON_OUTPUT_DIR}/{domain}"
    phase2_html = f"{output_dir}/phase2_report.html"
    phase2_json = f"{output_dir}/phase2_data.json"

    if os.path.exists(phase2_json) and os.path.exists(phase2_html):
        return True, {
            "html": phase2_html,
            "json": phase2_json,
            "summary": f"{output_dir}/phase2_summary.txt"
            if os.path.exists(f"{output_dir}/phase2_summary.txt") else None,
            "directory": output_dir
        }
    return False, None


def list_available_domains():
    """
    List domains that have Phase 2 data available.
    Returns: list of domain names
    """
    domains = []
    if os.path.exists(RECON_OUTPUT_DIR):
        for item in os.listdir(RECON_OUTPUT_DIR):
            domain_dir = os.path.join(RECON_OUTPUT_DIR, item)
            if os.path.isdir(domain_dir):
                phase2_json = os.path.join(domain_dir, "phase2_data.json")
                if os.path.exists(phase2_json):
                    domains.append(item)
    return sorted(domains)


def print_mode_menu():
    """Print the operation mode selection menu."""
    print()
    print(f"{Colors.BOLD}Select Operation Mode:{Colors.END}")
    print()
    print(f"  {Colors.CYAN}[1]{Colors.END} Full Scan (Phase 1 -> 2 -> 3)")
    print(f"      Complete pipeline: Discovery + parallel vulnerability scan")
    print(f"      Best for: New targets, full reconnaissance")
    print()
    print(f"  {Colors.CYAN}[2]{Colors.END} Discovery Only (Phase 1 -> 2)")
    print(f"      Subdomain enumeration + live host validation")
    print(f"      Run vulnerability scanning later with option 3")
    print()
    print(f"  {Colors.CYAN}[3]{Colors.END} Vuln Scan Only (Phase 3 Parallel) {Colors.GREEN}[FAST]{Colors.END}")
    print(f"      Tech-based nuclei scan with parallel workers")
    print(f"      Requires existing Phase 2 data")
    print(f"      Time: ~10-15 min for 300 hosts")
    print()


def run_phase3_only():
    """
    Run Phase 3 Parallel only on existing Phase 2 data.
    Uses Parent-Child worker architecture for speed.
    """
    print_step(1, "Phase 3 Parallel Mode - Tech-Based Nuclei Scan")
    print(f"{Colors.GREEN}Using parallel workers for 6-9x speedup!{Colors.END}")

    # List available domains
    available_domains = list_available_domains()

    if not available_domains:
        print_error("No Phase 2 data found!")
        print_info(f"Run Phase 1 & 2 first to generate data in {RECON_OUTPUT_DIR}/")
        return False, None, None

    print()
    print(f"{Colors.CYAN}Available domains with Phase 2 data:{Colors.END}")
    for i, domain in enumerate(available_domains, 1):
        json_path = f"{RECON_OUTPUT_DIR}/{domain}/phase2_data.json"
        host_count = "?"
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
                host_count = data.get('statistics', {}).get('total', '?')
        except Exception:
            pass
        print(f"  {Colors.YELLOW}[{i}]{Colors.END} {domain} ({host_count} live hosts)")

    print()

    # Get domain selection
    domain_input = get_user_input(
        f"{Colors.BOLD}Enter domain name or number from list{Colors.END}"
    )

    # Check if user entered a number
    try:
        idx = int(domain_input) - 1
        if 0 <= idx < len(available_domains):
            domain = available_domains[idx]
        else:
            print_error(f"Invalid selection: {domain_input}")
            return False, None, None
    except ValueError:
        domain = validate_domain(domain_input)
        if not domain:
            print_error(f"Invalid domain: {domain_input}")
            return False, None, None

    # Verify Phase 2 data exists
    exists, phase2_files = check_phase2_exists(domain)
    if not exists:
        print_error(f"No Phase 2 data found for: {domain}")
        print_info(f"Expected location: {RECON_OUTPUT_DIR}/{domain}/phase2_data.json")
        return False, None, None

    print_success(f"Found Phase 2 data for: {domain}")

    # Show Phase 2 stats
    host_count = 0
    if phase2_files.get('json'):
        try:
            with open(phase2_files['json'], 'r') as f:
                phase2_data = json.load(f)
                stats = phase2_data.get('statistics', {})
                host_count = stats.get('total', 0)
                print_info(f"Live hosts: {host_count}")
        except Exception:
            pass

    # Estimate time
    estimated_time = "10-15 minutes" if host_count > 100 else "5-10 minutes"

    # Confirmation
    print()
    print(f"{Colors.BOLD}Configuration:{Colors.END}")
    print(f"  - Target: {domain}")
    print(f"  - Mode: Parallel Workers (Parent-Child)")
    print(f"  - Webhook: {WEBHOOK_PHASE3}")
    print(f"  - Estimated time: {estimated_time}")
    print()

    confirm = get_user_input(
        f"{Colors.BOLD}Start parallel nuclei scan? (yes/no){Colors.END}",
        valid_options=["yes", "no", "y", "n"],
        default="yes"
    )

    if confirm not in ["yes", "y"]:
        print_info("Scan cancelled by user")
        return False, None, None

    # Trigger Phase 3
    print_step(2, "Starting Phase 3 Parallel (Worker-based Nuclei)")
    print_info("Manager spawning worker sub-workflows...")
    print_info(f"Estimated completion: {estimated_time}")

    start_time = datetime.now()

    success, result = trigger_phase3(domain)

    if not success:
        print_error(f"Failed to trigger Phase 3: {result}")
        return False, phase2_files, None

    print_success("Phase 3 webhook triggered successfully")
    if isinstance(result, dict):
        print_info(f"Response: {result.get('message', 'Workflow started')}")

    # Wait for Phase 3 completion
    success, phase3_files = wait_for_phase3_completion(domain)

    if not success:
        print_error(phase3_files)
        print_warning("Check n8n execution logs for details")
        return False, phase2_files, None

    print()
    print_success("Phase 3 completed successfully!")

    # Display stats
    if phase3_files.get('json') and os.path.exists(phase3_files['json']):
        try:
            with open(phase3_files['json'], 'r') as f:
                phase3_data = json.load(f)
                stats = phase3_data.get('stats', {}).get('findings', {})
                print_info(f"Total findings: {stats.get('total', 0)}")
                if stats.get('critical', 0) > 0:
                    print(f"  {Colors.RED}Critical: {stats.get('critical')}{Colors.END}")
                if stats.get('high', 0) > 0:
                    print(f"  {Colors.RED}High: {stats.get('high')}{Colors.END}")
                if stats.get('medium', 0) > 0:
                    print(f"  {Colors.YELLOW}Medium: {stats.get('medium')}{Colors.END}")
                if stats.get('low', 0) > 0:
                    print(f"  {Colors.BLUE}Low: {stats.get('low')}{Colors.END}")
        except Exception:
            pass

    end_time = datetime.now()
    duration = end_time - start_time

    print_results_summary(domain, phase2_files, phase3_files)
    print(f"{Colors.CYAN}Phase 3 execution time:{Colors.END} {duration}")

    return True, phase2_files, phase3_files


def run_full_or_discovery(mode):
    """
    Run Phase 1 & 2, optionally Phase 3.
    mode: 'full' (with nuclei) or 'discovery' (without nuclei)
    """
    run_nuclei = (mode == 'full')

    # Get domain from user
    print_step(2, "Target Configuration")

    domain_input = get_user_input(
        f"{Colors.BOLD}Enter target domain (e.g., example.com){Colors.END}"
    )

    domain = validate_domain(domain_input)
    if not domain:
        print_error(f"Invalid domain: {domain_input}")
        print_info("Domain should be like: example.com or sub.example.com")
        return False

    print_success(f"Target domain: {domain}")

    # Show what will run
    print()
    print(f"{Colors.BOLD}Phases to execute:{Colors.END}")
    print(f"  {Colors.GREEN}[+]{Colors.END} Phase 1: Subdomain Enumeration (subfinder, crt.sh)")
    print(f"  {Colors.GREEN}[+]{Colors.END} Phase 2: Live Host Validation (httpx, dnsx)")
    if run_nuclei:
        print(f"  {Colors.GREEN}[+]{Colors.END} Phase 3: Vulnerability Scanning (nuclei parallel)")
    else:
        print(f"  {Colors.YELLOW}[*]{Colors.END} Phase 3: Skipped (run later with option 3)")

    # Confirmation
    print()
    print(f"{Colors.BOLD}Configuration Summary:{Colors.END}")
    print(f"  * Target: {domain}")
    print(f"  * Phases: 1, 2" + (", 3 (parallel nuclei)" if run_nuclei else ""))
    print(f"  * Output: {RECON_OUTPUT_DIR}/{domain}/")
    print()

    confirm = get_user_input(
        f"{Colors.BOLD}Start reconnaissance? (yes/no){Colors.END}",
        valid_options=["yes", "no", "y", "n"],
        default="yes"
    )

    if confirm not in ["yes", "y"]:
        print_info("Reconnaissance cancelled by user")
        return False

    # Execute Phase 1 (chains to Phase 2)
    print_step(3, "Starting Phase 1 & 2 (Subdomain Enum -> Live Host Validation)")
    print_info("This may take several minutes depending on the target size...")

    start_time = datetime.now()

    success, result = trigger_phase1(domain)

    if not success:
        print_error(f"Failed to trigger Phase 1: {result}")
        return False

    print_success("Phase 1 webhook triggered successfully")
    if isinstance(result, dict):
        print_info(f"Response: {result.get('message', 'Workflow started')}")

    # Wait for Phase 2 completion
    success, phase2_files = wait_for_phase2_completion(domain)

    if not success:
        print_error(phase2_files)
        print_warning("Check n8n execution logs for details")
        print_info(f"n8n UI: {N8N_BASE_URL}")
        return False

    print()
    print_success("Phase 2 completed successfully!")

    # Read and display Phase 2 summary if available
    if phase2_files.get('json') and os.path.exists(phase2_files['json']):
        try:
            with open(phase2_files['json'], 'r') as f:
                phase2_data = json.load(f)
                stats = phase2_data.get('statistics', {})
                print_info(f"Live hosts found: {stats.get('total', 'N/A')}")
                print_info(f"HTTP verified: {stats.get('both', 0) + stats.get('httpOnly', 0)}")
                print_info(f"DNS only: {stats.get('dnsOnly', 'N/A')}")
        except Exception:
            pass

    phase3_files = None

    # Execute Phase 3 if requested
    if run_nuclei:
        print_step(4, "Starting Phase 3 (Parallel Nuclei Scanning)")
        print_info("Parallel workers scanning by tech stack...")
        print_warning("This may take 10-15 minutes for large targets")

        success, result = trigger_phase3(domain)

        if not success:
            print_error(f"Failed to trigger Phase 3: {result}")
            print_warning("Phase 2 results are still available")
        else:
            print_success("Phase 3 webhook triggered successfully")

            # Wait for Phase 3 completion
            success, phase3_files = wait_for_phase3_completion(domain)

            if not success:
                print_error(phase3_files)
                print_warning("Check n8n execution logs for details")
            else:
                print()
                print_success("Phase 3 completed successfully!")

                # Read and display Phase 3 summary
                if phase3_files.get('json') and os.path.exists(phase3_files['json']):
                    try:
                        with open(phase3_files['json'], 'r') as f:
                            phase3_data = json.load(f)
                            stats = phase3_data.get('stats', {}).get('findings', {})
                            print_info(f"Total findings: {stats.get('total', 0)}")
                            if stats.get('critical', 0) > 0:
                                print(f"  {Colors.RED}Critical: {stats.get('critical')}{Colors.END}")
                            if stats.get('high', 0) > 0:
                                print(f"  {Colors.RED}High: {stats.get('high')}{Colors.END}")
                            if stats.get('medium', 0) > 0:
                                print(f"  {Colors.YELLOW}Medium: {stats.get('medium')}{Colors.END}")
                            if stats.get('low', 0) > 0:
                                print(f"  {Colors.BLUE}Low: {stats.get('low')}{Colors.END}")
                    except Exception:
                        pass

    # Calculate total time
    end_time = datetime.now()
    duration = end_time - start_time

    # Final summary
    print_results_summary(domain, phase2_files, phase3_files)

    print(f"{Colors.CYAN}Total execution time:{Colors.END} {duration}")
    print()

    if not run_nuclei:
        print(f"{Colors.CYAN}Tip:{Colors.END} Run vulnerability scan later with option 3")
        print()

    print_success("Reconnaissance pipeline completed!")
    return True


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main orchestration function."""
    print_banner()

    # Step 1: Check n8n connectivity
    print_step(1, "Checking n8n instance connectivity...")

    if not check_n8n_health():
        print_error("Cannot connect to n8n instance!")
        print_info(f"Make sure n8n is running at {N8N_BASE_URL}")
        print_info("Start n8n with: n8n start")
        sys.exit(1)

    print_success("n8n instance is accessible")

    # Show mode selection menu
    print_mode_menu()

    mode_choice = get_user_input(
        f"{Colors.BOLD}Select mode (1/2/3){Colors.END}",
        valid_options=["1", "2", "3"],
        default="1"
    )

    if mode_choice == "1":
        print()
        print(f"{Colors.GREEN}Mode: Full Scan (Phase 1 -> 2 -> 3 Parallel){Colors.END}")
        run_full_or_discovery('full')

    elif mode_choice == "2":
        print()
        print(f"{Colors.GREEN}Mode: Discovery Only (Phase 1 -> 2){Colors.END}")
        run_full_or_discovery('discovery')

    elif mode_choice == "3":
        print()
        print(f"{Colors.GREEN}Mode: Vuln Scan Only (Phase 3 Parallel){Colors.END}")
        run_phase3_only()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print_warning("Interrupted by user (Ctrl+C)")
        print_info("Note: n8n workflows may still be running in the background")
        sys.exit(130)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)