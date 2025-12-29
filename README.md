<h1 align="center">
  <br>
  ReconDuctor v2
  <br>
</h1>
<img width="945" height="185" alt="image" src="https://github.com/user-attachments/assets/e11bdf2b-4ab6-47c6-92ae-9587db513f41" />

<h4 align="center">Field-ready Python reconnaissance tool for security professionals</h4>

<p align="center">
  <a href="#features">Features</a> |
  <a href="#screenshots">Screenshots</a> |
  <a href="#installation">Installation</a> |
  <a href="#configuration">Configuration</a> |
  <a href="#usage">Usage</a> |
  <a href="#ai-features">AI Features</a> |
  <a href="#command-reference">Commands</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/platform-linux-lightgrey.svg" alt="Platform: Linux">
  <img src="https://img.shields.io/badge/version-2.0.0-orange.svg" alt="Version 2.0.0">
</p>

---

A comprehensive subdomain enumeration and vulnerability scanning framework with AI-powered features, origin IP discovery, and crash recovery.

## Features

### Core Capabilities
- **Multi-source Subdomain Enumeration** - Passive and active discovery from 16+ sources
- **Batched Vulnerability Scanning** - Checkpoint-based Nuclei scans with resume support
- **Origin IP Discovery** - Find real IPs behind CDN/WAF using Shodan and SecurityTrails
- **Port Scanning** - Discover web services on non-standard ports with naabu
- **Screenshot Capture** - Automated screenshots of live hosts with gowitness
- **Subdomain Takeover Detection** - Identify vulnerable CNAME records with subjack
- **Crash Recovery** - Checkpoint system to resume interrupted scans

### AI-Powered Features
- **AI Wordlist Generation** - Uses Claude to generate intelligent, context-aware wordlists
- **AI Vulnerability Triage** - Risk-prioritized analysis with attack chain identification
- **AI URL Filtering** - Smart filtering of historical URLs by exploit likelihood

### Advanced Reconnaissance
- **Historical URL Mining (GAU)** - Automatic discovery of forgotten endpoints from Wayback, OTX, URLScan
- **Origin IP Discovery** - Find real IPs behind CDN/WAF using Shodan (discovered 64 new findings in testing!)
- **Battle Plan Generation** - Automated `targets/` folder with prioritized next steps and ready-to-use target files
- **Rich CLI Interface** - Real-time progress display with detailed statistics

## Screenshots

### Scan Management
Track all your scans with detailed statistics:

![List Scans](docs/images/list-scans.png)

*View all completed scans with subdomain counts, live hosts, findings, and scan dates*

### HTML Vulnerability Report
Beautiful, interactive HTML reports with severity breakdown:

![HTML Report](docs/images/report.png)

*Findings organized by severity with CVSS scores, CVE references, remediation links, and tags*

### AI-Powered Triage
Intelligent vulnerability analysis with business impact assessment:

![AI Triage](docs/images/ai-triage.png)

*Prioritized risk items with evidence, exploit details, business impact, attack chains, and remediation steps*

### Historical URL Discovery (GAU)
Discover forgotten endpoints and parameters:

![GAU Results](docs/images/gau-results.png)

*URLs categorized by type with parameter extraction and status codes*

## Scan Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PHASE 1: ENUMERATION                              │
├─────────────────────────────────────────────────────────────────────────────┤
│  Passive Enumeration                                                        │
│  ├── Subfinder (APIs: VirusTotal, SecurityTrails, etc.)                     │
│  ├── crt.sh (Certificate Transparency logs)                                 │
│  └── Shodan (SSL certificate CN extraction)                                 │
│                                                                             │
│  AI Wordlist Generation (--ai flag)                                         │
│  └── Claude generates targeted prefixes based on:                           │
│      • Historical subdomains from CT logs & Wayback Machine                 │
│      • Detected naming patterns and technologies                            │
│      • Industry-specific conventions                                        │
│                                                                             │
│  Active Enumeration                                                         │
│  ├── DNS Bruteforce (puredns + massdns)                                     │
│  └── Permutation Generation (alterx)                                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          PHASE 2: VALIDATION                                │
├─────────────────────────────────────────────────────────────────────────────┤
│  DNS Resolution                                                             │
│  └── Resolve all discovered subdomains to IP addresses                      │
│                                                                             │
│  Port Scanning (naabu)                                                      │
│  └── Scan 80+ common web ports to find services on non-standard ports       │
│                                                                             │
│  Runs in PARALLEL:                                                          │
│  │                                                                          │
│  │  HTTP Probing (httpx)                                                    │
│  │  └── Validate live hosts with status codes, titles, technologies         │
│  │                                                                          │
│  │  Subdomain Takeover Detection (subjack)                                  │
│  │  └── Check CNAME records against known vulnerable fingerprints           │
│  │                                                                          │
│  │  GAU Historical URL Mining (automatic)                                   │
│  │  ├── Mine Wayback Machine, OTX, URLScan for historical URLs              │
│  │  ├── Categorize by vulnerability type (SQLi, SSRF, LFI, XSS, RCE)        │
│  │  └── Generate gau_findings.html report                                   │
│  │                                                                          │
│  Screenshot Capture (gowitness)                                             │
│  ├── Capture screenshots of all live hosts                                  │
│  └── Generate interactive gallery (screenshots_gallery.html)                │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                       PHASE 3: VULNERABILITY SCANNING                       │
├─────────────────────────────────────────────────────────────────────────────┤
│  Smart Host Filtering                                                       │
│  ├── Skip 404 (Not Found) hosts - no content to scan                        │
│  ├── Skip 500+ (Server Error) hosts - unreliable targets                    │
│  └── Keep 401/403 hosts - may have auth bypass vulnerabilities              │
│                                                                             │
│  Nuclei Batched Scan                                                        │
│  ├── Checkpoint/resume support (recovers from interruption)                 │
│  ├── Smart host filtering (skip 404/500+ hosts)                             │
│  └── Configurable severity filters (critical, high, medium)                 │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           PHASE 4: ANALYSIS                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│  Origin IP Discovery (Shodan + SecurityTrails) - POWERFUL!                  │
│  └── Find real IPs behind Cloudflare/CDN using:                             │
│      • SSL Certificate CN matching (Shodan)                                 │
│      • Favicon hash correlation (Shodan)                                    │
│      • Historical DNS records (SecurityTrails)                              │
│  └── Discovered 64 NEW findings by bypassing WAF in real testing!           │
│                                                                             │
│  AI Vulnerability Triage (--ai-triage flag)                                 │
│  ├── Risk-prioritized analysis of all findings                              │
│  ├── Attack chain identification                                            │
│  ├── Executive summary generation                                           │
│  ├── Remediation priorities                                                 │
│  └── AI-powered GAU URL filtering:                                          │
│      • Ranks URLs by exploit likelihood (RCE > SSRF > LFI > SQLi)           │
│      • Deduplicates similar endpoints                                       │
│      • Selects top high-value URLs for testing                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              OUTPUT                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│  output/<domain>/                                                           │
│  ├── scan_info.json           # Scan metadata and statistics                │
│  ├── subdomains.txt           # All discovered subdomains                   │
│  ├── hosts.json               # Live hosts with HTTP details                │
│  ├── findings.json            # Nuclei vulnerability findings               │
│  ├── report.html              # Main HTML report                            │
│  ├── screenshots/             # Host screenshots (gowitness)                │
│  ├── screenshots_gallery.html # Interactive screenshot gallery              │
│  ├── gau_findings.html        # Historical URLs by category                 │
│  └── triage_report.html       # AI triage analysis (if --ai-triage)         │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

Install required external tools:

```bash
# Go tools (ProjectDiscovery suite)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/d3mondev/puredns/v2@latest

# GAU - GetAllUrls (historical URL mining)
go install github.com/lc/gau/v2/cmd/gau@latest

# Gowitness - Screenshot capture
go install github.com/sensepost/gowitness/v3@latest

# Subjack - Subdomain takeover detection
go install github.com/haccer/subjack@latest

# massdns (C program)
sudo apt install massdns  # Kali/Debian
# OR compile from source:
# git clone https://github.com/blechschmidt/massdns.git && cd massdns && make && sudo make install

# Update Nuclei templates
nuclei -update-templates
```

### Python Setup

```bash
# Clone repository
git clone https://github.com/reconductor/reconductor-v2.git
cd reconductor-v2

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Verify installation
reconductor check-tools
```

### API Keys (Optional)

Set via environment variables - **NEVER put API keys in config files!**

```bash
# For enhanced enumeration and origin IP discovery
export SHODAN_API_KEY="your_shodan_api_key"
export SECURITYTRAILS_API_KEY="your_securitytrails_api_key"

# For AI features (choose one provider)
export ANTHROPIC_API_KEY="sk-ant-..."      # Anthropic Claude
export OPENAI_API_KEY="sk-..."              # OpenAI
export GEMINI_API_KEY="..."                 # Google Gemini
export GROQ_API_KEY="..."                   # Groq
```

## Configuration

ReconDuctor uses YAML configuration files. The default config is `config/default.yaml`.

### Quick Setup

```bash
# Copy example config to local (local.yaml is gitignored)
cp config/example.yaml config/local.yaml

# Edit with your preferences
nano config/local.yaml
```

### LLM Provider Setup

ReconDuctor supports 6 LLM providers for AI features:

#### Option 1: Claude Code CLI (Recommended - No API Key!)

If you have [Claude Code](https://claude.ai/code) installed:

```yaml
# config/local.yaml
llm:
  primary_provider: claude_code
  primary_model: sonnet           # Options: sonnet, opus, haiku
```

#### Option 2: Ollama (Free, Local, Private)

```yaml
llm:
  primary_provider: ollama
  primary_model: llama3.2
  api_base: http://localhost:11434
```

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2
```

#### Option 3: Anthropic API

```yaml
llm:
  primary_provider: anthropic
  primary_model: claude-3-haiku-20240307
```

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

#### Option 4: OpenAI API

```yaml
llm:
  primary_provider: openai
  primary_model: gpt-4o-mini
```

```bash
export OPENAI_API_KEY="sk-..."
```

#### Option 5: Google Gemini

```yaml
llm:
  primary_provider: gemini
  primary_model: gemini-1.5-flash
```

```bash
export GEMINI_API_KEY="your-api-key"
```

#### Option 6: Groq (Fast Inference)

```yaml
llm:
  primary_provider: groq
  primary_model: llama-3.3-70b-versatile
```

```bash
export GROQ_API_KEY="your-api-key"
```

### Nuclei Configuration

Customize vulnerability scanning:

```yaml
nuclei:
  severity:
    - critical
    - high
    - medium

  exclude_tags:
    - fuzz
    - dos
    - intrusive
    - sqli          # Remove to enable SQLi testing
    - xss           # Remove to enable XSS testing
    - rce           # Remove to enable RCE testing

  rate_limit: 150
  bulk_size: 25
  concurrency: 25
  disable_interactsh: true
```

### Rate Limiting

Adaptive WAF-aware throttling:

```yaml
rate_limit:
  initial_rate: 30.0    # Starting requests/sec
  min_rate: 1.0         # Minimum when backing off
  backoff_factor: 0.5   # Reduce by 50% on WAF detection
  recovery_factor: 1.1  # Increase by 10% when stable
```

## Usage

### Quick Start

```bash
# Basic full scan
reconductor scan example.com

# Full scan with all AI features (recommended for thorough assessment)
reconductor scan example.com --ai --ai-triage

# Quick passive scan only
reconductor scan example.com --passive-only
```

### Full Scan Options

```bash
# Basic scan (all phases, includes GAU automatically)
reconductor scan example.com

# Scan with AI wordlist generation
reconductor scan example.com --ai

# Scan with AI vulnerability triage + URL filtering
reconductor scan example.com --ai-triage

# Complete assessment with all AI features
reconductor scan example.com --ai --ai-triage

# Skip vulnerability scanning (enumeration + validation only)
reconductor scan example.com --no-nuclei

# Custom output directory
reconductor scan example.com -o ./results

# Passive enumeration only (no bruteforce, no GAU)
reconductor scan example.com --passive-only

# Adjust rate limiting
reconductor scan example.com --rate-limit 50
```

### Resume Interrupted Scans

```bash
# Continue from checkpoint
reconductor continue example.com

# Continue and run AI triage on findings
reconductor continue example.com --ai-triage

# Continue but skip nuclei scanning
reconductor continue example.com --no-nuclei
```

### Individual Commands

```bash
# Subdomain enumeration only
reconductor enumerate example.com

# HTTP probe a list of targets
reconductor probe targets.txt

# Nuclei scan a list of targets
reconductor nuclei targets.txt

# Generate AI wordlist
reconductor ai-wordlist example.com

# Run AI triage on existing scan
reconductor triage example.com

# Run GAU standalone
reconductor gau example.com

# GAU with AI filtering
reconductor gau example.com --ai

# Find origin IPs behind CDN (Shodan required)
reconductor origin-ips example.com
```

### Utility Commands

```bash
# Check tool availability
reconductor check-tools

# List all completed scans
reconductor list-scans

# Show version
reconductor --version

# Show help
reconductor --help
```

## Command Reference

### `scan` - Full Domain Scan

| Option | Description |
|--------|-------------|
| `--output, -o` | Output directory for results |
| `--phase, -p` | Start from specific phase (0=all) |
| `--passive-only` | Only run passive enumeration |
| `--no-nuclei` | Skip vulnerability scanning |
| `--ai` | Enable AI wordlist generation |
| `--ai-triage` | Enable AI triage + GAU URL filtering |
| `--rate-limit, -r` | Requests per second (default: 30) |
| `--quiet, -q` | Minimal output mode |

### `continue` - Resume Scan

| Option | Description |
|--------|-------------|
| `--no-nuclei` | Skip vulnerability scanning on resume |
| `--ai-triage` | Run AI triage on findings |

### `triage` - AI Analysis

| Option | Description |
|--------|-------------|
| `--output, -o` | Output directory containing scan results |

### `gau` - Historical URL Mining

| Option | Description |
|--------|-------------|
| `--output, -o` | Output directory (defaults to output/<domain>) |
| `--ai` | Use AI to filter and rank high-value URLs |

### `origin-ips` - CDN Bypass

| Option | Description |
|--------|-------------|
| `--output, -o` | Output directory |

## AI Features

### AI Wordlist Generation (`--ai`)

Uses Claude (haiku) to generate intelligent subdomain prefixes:

1. **Intelligence Gathering** - Fetches historical subdomains from CT logs and Wayback Machine
2. **Pattern Analysis** - Detects naming conventions and technologies
3. **AI Generation** - Creates targeted prefixes based on gathered intelligence
4. **Wordlist Combination** - Merges with base wordlist, removes duplicates

```
Phase 1: Subdomain Enumeration
  [ok] Passive Enum     2184 (subfinder:501, crt.sh:1709, shodan:120)
  [ok] AI Wordlist      187 intelligent prefixes
  [ok] DNS Brute        +18 subdomains
```

### AI Vulnerability Triage (`--ai-triage`)

Uses Claude (sonnet) to analyze and prioritize findings:

- **Risk Prioritization** - Groups findings by actual risk, not just severity
- **Attack Chain Identification** - Finds related vulnerabilities that chain together
- **Executive Summary** - Business-friendly overview for stakeholders
- **Remediation Priorities** - Ordered fix recommendations

### Historical URL Mining (GAU)

GAU runs automatically in Phase 2 and mines URLs from:
- Wayback Machine
- OTX (Open Threat Exchange)
- URLScan
- CommonCrawl

### AI URL Filtering (`--ai-triage`)

When enabled, Claude ranks GAU URLs by exploit likelihood:

**Priority Order:**
1. RCE/Command injection (`cmd=`, `exec=`, `shell=`)
2. SSRF/Open redirect (`url=`, `redirect=`, `callback=`)
3. LFI/Path traversal (`file=`, `path=`, `include=`)
4. SQLi (`id=`, `uid=`, `page=`, `limit=`)
5. Auth endpoints (oauth, saml, token)
6. Debug paths (`/debug/`, `/trace/`, phpinfo)
7. Sensitive files (`.env`, `.conf`, `.sql`)
8. API endpoints (`/api/`, `/graphql/`)

### Origin IP Discovery

Find real IPs behind CDN/WAF protection using Shodan and SecurityTrails:
- SSL Certificate CN matching (Shodan)
- Favicon hash correlation (Shodan)
- Historical DNS records (SecurityTrails)

**Real-world result:** In testing, origin IP bypass discovered **64 new findings** that were hidden behind WAF protection!

## Output Structure

```
output/example.com/
|-- scan_info.json           # Scan metadata and statistics
|-- scan.db                  # SQLite checkpoint database
|-- subdomains.txt           # All discovered subdomains
|-- subdomains_all.md        # Formatted subdomain list
|-- subdomains_live.md       # Live subdomains only
|-- live_hosts.txt           # Live host URLs
|-- hosts.json               # Live hosts with HTTP details
|-- findings.json            # Nuclei vulnerability findings
|-- findings_summary.txt     # Human-readable findings summary
|-- report.html              # Main HTML report
|
|-- screenshots/             # Gowitness screenshots
|   |-- screenshot_<hash>.png
|   +-- ...
|-- screenshots_gallery.html # Interactive screenshot gallery
|
|-- gau_findings.html        # Historical URLs by category
|-- triage_report.html       # AI triage analysis (if --ai-triage)
|-- non_http_subdomains_report.html  # Non-HTTP services found
|
+-- targets/                 # BATTLE PLAN - Pentester action files
    |-- next_steps.md        # Prioritized action plan with commands
    |-- fuzz_urls.txt        # URLs with parameters for fuzzing
    |-- sqli_candidates.txt  # SQLi injection points
    |-- ssrf_candidates.txt  # SSRF/redirect candidates
    |-- lfi_candidates.txt   # LFI/path traversal candidates
    |-- origin_ips.txt       # Origin IPs for WAF bypass
    |-- all_params.txt       # All discovered parameters
    +-- live_urls.txt        # Live host URLs for scanning
```

## Battle Plan (targets/ folder)

After every scan, ReconDuctor generates an actionable **battle plan** in the `targets/` directory. This gives pentesters ready-to-use target files and prioritized next steps.

### next_steps.md

The `next_steps.md` file contains:
- **Prioritized actions** based on findings severity
- **Copy-paste commands** for common tools (sqlmap, ffuf, dalfox, etc.)
- **Target summary table** with counts per category

Example:
```markdown
# Next Steps - target.com

## Priority Actions

### 1. 🔴 Validate 3 CRITICAL findings
### 2. 🎯 Test 5 Origin IPs (WAF Bypass)
### 3. 💉 Test 12 SQLi Candidates
### 4. 🔗 Test 8 SSRF/Redirect Candidates
### 5. 🔨 Fuzz 45 URLs with Parameters
```

### Target Files

| File | Description | Use Case |
|------|-------------|----------|
| `fuzz_urls.txt` | URLs with parameters | Feed to ffuf, Burp Intruder |
| `sqli_candidates.txt` | URLs with id/user/order params | sqlmap -m, manual testing |
| `ssrf_candidates.txt` | URLs with redirect/url params | SSRF/open redirect testing |
| `lfi_candidates.txt` | URLs with file/path params | LFI/path traversal testing |
| `origin_ips.txt` | Origin IPs behind CDN | Direct scanning, WAF bypass |
| `all_params.txt` | All discovered parameters | Arjun, custom wordlists |
| `live_urls.txt` | All live host URLs | Feroxbuster, directory brute |

### Quick Usage

```bash
# After scan completes, start with the battle plan
cat output/target.com/targets/next_steps.md

# SQLi testing
sqlmap -m output/target.com/targets/sqli_candidates.txt --batch

# XSS testing
cat output/target.com/targets/fuzz_urls.txt | dalfox pipe

# Directory bruteforce
feroxbuster -L output/target.com/targets/live_urls.txt

# WAF bypass via origin IPs
while read ip; do curl -sk -H 'Host: target.com' "https://$ip"; done < output/target.com/targets/origin_ips.txt
```

## URL Categorization

GAU findings are automatically categorized by vulnerability type:

| Category | Pattern Examples |
|----------|-----------------|
| **SSRF Candidates** | `url=`, `redirect=`, `callback=`, `dest=` |
| **LFI Candidates** | `file=`, `path=`, `template=`, `include=` |
| **SQLi Candidates** | `id=`, `user=`, `search=`, `order=` |
| **XSS Candidates** | `q=`, `message=`, `content=`, `name=` |
| **Open Redirect** | `next=`, `return=`, `goto=`, `redir=` |
| **RCE Candidates** | `cmd=`, `exec=`, `command=`, `run=` |
| **API Endpoints** | `/api/`, `/v1/`, `/graphql/` |
| **Auth Endpoints** | `/login`, `/oauth`, `/token` |
| **Admin Paths** | `/admin`, `/dashboard`, `/manage` |
| **Debug Paths** | `/debug`, `/phpinfo`, `/trace` |

## External Tools

| Tool | Purpose | Source |
|------|---------|--------|
| **subfinder** | Passive subdomain enumeration | projectdiscovery |
| **httpx** | HTTP probing and validation | projectdiscovery |
| **nuclei** | Vulnerability scanning | projectdiscovery |
| **naabu** | Port scanning | projectdiscovery |
| **dnsx** | Fast DNS resolver | projectdiscovery |
| **puredns** | DNS bruteforce/resolution | d3mondev |
| **massdns** | Fast DNS resolver (backend) | blechschmidt |
| **alterx** | Subdomain permutation | projectdiscovery |
| **gau** | Historical URL mining | lc |
| **gowitness** | Screenshot capture | sensepost |
| **subjack** | Subdomain takeover detection | haccer |

## APIs Used

| Service | Purpose | Required |
|---------|---------|----------|
| **Anthropic Claude** | AI features (wordlist, triage, GAU) | For AI features |
| **crt.sh** | Certificate Transparency logs | No (free) |
| **Shodan** | Subdomain enum, Origin IP discovery | Optional |
| **SecurityTrails** | Historical DNS records for origin IP discovery | Optional |
| **Wayback Machine** | Historical URLs (via GAU) | No (free) |
| **CommonCrawl** | Historical URLs (via GAU) | No (free) |
| **OTX** | Historical URLs (via GAU) | No (free) |
| **URLScan** | Historical URLs (via GAU) | No (free) |

## Project Architecture

```
reconductor/
|-- core/                    # Core framework
|   |-- config.py            # Configuration management
|   |-- database.py          # SQLite storage
|   |-- checkpoint.py        # Crash recovery
|   |-- orchestrator.py      # Main scan pipeline
|   |-- exporter.py          # Report generation
|   |-- rate_limiter.py      # Adaptive rate limiting
|   |-- scope.py             # Scope validation
|   +-- logger.py            # Structured logging
|
|-- models/                  # Data models
|   |-- subdomain.py         # Subdomain model
|   |-- host.py              # Host model
|   |-- finding.py           # Vulnerability finding
|   +-- scan.py              # Scan state
|
|-- modules/
|   |-- subdomain/           # Enumeration
|   |   |-- passive.py       # Subfinder, crt.sh, Shodan
|   |   |-- puredns_wrapper.py
|   |   +-- alterx_wrapper.py
|   |
|   |-- validation/          # Host validation
|   |   |-- http_probe.py    # httpx integration
|   |   |-- dns_resolve.py   # DNS resolution
|   |   +-- port_scan.py     # naabu integration
|   |
|   |-- scanning/            # Vulnerability scanning
|   |   |-- nuclei_manager.py    # Parallel Nuclei workers
|   |   |-- takeover.py          # Takeover detection
|   |   +-- subjack_wrapper.py   # Subjack integration
|   |
|   |-- recon/               # Reconnaissance
|   |   |-- shodan_recon.py      # Origin IP discovery
|   |   |-- gau_wrapper.py       # GAU historical URL mining
|   |   +-- screenshot_capture.py # Gowitness screenshots
|   |
|   +-- ai/                  # AI integration
|       |-- llm_client.py        # Multi-provider LLM client
|       |-- wordlist_agent.py    # AI wordlist generation
|       |-- finding_analyzer.py  # AI vulnerability triage
|       +-- gau_filter_agent.py  # AI GAU URL filtering
|
|-- utils/                   # Utilities
|   |-- executor.py          # Tool execution
|   |-- parser.py            # Output parsing
|   |-- deduplicator.py      # Deduplication
|   |-- validator.py         # Input validation
|   +-- tempfiles.py         # Secure temp files
|
+-- cli.py                   # CLI interface (Typer + Rich)
```

## Examples

### Quick Passive Scan

```bash
reconductor scan target.com --passive-only
```

### Full Assessment with AI

```bash
# Complete assessment with all AI features
reconductor scan target.com --ai --ai-triage

# View results
firefox output/target.com/report.html           # Main report
firefox output/target.com/triage_report.html    # AI triage
firefox output/target.com/gau_findings.html     # Historical URLs
firefox output/target.com/screenshots_gallery.html
```

### Post-Scan Analysis

```bash
# Run AI triage on existing findings
reconductor triage target.com

# List all scans
reconductor list-scans
```

## Sample Scan Output

Example output from a real scan (domain sanitized):

### Discovered Subdomains (`subdomains.txt`)
```
a.ns.example.com
api.example.com
b.ns.example.com
design.example.com
docs.example.com
events.example.com
go.example.com
gslink.example.com
example.com
info.example.com
links.example.com
mta-sts.forwarding.example.com
mta-sts.example.com
support.example.com
www.example.com
```

### Live Hosts (`live_hosts.txt`)
```
https://api.example.com
https://docs.example.com
https://gslink.example.com
https://example.com
https://mta-sts.forwarding.example.com
https://mta-sts.example.com
https://support.example.com
https://www.example.com
```

### Scan Statistics (`scan_info.json`)
```json
{
  "domain": "example.com",
  "status": "completed",
  "duration_seconds": 104.75,
  "stats": {
    "subdomains_discovered": 17,
    "passive_total": 17,
    "subfinder_count": 16,
    "crtsh_count": 15,
    "dns_resolved": 11,
    "open_ports": 58,
    "hosts_alive": 25,
    "origin_ips_found": 5,
    "screenshots_captured": 25,
    "gau_total_urls": 83,
    "gau_unique_urls": 37,
    "gau_urls_with_params": 12
  }
}
```

### Battle Plan (`targets/next_steps.md`)
```markdown
# Next Steps - example.com

## Priority Actions

### 1. 💉 Test 7 SQLi Candidates
URLs with id/user/order parameters - classic injection points.

### 2. 🔨 Fuzz 12 URLs with Parameters
cat targets/fuzz_urls.txt | qsreplace FUZZ | ffuf -u FUZZ -w payloads.txt

### 3. 🔍 Content Discovery on 25 Live Hosts
feroxbuster -L targets/live_urls.txt

## Target Summary

| Category         | Count | File                       |
|------------------|-------|----------------------------|
| URLs with params | 12    | targets/fuzz_urls.txt      |
| SQLi candidates  | 7     | targets/sqli_candidates.txt|
| Live hosts       | 25    | targets/live_urls.txt      |
```

## Tips

1. **Start with passive scan** to get initial subdomains quickly
2. **Use `--ai` for thorough assessments** - generates targeted wordlists
3. **GAU runs automatically** - historical URLs included in every full scan
4. **Use `--ai-triage` for reporting** - creates executive summaries + filters GAU URLs
5. **Check screenshots gallery** for quick visual assessment
6. **Monitor rate limits** - adjust with `--rate-limit` if getting blocked
7. **Review gau_findings.html** - categorized URLs for manual testing
8. **Try origin-ips command** - can bypass WAF and find hidden vulnerabilities!

## Security Notice

- **API Keys**: Always use environment variables, never commit secrets
- **Scope**: Only scan authorized targets
- **Rate Limiting**: Respect target infrastructure
- **Responsible Disclosure**: Report vulnerabilities responsibly

## License

MIT License

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before scanning any targets. The authors are not responsible for misuse of this tool.

---

**ReconDuctor v2** - Built for security professionals who need comprehensive, AI-enhanced reconnaissance.
