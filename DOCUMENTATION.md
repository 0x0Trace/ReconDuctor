# ReconDuctor v2 - Comprehensive Documentation

## Overview

ReconDuctor v2 is a field-ready Python reconnaissance tool for subdomain enumeration and vulnerability scanning. It integrates multiple industry-standard tools into a unified pipeline with crash recovery, scope validation, and adaptive rate limiting.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [CLI Commands](#cli-commands)
5. [Pipeline Phases](#pipeline-phases)
6. [Core Components](#core-components)
7. [Module Details](#module-details)
8. [Configuration](#configuration)
9. [Security Features](#security-features)
10. [Future Improvements](#future-improvements)

---

## Architecture

```
reconductor-v2/
├── reconductor/
│   ├── core/                    # Core framework
│   │   ├── config.py           # Pydantic settings management
│   │   ├── logger.py           # Structured logging (structlog)
│   │   ├── database.py         # SQLite async storage
│   │   ├── checkpoint.py       # Crash recovery system
│   │   ├── scope.py            # Domain/ASN/IP scope validation
│   │   ├── rate_limiter.py     # Adaptive WAF-aware rate limiting
│   │   └── orchestrator.py     # Main pipeline controller
│   │
│   ├── models/                  # Pydantic data models
│   │   ├── subdomain.py        # Subdomain with source tracking
│   │   ├── host.py             # Host with IPv4/IPv6, CDN detection
│   │   ├── finding.py          # Vulnerability findings
│   │   └── scan.py             # Scan state and statistics
│   │
│   ├── modules/
│   │   ├── subdomain/          # Phase 1: Enumeration
│   │   │   ├── passive.py      # Subfinder + crt.sh integration
│   │   │   ├── puredns_wrapper.py  # DNS brute-force with wildcard filtering
│   │   │   └── alterx_wrapper.py   # AI-powered permutation generation
│   │   │
│   │   ├── validation/         # Phase 2: Validation
│   │   │   ├── http_probe.py   # httpx HTTP probing
│   │   │   ├── dns_resolve.py  # dnsx DNS resolution
│   │   │   └── port_scan.py    # naabu port scanning
│   │   │
│   │   ├── scanning/           # Phase 3: Vulnerability Scanning
│   │   │   ├── nuclei_manager.py   # Dynamic parallel Nuclei scanning
│   │   │   ├── takeover.py         # Subdomain takeover detection
│   │   │   └── subjack_wrapper.py  # Subjack takeover scanning
│   │   │
│   │   ├── recon/              # Phase 4: Analysis
│   │   │   ├── shodan_recon.py     # Origin IP discovery
│   │   │   ├── gau_wrapper.py      # GAU historical URL mining
│   │   │   └── screenshot_capture.py # Gowitness screenshots
│   │   │
│   │   └── ai/                 # AI/LLM Integration
│   │       ├── llm_client.py       # Multi-provider LLM client
│   │       ├── wordlist_agent.py   # AI wordlist generation
│   │       ├── triage_agent.py     # AI vulnerability triage
│   │       └── gau_filter_agent.py # AI GAU URL filtering
│   │
│   ├── utils/
│   │   ├── executor.py         # Async subprocess execution with security
│   │   ├── parser.py           # Tool output parsers
│   │   ├── deduplicator.py     # Subdomain deduplication
│   │   ├── validator.py        # LLM output validation
│   │   └── tempfiles.py        # Secure temp file management
│   │
│   └── cli.py                  # Rich CLI interface
│
├── config/
│   └── default.yaml            # Default configuration
│
├── wordlists/
│   ├── subdomains.txt          # Base subdomain wordlist
│   └── resolvers.txt           # DNS resolver list
│
└── tests/
    └── test_core.py            # Unit tests (19 tests)
```

---

## Installation

### Prerequisites

```bash
# Python 3.11+
python3 --version

# Go 1.21+ (for ProjectDiscovery tools)
go version
```

### Install ProjectDiscovery Tools

```bash
# Required tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/d3mondev/puredns/v2@latest

# Update Nuclei templates
nuclei -update-templates
```

### Install ReconDuctor

```bash
cd /home/kali/projects/reconductor/reconductor-v2

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install package
pip install -e .

# Verify installation
reconductor --version
reconductor check-tools
```

---

## Quick Start

### Basic Scan

```bash
# Activate virtual environment
source venv/bin/activate

# Full reconnaissance scan
reconductor scan example.com

# Passive-only scan (no brute-force)
reconductor scan example.com --passive-only

# Skip vulnerability scanning
reconductor scan example.com --no-nuclei

# Custom output directory
reconductor scan example.com -o ./results/example
```

### Individual Commands

```bash
# Subdomain enumeration only
reconductor enumerate example.com -o subdomains.txt

# HTTP probing
reconductor probe targets.txt -o live_hosts.json

# Nuclei scanning
reconductor nuclei targets.txt -s critical,high -r 100
```

### Resume Interrupted Scan

```bash
# List incomplete scans
reconductor list-incomplete

# Resume a scan
reconductor resume example.com
```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `scan <domain>` | Run full reconnaissance pipeline |
| `continue <domain>` | Continue a scan from where it left off |
| `triage <domain>` | Run AI-powered triage on existing findings |
| `enumerate <domain>` | Subdomain enumeration only |
| `probe <targets>` | HTTP probe targets for live hosts |
| `nuclei <targets>` | Run Nuclei vulnerability scan |
| `nuclei-scan <domain>` | Run Nuclei on a previously enumerated domain |
| `ai-wordlist <domain>` | Generate AI-powered wordlist |
| `origin-ips <domain>` | Find origin IPs behind CDN/WAF |
| `list-scans` | List all scans with status |
| `check-tools` | Verify tool availability |

### Scan Command Options

| Option | Description |
|--------|-------------|
| `--ai` | Enable AI wordlist generation |
| `--ai-triage` | Enable AI vulnerability triage + GAU URL filtering |
| `--passive-only` | Skip active enumeration (no GAU) |
| `--no-nuclei` | Skip vulnerability scanning |
| `-o, --output` | Custom output directory |
| `-r, --rate-limit` | Requests per second |
| `-q, --quiet` | Minimal output |

> **Note:** GAU historical URL mining runs automatically in Phase 2 (parallel with HTTP probing). Use `--ai-triage` for AI-powered URL filtering.

### Global Options

| Option | Description |
|--------|-------------|
| `--config <path>` | Custom config file |
| `--debug` | Enable debug logging |
| `--json` | JSON log output |
| `-o, --output` | Output file/directory |

---

## Pipeline Phases

### Phase 1: Subdomain Enumeration

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SUBDOMAIN ENUMERATION                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. Passive Enumeration (subfinder)                                         │
│     └── 10+ sources: VirusTotal, Shodan, SecurityTrails...                  │
│                                                                             │
│  2. Certificate Transparency (crt.sh)                                       │
│     └── SSL certificate logs                                                │
│                                                                             │
│  3. DNS Brute-force (puredns)                                               │
│     └── Wordlist + wildcard filtering                                       │
│                                                                             │
│  4. Permutation Generation (alterx)                                         │
│     └── Pattern-based mutations: dev-api, api-v2, etc.                      │
│                                                                             │
│  5. AI Wordlist Generation (Ollama/OpenAI)                                  │
│     └── Context-aware subdomain suggestions                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Features:**
- Deduplication across all sources
- Scope validation (blocks out-of-scope subdomains)
- Progress checkpointing

### Phase 2: Validation Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            VALIDATION PIPELINE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. DNS Resolution (dnsx)                                                   │
│     ├── A, AAAA, CNAME, MX, NS records                                      │
│     └── Filters non-resolving subdomains                                    │
│                                                                             │
│  2. Port Scanning (naabu)                                                   │
│     ├── Common web ports: 80, 443, 8080, 8443...                            │
│     └── Scope-validated targets only                                        │
│                                                                             │
│  PARALLEL EXECUTION:                                                        │
│  ├── HTTP Probing (httpx)                                                   │
│  │   ├── Status codes, titles, technologies                                 │
│  │   └── CDN detection, favicon hashing                                     │
│  │                                                                          │
│  ├── Subdomain Takeover Detection (subjack)                                 │
│  │   ├── CNAME fingerprint matching                                         │
│  │   └── Checks GitHub, Heroku, AWS, Azure, etc.                            │
│  │                                                                          │
│  └── GAU Historical URL Mining (automatic)                                  │
│      ├── Mines: Wayback, OTX, URLScan                                       │
│      ├── Categorizes by vulnerability type                                  │
│      └── Generates gau_findings.html                                        │
│                                                                             │
│  3. Screenshot Capture (gowitness)                                          │
│     ├── Captures screenshots of live hosts                                  │
│     └── Generates screenshots_gallery.html                                  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Features:**
- IPv4 and IPv6 support
- CDN/WAF detection
- Technology fingerprinting
- Parallel execution for speed

### Phase 3: Vulnerability Scanning

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          VULNERABILITY SCANNING                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Nuclei Batched Scanning                                                    │
│     ├── Checkpoint/resume support (recovers from interruption)              │
│     ├── Smart host filtering (skip 404/500+ hosts)                          │
│     ├── Severity filtering: critical, high, medium                          │
│     ├── Excluded tags: fuzz, dos, intrusive, oob                            │
│     └── Adaptive rate limiting                                              │
│                                                                             │
│  Smart Host Filtering                                                       │
│     ├── Skip 404 hosts (no content)                                         │
│     ├── Skip 5xx hosts (unreliable)                                         │
│     └── Keep 401/403 hosts (auth bypass potential)                          │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Key Features:**
- Per-host rate limiting
- WAF detection and backoff
- Finding deduplication
- IP clustering for WAF evasion

### Phase 4: Analysis

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                ANALYSIS                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. Origin IP Discovery (Shodan + SecurityTrails)                           │
│     ├── SSL Certificate CN matching (Shodan)                                │
│     ├── Favicon hash correlation (Shodan)                                   │
│     ├── Historical DNS records (SecurityTrails)                             │
│     └── Finds real IPs behind CDN/WAF                                       │
│                                                                             │
│  2. Origin IP Aggressive Scan (automatic when origins found)                │
│     ├── Nuclei scan directly against origin IPs bypassing WAF               │
│     ├── Uses Host header spoofing to reach target domain                    │
│     ├── Aggressive templates: CVEs 2023-2025, RCE, LFI, SSRF, SQLi, XSS     │
│     ├── Detects version disclosure hidden by CDN (nginx, PHP, etc.)         │
│     └── Higher rate limits (150 rps) - no CDN throttling                    │
│                                                                             │
│  3. AI Vulnerability Triage (--ai-triage flag)                              │
│     ├── Risk-prioritized analysis of findings                               │
│     ├── Attack chain identification                                         │
│     ├── Executive summary generation                                        │
│     ├── Remediation priorities                                              │
│     └── AI-powered GAU URL filtering:                                       │
│         • Ranks by exploit likelihood (RCE > SSRF > LFI)                    │
│         • Deduplicates similar endpoints                                    │
│         • Validates if URLs still exist                                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**URL Categorization (GAU - runs in Phase 2):**
| Category | Pattern Examples | Priority |
|----------|-----------------|----------|
| RCE Candidates | `cmd=`, `exec=`, `shell=` | 1 (Highest) |
| SSRF Candidates | `url=`, `redirect=`, `callback=` | 2 |
| LFI Candidates | `file=`, `path=`, `template=` | 3 |
| SQLi Candidates | `id=`, `user=`, `search=` | 4 |
| Auth Endpoints | oauth, saml, token | 5 |
| Debug Paths | `/debug/`, `/trace/`, phpinfo | 6 |
| Sensitive Files | `.env`, `.conf`, `.sql` | 7 |
| API Endpoints | `/api/`, `/graphql/` | 8 |

---

## Core Components

### 1. Configuration (config.py)

```python
from reconductor.core.config import get_settings

settings = get_settings()
print(settings.app_name)          # "ReconDuctor"
print(settings.max_workers)       # 20
print(settings.scope)             # ScopeConfig
print(settings.nuclei)            # NucleiConfig
print(settings.llm)               # LLMConfig
```

**Configuration Hierarchy:**
1. Default values (in code)
2. YAML config file (`config/default.yaml`)
3. Environment variables (`RECONDUCTOR_*`)

### 2. Scope Validator (scope.py)

```python
from reconductor.core.scope import ScopeValidator
from reconductor.core.config import ScopeConfig

config = ScopeConfig(
    allowed_domains=["example.com"],
    blocked_patterns=[r".*\.internal\..*"],
)
validator = ScopeValidator(config)

# Check single target
validator.is_in_scope("api.example.com")      # True
validator.is_in_scope("api.other.com")        # False
validator.is_in_scope("internal.example.com") # False (blocked)

# Batch validation
valid, rejected = validator.validate_batch(targets)
```

**Scope Types:**
- Domain-based (subdomains of allowed domains)
- ASN-based (IP belongs to allowed ASN)
- IP range-based (CIDR notation)
- Pattern blocking (regex exclusions)

### 3. Adaptive Rate Limiter (rate_limiter.py)

```python
from reconductor.core.rate_limiter import AdaptiveRateLimiter

limiter = AdaptiveRateLimiter(initial_rate=30.0)

# Record responses
limiter.record_response("1.2.3.4", 200)       # Success
limiter.record_response("1.2.3.4", 429)       # Rate limited -> backs off
limiter.record_response("1.2.3.4", 200, body="Access Denied by Cloudflare")

# Get current rate for IP
rate = limiter.get_rate("1.2.3.4")            # Returns adjusted rate
```

**WAF Detection:**
- Status codes: 429, 403, 503, 406, 418, 520-524
- Body patterns: Cloudflare, Incapsula, Akamai, etc.
- Automatic backoff and recovery

### 4. Checkpoint System (checkpoint.py)

```python
from reconductor.core.checkpoint import CheckpointManager

manager = CheckpointManager(db_path)

# Save progress
await manager.save_subdomains(scan_id, subdomains)
await manager.save_hosts(scan_id, hosts)
await manager.update_phase(scan_id, ScanPhase.VALIDATION)

# Resume scan
scan = await manager.load_scan(scan_id)
subdomains = await manager.load_subdomains(scan_id)
```

### 5. Tool Executor (executor.py)

```python
from reconductor.utils.executor import get_executor, ToolExecutor

executor = get_executor()

# Run a command
result = await executor.run(
    ["subfinder", "-d", "example.com", "-silent"],
    timeout=300,
)

if result.success:
    print(result.stdout)
else:
    print(f"Error: {result.error}")

# Check tool availability
ToolExecutor.check_tool_available("subfinder")  # True/False
ToolExecutor.get_tool_path("httpx")             # /home/user/go/bin/httpx
```

**Security Features:**
- Command injection prevention
- Smart header value handling
- Go tool path prioritization

---

## Module Details

### Passive Enumeration (passive.py)

```python
from reconductor.modules.subdomain.passive import PassiveEnumerationPipeline

pipeline = PassiveEnumerationPipeline()
subdomains = await pipeline.enumerate("example.com", use_crtsh=True)

# Results include source attribution
for sub in subdomains:
    print(f"{sub.name} - Source: {sub.source}")
```

### Puredns Wrapper (puredns_wrapper.py)

```python
from reconductor.modules.subdomain.puredns_wrapper import PurednsWrapper

puredns = PurednsWrapper()

# Brute-force with wildcard filtering
result = await puredns.bruteforce(
    domain="example.com",
    wordlist=Path("wordlists/subdomains.txt"),
)

print(f"Valid: {len(result.valid_subdomains)}")
print(f"Wildcards detected: {result.wildcard_roots}")
```

### HTTP Prober (http_probe.py)

```python
from reconductor.modules.validation.http_probe import HttpProber

prober = HttpProber()
hosts = await prober.probe(
    targets=["api.example.com", "www.example.com"],
    threads=50,
    rate_limit=150,
)

for host in hosts:
    print(f"{host.hostname}: {host.status_code} - {host.title}")
    print(f"  Technologies: {host.technologies}")
    print(f"  CDN: {host.cdn_provider}")
```

### Nuclei Manager (nuclei_manager.py)

```python
from reconductor.modules.scanning.nuclei_manager import NucleiManager

manager = NucleiManager()
findings = await manager.scan(
    targets=["https://example.com"],
    severity=["critical", "high"],
    rate_limit=100,
)

for finding in findings:
    print(f"[{finding.severity}] {finding.name}")
    print(f"  URL: {finding.matched_url}")
    print(f"  Template: {finding.template_id}")
```

### LLM Client (llm_client.py)

```python
from reconductor.modules.ai.llm_client import LLMClient
from reconductor.core.config import LLMConfig, LLMProvider

# Use Ollama (local, free, private)
config = LLMConfig(
    primary_provider=LLMProvider.OLLAMA,
    primary_model="llama3.2",
)
client = LLMClient(config)

# Generate wordlist suggestions
response = await client.generate(
    "Generate 20 subdomain prefixes for a tech company"
)
```

---

## Configuration

### Default Configuration (config/default.yaml)

```yaml
# General settings
log_level: INFO
debug: false

# Scope
scope:
  allowed_domains:
    - example.com
  blocked_patterns:
    - ".*\\.internal\\..*"

# Rate limiting
rate_limit:
  initial_rate: 30.0
  min_rate: 1.0
  max_rate: 100.0

# Nuclei settings
nuclei:
  exclude_tags:
    - fuzz
    - dos
    - intrusive
    - oob
    - oast
  severity:
    - critical
    - high
    - medium
  max_workers: 10

# LLM settings
llm:
  primary_provider: ollama
  primary_model: llama3.2
```

### Environment Variables

```bash
# Override settings via environment
export RECONDUCTOR_DEBUG=true
export RECONDUCTOR_LOG_LEVEL=DEBUG
export RECONDUCTOR_MAX_WORKERS=30

# API keys (use SecretStr - won't be logged)
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Security Features

### 1. Command Injection Prevention

```python
# executor.py - sanitize_command()
# Blocks: ; & | ` $ \n \r \x00
# Smart handling for HTTP headers (allows ; in Accept headers)

# Example - this would be blocked:
# "example.com; rm -rf /" -> CommandInjectionError
```

### 2. Secure Temp Files

```python
# tempfiles.py - TempFileManager
# Uses tempfile.mkstemp() for atomic creation
# Random names: reconductor_a7bf9c2e_targets.txt
# Automatic cleanup via atexit handler
```

### 3. Credential Protection

```python
# config.py - SecretStr for API keys
# Won't appear in logs or repr()
api_key: Optional[SecretStr] = Field(default=None, repr=False)

# Safe retrieval
key = config.get_api_key()  # Returns string or None
```

### 4. TLS Support for Ollama

```python
# llm_client.py - OllamaProvider
OllamaProvider(
    api_base="https://ollama.internal:11434",
    verify_ssl=True,           # Enable verification
    ssl_cert="/path/to/ca.pem" # Custom CA certificate
)
```

### 5. Scope Enforcement

```python
# All targets validated before scanning
# Blocks out-of-scope subdomains
# Prevents DNS rebinding (IP re-validation)
```

---

## Future Improvements

### HIGH Priority (Recommended for Field Use)

#### 1. User-Agent Rotation
**Current:** Static User-Agent string
**Improvement:**
```python
# Implement UA rotation pool
UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36...",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36...",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)...",
]

def get_random_ua() -> str:
    return random.choice(UA_POOL)
```

#### 2. Improved Rate Limiter Jitter
**Current:** Uniform jitter 0.5-2.0x
**Improvement:**
```python
# Use log-normal distribution for more realistic patterns
import numpy as np

def human_like_delay(base_delay: float) -> float:
    # Log-normal distribution mimics human behavior
    jitter = np.random.lognormal(0, 0.5)
    return base_delay * min(jitter, 3.0)  # Cap at 3x
```

#### 3. TLS Fingerprint Rotation (JA3/JA4)
**Current:** Python httpx default fingerprint
**Improvement:**
```python
# Option 1: Use curl-impersonate for critical probes
cmd = [
    "curl-impersonate-chrome",
    "--ciphers", "TLS_AES_128_GCM_SHA256,...",
    url
]

# Option 2: Use tls-client library
from tls_client import Session
session = Session(client_identifier="chrome_120")
```

#### 4. Enhanced Scope URL Parsing
**Current:** Basic string splitting
**Improvement:**
```python
from urllib.parse import urlparse
import idna

def normalize_target(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"https://{target}")
    hostname = parsed.hostname or target

    # Handle punycode
    try:
        hostname = idna.decode(hostname)
    except:
        pass

    # Normalize
    return hostname.lower().rstrip(".")
```

#### 5. DNS Rebinding Protection
**Current:** Single validation at discovery
**Improvement:**
```python
async def validate_ip_before_request(hostname: str, expected_ips: set[str]) -> bool:
    """Re-validate IP hasn't changed before each request."""
    current_ips = await resolve_hostname(hostname)
    if not current_ips.intersection(expected_ips):
        logger.warning(f"DNS rebinding detected for {hostname}")
        return False
    return True
```

#### 6. Complete Nuclei Exclusion List
**Current:** Partial exclusion list
**Improvement:**
```yaml
nuclei:
  exclude_tags:
    - fuzz
    - fuzzing
    - dos
    - intrusive
    - sqli
    - xss
    - rce
    - bruteforce
    - oob
    - oast
    - interactsh
    - ssrf
    - redirect
    - timing
    - blind
    - exploit
    - dangerous
    - crlf
    - xxe
```

### MEDIUM Priority

#### 7. Proxy Rotation
```python
class ProxyPool:
    def __init__(self, proxies: list[str]):
        self.proxies = proxies
        self.current = 0
        self.health = {p: True for p in proxies}

    def get_next(self) -> Optional[str]:
        healthy = [p for p in self.proxies if self.health[p]]
        if not healthy:
            return None
        proxy = healthy[self.current % len(healthy)]
        self.current += 1
        return proxy

    def mark_unhealthy(self, proxy: str):
        self.health[proxy] = False
```

#### 8. Request Header Randomization
```python
def randomize_headers() -> dict[str, str]:
    return {
        "Accept": random.choice([
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        ]),
        "Accept-Language": random.choice([
            "en-US,en;q=0.9",
            "en-GB,en;q=0.9",
            "en-US,en;q=0.5",
        ]),
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": random.choice(["1", None]),
        "Upgrade-Insecure-Requests": "1",
    }
```

#### 9. Output Format: SARIF
```python
def to_sarif(findings: list[Finding]) -> dict:
    """Export findings in SARIF format for CI/CD integration."""
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ReconDuctor", "version": "2.0"}},
            "results": [finding_to_sarif(f) for f in findings]
        }]
    }
```

#### 10. Encrypted Checkpoint Data
```python
from cryptography.fernet import Fernet

class EncryptedCheckpointManager(CheckpointManager):
    def __init__(self, db_path: Path, key: bytes):
        super().__init__(db_path)
        self.cipher = Fernet(key)

    def _encrypt(self, data: str) -> bytes:
        return self.cipher.encrypt(data.encode())

    def _decrypt(self, data: bytes) -> str:
        return self.cipher.decrypt(data).decode()
```

### LOW Priority (Polish)

- Version pinning for external tools
- Plugin architecture for custom enumeration sources
- Distributed state management (Redis)
- Progress persistence for subfinder mid-enumeration
- Hostname normalization before comparison
- IPv6 handling audit across all modules

---

## Current Status

| Category | Status |
|----------|--------|
| **Build** | Complete |
| **Tests** | 19/19 passing |
| **Critical Security** | All 5 issues fixed |
| **Documentation** | Complete |
| **Field Ready** | Yes (for CTF/Bug Bounty) |
| **Professional Pentest** | After HIGH priority fixes |

---

## License

MIT License

---

## Quick Reference

```bash
# Activate environment
cd /home/kali/projects/reconductor/reconductor-v2
source venv/bin/activate

# Check tools
reconductor check-tools

# Full scan
reconductor scan example.com -o ./output

# Passive only
reconductor scan example.com --passive-only

# Probe targets
reconductor probe targets.txt

# Resume scan
reconductor resume example.com

# Run tests
python -m pytest tests/ -v
```
