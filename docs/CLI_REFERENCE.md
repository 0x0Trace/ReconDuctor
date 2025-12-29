# ReconDuctor v2 - CLI Command Reference

Complete command-line reference for all ReconDuctor commands and options.

## Global Options

| Option | Description |
|--------|-------------|
| `--version` | Show version and exit |
| `--help` | Show help message |

---

## Main Commands

### `scan` - Full Domain Scan

Run a complete reconnaissance scan on a target domain.

```bash
reconductor scan <domain> [OPTIONS]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `domain` | Target domain to scan (required) |

#### Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--output` | `-o` | `output/<domain>` | Output directory for results |
| `--phase` | `-p` | `0` | Start from specific phase (0=all phases) |
| `--passive-only` | | `false` | Only run passive enumeration (no DNS brute-force, no GAU) |
| `--no-nuclei` | | `false` | Skip vulnerability scanning |
| `--ai` | | `false` | Enable AI wordlist generation |
| `--ai-triage` | | `false` | Enable AI vulnerability triage and GAU URL filtering |
| `--rate-limit` | `-r` | `30` | Requests per second |
| `--quiet` | `-q` | `false` | Minimal output mode |

#### Examples

```bash
# Basic full scan
reconductor scan example.com

# Full scan with all AI features
reconductor scan example.com --ai --ai-triage

# Passive enumeration only
reconductor scan example.com --passive-only

# Skip vulnerability scanning
reconductor scan example.com --no-nuclei

# Custom output directory
reconductor scan example.com -o ./results/example

# Slower rate for sensitive targets
reconductor scan example.com --rate-limit 10
```

---

### `continue` - Resume Interrupted Scan

Continue a scan from the last checkpoint.

```bash
reconductor continue <domain> [OPTIONS]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `domain` | Domain of the scan to continue (required) |

#### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--no-nuclei` | `false` | Skip vulnerability scanning |
| `--ai-triage` | `false` | Run AI triage on findings |

#### Examples

```bash
# Continue from checkpoint
reconductor continue example.com

# Continue with AI triage
reconductor continue example.com --ai-triage

# Continue but skip nuclei
reconductor continue example.com --no-nuclei
```

---

### `enumerate` - Subdomain Enumeration

Run subdomain enumeration only.

```bash
reconductor enumerate <domain> [OPTIONS]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `domain` | Target domain (required) |

#### Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--output` | `-o` | `output/<domain>` | Output directory |
| `--passive-only` | | `false` | Only passive enumeration |
| `--ai` | | `false` | Enable AI wordlist generation |

#### Examples

```bash
# Full enumeration
reconductor enumerate example.com

# Passive only
reconductor enumerate example.com --passive-only

# With AI wordlist
reconductor enumerate example.com --ai
```

---

### `probe` - HTTP Probing

Probe a list of targets for HTTP responses.

```bash
reconductor probe <targets_file> [OPTIONS]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `targets_file` | File containing targets (one per line) |

#### Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--output` | `-o` | `./probe_results` | Output directory |
| `--rate-limit` | `-r` | `30` | Requests per second |

#### Examples

```bash
# Probe targets
reconductor probe targets.txt

# Custom output
reconductor probe targets.txt -o ./results
```

---

### `nuclei` - Vulnerability Scanning

Run Nuclei vulnerability scanning on targets.

```bash
reconductor nuclei <targets_file> [OPTIONS]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `targets_file` | File containing targets (one per line) |

#### Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--output` | `-o` | `./nuclei_results` | Output directory |
| `--rate-limit` | `-r` | `150` | Requests per second |

#### Examples

```bash
# Scan targets
reconductor nuclei live_hosts.txt

# Custom output
reconductor nuclei targets.txt -o ./vuln_results
```

---

### `triage` - AI Vulnerability Triage

Run AI analysis on existing scan findings.

```bash
reconductor triage <domain> [OPTIONS]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `domain` | Domain of existing scan (required) |

#### Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--output` | `-o` | `output/<domain>` | Output directory containing scan results |

#### Examples

```bash
# Run triage on existing scan
reconductor triage example.com

# Custom output location
reconductor triage example.com -o ./custom/path
```

---

### `gau` - Historical URL Mining

Run GAU to discover historical URLs.

```bash
reconductor gau <domain> [OPTIONS]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `domain` | Target domain (required) |

#### Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--output` | `-o` | `output/<domain>` | Output directory |
| `--ai` | | `false` | Use AI to filter and rank URLs |

#### Examples

```bash
# Run GAU
reconductor gau example.com

# With AI filtering
reconductor gau example.com --ai

# Custom output
reconductor gau example.com -o ./gau_results
```

---

### `ai-wordlist` - AI Wordlist Generation

Generate intelligent subdomain wordlist using AI.

```bash
reconductor ai-wordlist <domain> [OPTIONS]
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `domain` | Target domain (required) |

#### Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--output` | `-o` | `output/<domain>` | Output directory |

#### Examples

```bash
# Generate AI wordlist
reconductor ai-wordlist example.com
```

---

### `origin-ips` - Origin IP Discovery

Find origin IPs behind CDN/WAF using Shodan.

```bash
reconductor origin-ips <domain> [OPTIONS]
```

**Requires:** `SHODAN_API_KEY` environment variable

#### Arguments

| Argument | Description |
|----------|-------------|
| `domain` | Target domain (required) |

#### Options

| Option | Short | Default | Description |
|--------|-------|---------|-------------|
| `--output` | `-o` | `output/<domain>` | Output directory |

#### Examples

```bash
# Find origin IPs
export SHODAN_API_KEY="your-key"
reconductor origin-ips example.com
```

---

## Utility Commands

### `check-tools` - Verify Tool Availability

Check if all required external tools are installed.

```bash
reconductor check-tools
```

#### Output

```
Tool Availability:
  [ok] subfinder    - Passive subdomain enumeration
  [ok] httpx        - HTTP probing
  [ok] nuclei       - Vulnerability scanning
  [ok] naabu        - Port scanning
  [ok] dnsx         - DNS resolution
  [ok] puredns      - DNS bruteforce
  [ok] massdns      - Fast DNS resolver
  [ok] alterx       - Permutation generation
  [ok] gau          - Historical URL mining
  [ok] gowitness    - Screenshot capture
  [ok] subjack      - Subdomain takeover

All tools available!
```

---

### `list-scans` - List Completed Scans

Display all completed and in-progress scans.

```bash
reconductor list-scans
```

#### Output

Shows table with:
- Domain
- Subdomains count
- Live hosts count
- Findings count
- Phase status
- Date

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error |
| `2` | Invalid arguments |
| `3` | Tool not found |
| `4` | Permission denied |
| `5` | Network error |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SHODAN_API_KEY` | Shodan API key for origin IP discovery |
| `ANTHROPIC_API_KEY` | Anthropic Claude API key |
| `OPENAI_API_KEY` | OpenAI API key |
| `GEMINI_API_KEY` | Google Gemini API key |
| `GOOGLE_API_KEY` | Alternative Google API key |
| `GROQ_API_KEY` | Groq API key |

---

## Configuration File

Default: `config/default.yaml`
Local override: `config/local.yaml` (gitignored)

See `config/example.yaml` for a template with all options.

---

## Battle Plan Output

Every scan automatically generates a `targets/` directory with pentester-ready files:

| File | Description |
|------|-------------|
| `next_steps.md` | **START HERE** - Prioritized action plan with commands |
| `fuzz_urls.txt` | URLs with parameters for fuzzing |
| `sqli_candidates.txt` | SQLi injection points |
| `ssrf_candidates.txt` | SSRF/redirect candidates |
| `lfi_candidates.txt` | LFI/path traversal candidates |
| `origin_ips.txt` | Origin IPs for WAF bypass |
| `all_params.txt` | All discovered parameters |
| `live_urls.txt` | All live host URLs |

```bash
# Quick start after scan
cat output/target.com/targets/next_steps.md
```

---

## Quick Reference Card

```
# SCANNING
reconductor scan <domain>                 # Full scan
reconductor scan <domain> --ai --ai-triage # With all AI
reconductor scan <domain> --passive-only  # Passive only
reconductor scan <domain> --no-nuclei     # No vuln scan

# RESUMING
reconductor continue <domain>             # Resume scan
reconductor continue <domain> --ai-triage # Resume + AI

# INDIVIDUAL COMMANDS
reconductor enumerate <domain>            # Subdomain enum
reconductor probe <file>                  # HTTP probe
reconductor nuclei <file>                 # Vuln scan
reconductor triage <domain>               # AI triage
reconductor gau <domain> --ai             # Historical URLs
reconductor origin-ips <domain>           # CDN bypass

# UTILITY
reconductor check-tools                   # Verify tools
reconductor list-scans                    # Show all scans
reconductor --version                     # Version
reconductor --help                        # Help
```
