# ReconDuctor v2 - Usage Guide

This guide provides detailed usage examples and workflows for ReconDuctor v2.

## Table of Contents
- [Quick Start](#quick-start)
- [Scanning Workflows](#scanning-workflows)
- [Managing Scans](#managing-scans)
- [AI Features](#ai-features)
- [Battle Plan](#battle-plan)
- [Output Analysis](#output-analysis)
- [Advanced Usage](#advanced-usage)

---

## Quick Start

### 1. Verify Installation

```bash
# Check all required tools are installed
reconductor check-tools
```

Expected output:
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
```

### 2. Your First Scan

```bash
# Basic full scan
reconductor scan example.com

# Watch the progress in real-time
# Phase 1: Enumeration -> Phase 2: Validation -> Phase 3: Scanning -> Phase 4: Analysis
```

### 3. View Results

```bash
# Open the HTML report
firefox output/example.com/report.html

# Quick summary
cat output/example.com/findings_summary.txt
```

---

## Scanning Workflows

### Workflow 1: Quick Reconnaissance (5-10 min)

For fast initial assessment:

```bash
reconductor scan target.com --passive-only
```

What this does:
- Passive subdomain enumeration only (no DNS brute-force)
- No GAU historical URL mining
- Fast results for initial scope understanding

Output:
- `subdomains.txt` - All discovered subdomains
- `subdomains_all.md` - Formatted list

### Workflow 2: Standard Assessment (30-60 min)

For typical security assessments:

```bash
reconductor scan target.com
```

What this does:
- Full 4-phase pipeline
- Passive + active enumeration
- HTTP probing with technology detection
- Port scanning on non-standard ports
- Vulnerability scanning with Nuclei
- Screenshot capture
- Historical URL mining (GAU)

### Workflow 3: Comprehensive Assessment with AI (1-2 hours)

For thorough assessments with AI analysis:

```bash
reconductor scan target.com --ai --ai-triage
```

What this does:
- Everything in standard assessment PLUS:
- AI-generated wordlists based on target intelligence
- AI vulnerability triage with risk prioritization
- AI-filtered GAU URLs ranked by exploit likelihood
- Executive summary generation

Output includes:
- `triage_report.html` - AI-powered risk analysis

### Workflow 4: Enumeration Only (No Scanning)

For subdomain discovery without vulnerability testing:

```bash
reconductor scan target.com --no-nuclei
```

Useful when:
- Building target inventory
- Scope validation
- Preparing for manual testing

---

## Managing Scans

### List All Scans

View all completed and in-progress scans:

```bash
reconductor list-scans
```


Output columns:
- **Domain** - Target domain
- **Subdomains** - Total subdomains discovered
- **Live Hosts** - Hosts responding to HTTP
- **Findings** - Vulnerabilities found
- **Phase** - Current/completed phase
- **Date** - Scan date

### Resume Interrupted Scans

If a scan is interrupted (network issue, system crash, etc.):

```bash
# Continue from last checkpoint
reconductor continue target.com
```

The checkpoint system automatically saves progress after each phase.

### Add AI Analysis to Existing Scan

Run AI triage on completed scan:

```bash
reconductor triage target.com
```

Or when resuming:

```bash
reconductor continue target.com --ai-triage
```

---

## AI Features

### AI Wordlist Generation

Generate intelligent subdomain prefixes:

```bash
# During scan
reconductor scan target.com --ai

# Standalone
reconductor ai-wordlist target.com
```

The AI analyzes:
- Historical subdomains from CT logs
- Naming patterns (dev, staging, api, etc.)
- Technology stack indicators
- Industry-specific conventions

Example output:
```
Phase 1: Subdomain Enumeration
  [ok] Passive Enum     2184 (subfinder:501, crt.sh:1709, shodan:120)
  [ok] AI Wordlist      187 intelligent prefixes
  [ok] DNS Brute        +18 subdomains (found via AI wordlist!)
```

### AI Vulnerability Triage

Generate executive-ready reports:

```bash
reconductor scan target.com --ai-triage
```


The triage report includes:
- **Prioritized Risk Items** - Grouped by actual risk, not just severity
- **Evidence/PoC** - Proof of vulnerability
- **Exploit Details** - How to reproduce
- **Business Impact** - Real-world consequences
- **Attack Chain** - How vulnerabilities combine
- **Remediation** - Specific fix recommendations

### AI URL Filtering

When `--ai-triage` is enabled, GAU URLs are AI-filtered:

```bash
reconductor gau target.com --ai
```

URLs are ranked by exploit likelihood:
1. RCE/Command injection
2. SSRF/Open redirect
3. LFI/Path traversal
4. SQLi candidates
5. Auth endpoints
6. Debug paths
7. Sensitive files
8. API endpoints

---

## Battle Plan

After every scan completes, ReconDuctor generates an actionable **battle plan** in the `targets/` directory. This is your starting point for manual testing.

### What's Generated

```
output/target.com/targets/
├── next_steps.md        # START HERE - Prioritized action plan
├── fuzz_urls.txt        # URLs with parameters for fuzzing
├── sqli_candidates.txt  # SQLi injection points (id=, user=, order=)
├── ssrf_candidates.txt  # SSRF/redirect candidates (url=, redirect=)
├── lfi_candidates.txt   # LFI candidates (file=, path=, template=)
├── origin_ips.txt       # Origin IPs for WAF bypass
├── all_params.txt       # All discovered parameters
└── live_urls.txt        # All live host URLs
```

### Using the Battle Plan

#### Step 1: Read next_steps.md

```bash
cat output/target.com/targets/next_steps.md
```

This file contains:
- **Prioritized actions** based on what was found
- **Copy-paste commands** for each test type
- **Summary table** of all targets

Example output:
```markdown
# Next Steps - target.com

## Priority Actions

### 1. 🔴 Validate 3 CRITICAL findings
### 2. 🎯 Test 5 Origin IPs (WAF Bypass)
### 3. 💉 Test 12 SQLi Candidates
### 4. 🔗 Test 8 SSRF/Redirect Candidates
### 5. 🔨 Fuzz 45 URLs with Parameters

## Target Summary
| Category | Count | File |
|----------|-------|------|
| URLs with params | 45 | targets/fuzz_urls.txt |
| Origin IPs | 5 | targets/origin_ips.txt |
| SQLi candidates | 12 | targets/sqli_candidates.txt |
```

#### Step 2: Test SQLi Candidates

```bash
# With sqlmap (batch mode)
sqlmap -m output/target.com/targets/sqli_candidates.txt --batch --risk=2 --level=3

# Manual quick test
cat output/target.com/targets/sqli_candidates.txt | qsreplace "'" | httpx -silent -mc 500
```

#### Step 3: Test SSRF/Redirects

```bash
# Open redirect test
cat output/target.com/targets/ssrf_candidates.txt | qsreplace 'https://evil.com' | httpx -silent -location

# SSRF with Burp Collaborator
cat output/target.com/targets/ssrf_candidates.txt | qsreplace 'http://YOUR-COLLAB.burpcollaborator.net' | httpx -silent
```

#### Step 4: Fuzz Parameters

```bash
# XSS testing with dalfox
cat output/target.com/targets/fuzz_urls.txt | dalfox pipe --skip-bav

# General fuzzing with ffuf
cat output/target.com/targets/fuzz_urls.txt | qsreplace FUZZ | ffuf -u FUZZ -w /path/to/payloads.txt
```

#### Step 5: WAF Bypass via Origin IPs

```bash
# Test origin IPs respond
while read ip; do
  curl -sk -H 'Host: target.com' "https://$ip" | head -20
done < output/target.com/targets/origin_ips.txt

# Full scan on origin
nmap -sV -sC -p- -iL output/target.com/targets/origin_ips.txt -oA origin_scan

# Directory brute on origin
ffuf -u 'https://ORIGIN_IP/FUZZ' -H 'Host: target.com' -w wordlist.txt
```

#### Step 6: Content Discovery

```bash
# Directory bruteforce on all live hosts
feroxbuster -L output/target.com/targets/live_urls.txt -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Find hidden endpoints with katana
katana -list output/target.com/targets/live_urls.txt -d 3 -jc | tee discovered_endpoints.txt
```

#### Step 7: Parameter Discovery

```bash
# Use discovered params to find hidden parameters on other endpoints
arjun -i output/target.com/targets/live_urls.txt -w output/target.com/targets/all_params.txt
```

### Pro Tips

1. **Always start with `next_steps.md`** - it prioritizes what's most likely to yield results
2. **Origin IPs are gold** - WAF bypass can reveal hidden vulnerabilities
3. **Chain attacks** - SQLi on dev server might give creds for prod
4. **Validate manually** - automated tools miss context-dependent issues
5. **Check all params** - `all_params.txt` is useful for arjun and custom scripts

---

## Output Analysis

### HTML Reports

#### Main Report (`report.html`)


Contains:
- Severity breakdown chart
- All vulnerability findings
- CVSS scores and CVE references
- Remediation links
- Tags for filtering

#### GAU Findings (`gau_findings.html`)


Contains:
- Historical URLs categorized by type
- Parameter extraction
- Status code validation
- URL counts by category

#### Triage Report (`triage_report.html`)

AI-generated executive summary with:
- Risk-prioritized findings
- Attack chain analysis
- Business impact assessment
- Remediation priorities

#### Screenshots Gallery (`screenshots_gallery.html`)

Interactive gallery of all captured screenshots for visual assessment.

### JSON Files

For programmatic access:

```bash
# Parse findings
cat output/target.com/findings.json | jq '.[] | select(.severity == "critical")'

# Count hosts by status
cat output/target.com/hosts.json | jq '.[] | .status_code' | sort | uniq -c
```

### Text Files

For quick reference:

```bash
# All subdomains (one per line)
cat output/target.com/subdomains.txt

# Live hosts only
cat output/target.com/live_hosts.txt

# Findings summary
cat output/target.com/findings_summary.txt
```

---

## Advanced Usage

### Origin IP Discovery

Find real IPs behind CDN/WAF:

```bash
reconductor origin-ips target.com
```

Requires: `SHODAN_API_KEY` environment variable

**Real-world result:** In testing, origin IP bypass discovered **64 new findings** that were hidden behind WAF protection!

Uses:
- SSL Certificate CN matching
- Favicon hash correlation
- Historical DNS records

### Custom Rate Limiting

Adjust for different targets:

```bash
# Slower for sensitive targets
reconductor scan target.com --rate-limit 10

# Faster for authorized testing
reconductor scan target.com --rate-limit 100
```

### Selective Phase Execution

Start from a specific phase:

```bash
# Start from validation (skip enumeration)
reconductor scan target.com --phase 2

# Start from scanning (skip enum + validation)
reconductor scan target.com --phase 3
```

### Custom Output Directory

```bash
reconductor scan target.com -o /path/to/results
```

### Standalone Commands

Run individual components:

```bash
# Just enumerate subdomains
reconductor enumerate target.com

# Just probe HTTP
reconductor probe targets.txt

# Just run Nuclei
reconductor nuclei targets.txt

# Just run GAU
reconductor gau target.com

# GAU with AI filtering
reconductor gau target.com --ai
```

---

## Best Practices

### 1. Start Small

Begin with passive-only to understand scope:

```bash
reconductor scan target.com --passive-only
```

### 2. Review Before Full Scan

Check subdomains before vulnerability scanning:

```bash
reconductor scan target.com --no-nuclei
# Review output/target.com/subdomains.txt
# Then run nuclei separately if needed
```

### 3. Use AI for Important Assessments

AI features significantly improve results:

```bash
reconductor scan target.com --ai --ai-triage
```

### 4. Check Screenshots Early

Screenshots quickly reveal:
- Login pages
- Admin panels
- Error pages
- Technology stack

```bash
firefox output/target.com/screenshots_gallery.html
```

### 5. Don't Ignore GAU

Historical URLs often reveal:
- Forgotten endpoints
- Debug parameters
- Sensitive file paths
- API endpoints

```bash
firefox output/target.com/gau_findings.html
```

### 6. Try Origin IP Bypass

CDN/WAF protection may hide vulnerabilities:

```bash
reconductor origin-ips target.com
# Then scan discovered IPs directly
```

---

## Troubleshooting

### Scan Interrupted

```bash
reconductor continue target.com
```

### Missing Tools

```bash
reconductor check-tools
# Install any missing tools shown as [FAIL]
```

### Rate Limited

```bash
# Reduce rate
reconductor scan target.com --rate-limit 10
```

### AI Features Not Working

```bash
# Check environment variables
echo $ANTHROPIC_API_KEY
echo $OPENAI_API_KEY

# Or use Claude Code (no key needed)
# Set in config/local.yaml:
# llm:
#   primary_provider: claude_code
```

---


