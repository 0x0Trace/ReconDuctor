# Usage Guide

Practical examples and common use cases for Reconductor.

---

## Table of Contents

- [Basic Usage](#basic-usage)
- [Operation Modes](#operation-modes)
- [Common Workflows](#common-workflows)
- [Advanced Usage](#advanced-usage)
- [API/Webhook Usage](#apiwebhook-usage)
- [Monitoring and Debugging](#monitoring-and-debugging)
- [Best Practices](#best-practices)

---

## Basic Usage

### Starting n8n

Before using Reconductor, ensure n8n is running:

```bash
# Start n8n
n8n start

# Or run in background
nohup n8n start > /tmp/n8n.log 2>&1 &

# Verify n8n is running
curl http://localhost:5678/healthz
```

### Running the Orchestrator

```bash
# Make executable (first time only)
chmod +x recon_orchestrator.py

# Run the orchestrator
./recon_orchestrator.py

# Or with Python explicitly
python3 recon_orchestrator.py
```

### Interactive Menu

The orchestrator presents an interactive menu:

```
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

Select Operation Mode:

  [1] Full Scan (Phase 1 -> 2 -> 3)
      Complete pipeline: Discovery + parallel vulnerability scan
      Best for: New targets, full reconnaissance

  [2] Discovery Only (Phase 1 -> 2)
      Subdomain enumeration + live host validation
      Run vulnerability scanning later with option 3

  [3] Vuln Scan Only (Phase 3 Parallel) [FAST]
      Tech-based nuclei scan with parallel workers
      Requires existing Phase 2 data
      Time: ~10-15 min for 300 hosts

Select mode (1/2/3) [1]:
```

---

## Operation Modes

### Mode 1: Full Scan (Recommended for New Targets)

**Use Case**: Complete reconnaissance from scratch.

**Workflow**: Phase 1 → Phase 2 → Phase 3

**Example**:

```bash
./recon_orchestrator.py

# Select: 1
# Enter domain: example.com
# Confirm: yes

# Wait for completion (30-60 minutes for large targets)
```

**What Happens**:
1. Phase 1 discovers subdomains (2-5 minutes)
2. Phase 2 validates live hosts (5-10 minutes)
3. Phase 3 scans for vulnerabilities (10-45 minutes)
4. Reports generated in `/tmp/recon/example.com/`

**Output Files**:
- `phase2_data.json` - Live hosts with technology data
- `phase2_report.html` - Host validation report
- `phase3_data.json` - All vulnerability findings
- `phase3_report.html` - Vulnerability report
- `phase3_all_results.jsonl` - Raw nuclei results

---

### Mode 2: Discovery Only (Fast Enumeration)

**Use Case**: Quick discovery without vulnerability scanning.

**Workflow**: Phase 1 → Phase 2

**Example**:

```bash
./recon_orchestrator.py

# Select: 2
# Enter domain: example.com
# Confirm: yes

# Wait for completion (5-15 minutes)
```

**Why Use This**:
- Quick asset discovery
- Want to review targets before scanning
- Save Phase 3 for later
- Testing/validation purposes

**Next Steps**:
Run Mode 3 later to perform vulnerability scanning on discovered hosts.

---

### Mode 3: Vulnerability Scan Only (Fastest)

**Use Case**: Run nuclei scan on previously discovered hosts.

**Workflow**: Phase 3 (requires Phase 2 data)

**Example**:

```bash
./recon_orchestrator.py

# Select: 3
# List of available domains appears:
#   [1] example.com (42 live hosts)
#   [2] target.com (128 live hosts)
#   [3] testing.net (15 live hosts)

# Select: 1 (or enter "example.com")
# Confirm: yes

# Wait for completion (10-15 minutes for 300 hosts)
```

**Why Use This**:
- Re-scan targets with updated nuclei templates
- Previously ran Mode 2, now want vulnerability data
- Faster than full scan (skips discovery)
- Test different nuclei configurations

---

## Common Workflows

### Workflow 1: New Target Assessment

**Scenario**: You want to assess a new target completely.

```bash
# Step 1: Start n8n
n8n start

# Step 2: Run full scan
./recon_orchestrator.py
# Select: 1 (Full Scan)
# Enter: newtarget.com

# Step 3: Wait for completion
# Monitor progress in /tmp/recon/newtarget.com/

# Step 4: Review reports
firefox /tmp/recon/newtarget.com/phase2_report.html
firefox /tmp/recon/newtarget.com/phase3_report.html
```

---

### Workflow 2: Quick Discovery

**Scenario**: You need to quickly find all subdomains and live hosts.

```bash
# Run discovery only
./recon_orchestrator.py
# Select: 2 (Discovery Only)
# Enter: target.com

# Check results
cat /tmp/recon/target.com/phase2_summary.txt
jq '.statistics' /tmp/recon/target.com/phase2_data.json
```

---

### Workflow 3: Scheduled Rescans

**Scenario**: Periodically rescan targets with updated templates.

```bash
# Update nuclei templates first
nuclei -update-templates

# Rescan existing target
./recon_orchestrator.py
# Select: 3 (Vuln Scan Only)
# Select from list of existing domains

# Compare results with previous scans
diff /tmp/recon/target.com/phase3_data.json /backup/old_scan.json
```

---

### Workflow 4: Bug Bounty Workflow

**Scenario**: Complete bug bounty reconnaissance.

```bash
# Day 1: Full discovery
./recon_orchestrator.py
# Mode 1: Full Scan
# Target: bugbounty.com

# Review critical/high findings
jq '.findings[] | select(.severity=="critical" or .severity=="high")' \
  /tmp/recon/bugbounty.com/phase3_data.json

# Day 2+: Periodic rescans with updated templates
./recon_orchestrator.py
# Mode 3: Vuln Scan Only
# Select: bugbounty.com
```

---

## Advanced Usage

### Scanning Multiple Domains

Create a batch script:

```bash
#!/bin/bash
# batch-scan.sh - Scan multiple domains

DOMAINS=(
  "target1.com"
  "target2.com"
  "target3.com"
)

for domain in "${DOMAINS[@]}"; do
  echo "Starting scan for: $domain"

  # Trigger via webhook (non-interactive)
  curl -X POST http://localhost:5678/webhook/recon-phase1 \
    -H "Content-Type: application/json" \
    -d "{\"domain\": \"$domain\"}"

  # Wait 30 minutes between scans
  sleep 1800
done
```

---

### Custom Timeouts

For very large targets, increase timeouts:

```python
# Edit recon_orchestrator.py
PHASE2_TIMEOUT = 1800  # 30 minutes
PHASE3_TIMEOUT = 3600  # 60 minutes
```

---

### Filtering Results

Extract specific findings:

```bash
# All critical vulnerabilities
jq '.findings[] | select(.severity=="critical")' \
  /tmp/recon/example.com/phase3_data.json

# All CVEs found
jq '.findings[] | select(.cve != null) | {host, cve, severity}' \
  /tmp/recon/example.com/phase3_data.json

# Count by severity
jq '.stats.findings' /tmp/recon/example.com/phase3_data.json

# All findings for specific host
jq '.findings[] | select(.host | contains("api.example.com"))' \
  /tmp/recon/example.com/phase3_data.json
```

---

### Exporting Results

```bash
# Export to CSV
jq -r '.findings[] | [.host, .severity, .name, .matched_at] | @csv' \
  /tmp/recon/example.com/phase3_data.json > findings.csv

# Export critical findings to JSON
jq '.findings[] | select(.severity=="critical")' \
  /tmp/recon/example.com/phase3_data.json > critical.json

# Generate summary report
jq '{
  domain: .domain,
  total_hosts: .stats.hosts,
  total_findings: .stats.findings.total,
  critical: .stats.findings.critical,
  high: .stats.findings.high
}' /tmp/recon/example.com/phase3_data.json
```

---

## API/Webhook Usage

### Trigger Phase 1 via Webhook

```bash
# Basic trigger
curl -X POST http://localhost:5678/webhook/recon-phase1 \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# With custom parameters (if workflow supports)
curl -X POST http://localhost:5678/webhook/recon-phase1 \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "recursive": true,
    "sources": "crtsh,virustotal"
  }'
```

### Trigger Phase 3 via Webhook

```bash
# Requires Phase 2 data to exist
curl -X POST http://localhost:5678/webhook/recon-phase3-parallel \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Check n8n Workflow Status

```bash
# Health check
curl http://localhost:5678/healthz

# List active workflows (requires auth)
curl http://localhost:5678/api/v1/workflows \
  -H "X-N8N-API-KEY: your-api-key"
```

---

## Monitoring and Debugging

### Monitor Phase 3 Worker Progress

```bash
# Watch marker files (completion indicators)
watch -n 2 'ls -la /tmp/phase3_done_*_worker_*.marker 2>/dev/null'

# Count active nuclei processes
watch -n 1 'ps aux | grep nuclei | grep -v grep | wc -l'

# Check individual worker status
for i in 1 2 3 4 5; do
  echo "Worker $i: $(cat /tmp/phase3_done_*_worker_$i.marker 2>/dev/null || echo 'running...')"
done
```

### Check Output Files in Real-Time

```bash
# Watch Phase 2 progress
watch -n 5 'ls -lh /tmp/recon/example.com/'

# Monitor Phase 3 JSONL size
watch -n 5 'du -h /tmp/recon/example.com/phase3_all_results.jsonl'

# Count findings as they're discovered
watch -n 10 'wc -l /tmp/phase3_results_*_worker_*.jsonl | tail -1'
```

### View n8n Execution Logs

```bash
# Tail n8n logs
tail -f ~/.n8n/logs/n8n.log

# View recent workflow executions in n8n UI
# Open: http://localhost:5678/workflows
# Click on workflow → "Executions" tab
```

### Debug JSONL Output

```bash
# Validate JSONL format
jq . /tmp/recon/example.com/phase3_all_results.jsonl > /dev/null
echo "Valid: $?"

# Count total lines
wc -l /tmp/recon/example.com/phase3_all_results.jsonl

# View first 5 entries
head -5 /tmp/recon/example.com/phase3_all_results.jsonl | jq .

# Check for entries with severity
grep -c '"severity"' /tmp/recon/example.com/phase3_all_results.jsonl

# Find all unique severities
jq -r '.info.severity' /tmp/recon/example.com/phase3_all_results.jsonl | sort -u
```

---

## Best Practices

### 1. Always Update Nuclei Templates

```bash
# Update before scanning
nuclei -update-templates

# Check template version
nuclei -version
nuclei -templates-version
```

### 2. Review Phase 2 Before Phase 3

```bash
# Check host count
jq '.statistics.total' /tmp/recon/example.com/phase2_data.json

# Review technologies
jq '.statistics.technologies' /tmp/recon/example.com/phase2_data.json

# If too many hosts (500+), consider:
# - Filtering by technology
# - Running in smaller batches
# - Increasing workers (edit workflow)
```

### 3. Backup Results

```bash
# Create timestamped backup
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
cp -r /tmp/recon/example.com /backup/recon_${TIMESTAMP}_example.com
```

### 4. Clean Up Temporary Files

```bash
# Remove worker temp files after Phase 3 completes
rm -f /tmp/phase3_targets_*_worker_*.txt
rm -f /tmp/phase3_results_*_worker_*.jsonl
rm -f /tmp/phase3_done_*_worker_*.marker
```

### 5. Rate Limit Considerations

For sensitive targets:

```bash
# Edit Phase 3 Worker workflow in n8n
# Reduce rate limit: -rl 5 (default is 15)
# Reduce bulk size: -bs 1 (default is 2)
# Increase timeout: -timeout 15 (default is 8)
```

### 6. Monitor Resource Usage

```bash
# Watch CPU/memory during scans
htop

# Monitor disk space
df -h /tmp

# Check network usage
iftop
```

---

## Example Scenarios

### Scenario 1: Large Target (1000+ Subdomains)

```bash
# Use discovery first to assess scope
./recon_orchestrator.py  # Mode 2

# Check subdomain count
jq '.statistics.total' /tmp/recon/largetarget.com/phase2_data.json

# If 500+, run Phase 3 later during off-hours
# Consider splitting by technology or increasing timeout
```

### Scenario 2: Quick Triage

```bash
# Fast discovery only
./recon_orchestrator.py  # Mode 2

# Review live hosts
cat /tmp/recon/target.com/phase2_summary.txt

# If interesting, run full scan
./recon_orchestrator.py  # Mode 3
```

### Scenario 3: Continuous Monitoring

```bash
# Setup cron job for weekly rescans
crontab -e

# Add (runs every Sunday at 2 AM):
0 2 * * 0 /path/to/recon_orchestrator.py --mode 3 --domain example.com
```

---

## Troubleshooting Common Issues

For detailed troubleshooting, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

**Quick Fixes**:

```bash
# n8n not responding
pkill -f n8n
n8n start

# Workers not completing
# Check logs: ~/.n8n/logs/n8n.log
# Check marker files: ls /tmp/phase3_done_*

# No results in report
# Verify JSONL file exists and has content
wc -l /tmp/recon/example.com/phase3_all_results.jsonl
```

---

## Next Steps

- **Configuration**: See [CONFIGURATION.md](CONFIGURATION.md) for customization options
- **Architecture**: See [WORKFLOWS.md](WORKFLOWS.md) for workflow details
- **Troubleshooting**: See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for issue resolution

---

**Last Updated**: 2025-12-11
