# Troubleshooting Guide

Common issues and their solutions for Reconductor.

---

## Table of Contents

- [Installation Issues](#installation-issues)
- [n8n Connection Issues](#n8n-connection-issues)
- [Workflow Execution Issues](#workflow-execution-issues)
- [Phase 1 Issues](#phase-1-issues)
- [Phase 2 Issues](#phase-2-issues)
- [Phase 3 Issues](#phase-3-issues)
- [Performance Issues](#performance-issues)
- [Output Issues](#output-issues)
- [Getting Help](#getting-help)

---

## Installation Issues

### Command Not Found: subfinder/httpx/dnsx/nuclei

**Symptom**: `bash: subfinder: command not found`

**Cause**: Go tools not in PATH

**Solution**:

```bash
# Check if tools are installed
ls ~/go/bin/

# Add Go bin to PATH
export PATH=$PATH:$HOME/go/bin

# Make permanent
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc

# Verify
which subfinder
```

---

### n8n Installation Fails

**Symptom**: `npm install -g n8n` fails with permission errors

**Solution**:

```bash
# Option 1: Use sudo (not recommended)
sudo npm install -g n8n

# Option 2: Configure npm for user-level installs (recommended)
mkdir ~/.npm-global
npm config set prefix '~/.npm-global'
echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

# Then install
npm install -g n8n
```

---

### Go Installation Issues

**Symptom**: `go: command not found`

**Solution**:

```bash
# Download and install Go
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

# Add to PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
source ~/.bashrc

# Verify
go version
```

---

## n8n Connection Issues

### Cannot Connect to n8n

**Symptom**: `Connection refused - is n8n running?`

**Diagnosis**:

```bash
# Check if n8n is running
ps aux | grep n8n

# Check if port 5678 is listening
netstat -tuln | grep 5678
# Or: ss -tuln | grep 5678

# Try to access n8n
curl http://localhost:5678/healthz
```

**Solutions**:

```bash
# Start n8n if not running
n8n start

# If port is in use by another process
lsof -i :5678
# Kill the process or change n8n port:
N8N_PORT=5679 n8n start

# Update orchestrator if port changed
# Edit recon_orchestrator.py:
# N8N_BASE_URL = "http://localhost:5679"
```

---

### n8n Starts But Immediately Exits

**Symptom**: n8n starts but process dies immediately

**Diagnosis**:

```bash
# Check n8n logs
cat ~/.n8n/logs/n8n.log

# Run n8n in foreground to see errors
n8n start
```

**Common Causes**:

1. **Port already in use**
   ```bash
   N8N_PORT=5679 n8n start
   ```

2. **Database corruption**
   ```bash
   # Backup and reset n8n database
   mv ~/.n8n/database.sqlite ~/.n8n/database.sqlite.bak
   n8n start
   # Note: This will delete all workflows! Re-import them.
   ```

3. **Permission issues**
   ```bash
   chmod -R 755 ~/.n8n
   ```

---

## Workflow Execution Issues

### Workflows Not Found in n8n

**Symptom**: Webhooks return 404

**Solution**:

```bash
# Check if workflows are imported
# Open n8n UI: http://localhost:5678
# Navigate to "Workflows" tab
# Ensure these workflows exist:
# - Recon Automation - Phase 1: Subdomain Enumeration
# - Recon Automation - Phase 2: Live Host Validation
# - Recon - Phase 3 Main Manager

# If missing, re-import JSON files
# Click "Workflows" → "Import from File"
```

---

### Workflows Not Active

**Symptom**: Webhook triggers but nothing happens

**Solution**:

```bash
# Open n8n UI: http://localhost:5678
# For each workflow:
# 1. Open the workflow
# 2. Check the toggle switch at top-right is "Active" (blue)
# 3. If not active, click to activate

# Phase 3 Worker should remain INACTIVE (spawned by Manager)
```

---

### Execution Timeout

**Symptom**: `Timeout after Xs - Phase may still be running`

**Solution**:

```bash
# Option 1: Increase timeout in orchestrator
# Edit recon_orchestrator.py:
PHASE2_TIMEOUT = 1800  # 30 minutes
PHASE3_TIMEOUT = 3600  # 60 minutes

# Option 2: Check if workflow is actually stuck
# Open n8n UI → Workflow → Executions tab
# Check latest execution status

# Option 3: Check output directory manually
ls -la /tmp/recon/example.com/
# Files may be there even if orchestrator timed out
```

---

## Phase 1 Issues

### No Subdomains Found

**Symptom**: Phase 1 completes but finds 0 subdomains

**Diagnosis**:

```bash
# Test subfinder manually
subfinder -d example.com -silent

# Check if domain is valid
dig example.com

# Test crt.sh manually
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq .
```

**Solutions**:

1. **Domain has no subdomains** (unlikely for public domains)
   - Try a known domain: `subfinder -d google.com`

2. **Subfinder API keys not configured**
   ```bash
   # Add API keys to improve results
   mkdir -p ~/.config/subfinder
   nano ~/.config/subfinder/provider-config.yaml
   # Add keys (see CONFIGURATION.md)
   ```

3. **Network/firewall blocking requests**
   ```bash
   # Test connectivity
   curl https://crt.sh
   curl https://api.shodan.io
   ```

---

### Phase 1 → Phase 2 Chain Broken

**Symptom**: Phase 1 completes but Phase 2 never starts

**Diagnosis**:

```bash
# Check Phase 1 workflow in n8n
# Look at the last node (should be HTTP Request or Webhook)
# Verify URL: http://localhost:5678/webhook/recon-phase2

# Check n8n logs
tail -50 ~/.n8n/logs/n8n.log
```

**Solution**:

```bash
# Verify webhook URL in Phase 1 workflow
# Open Phase 1 workflow in n8n
# Find the node that triggers Phase 2
# Check URL matches Phase 2 webhook path

# Manually trigger Phase 2 for testing
curl -X POST http://localhost:5678/webhook/recon-phase2 \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "subdomains": ["www.example.com", "api.example.com"]
  }'
```

---

## Phase 2 Issues

### Tools Not Found: httpx/dnsx

**Symptom**: Phase 2 fails with "command not found"

**Solution**:

```bash
# Check if tools are installed
which httpx
which dnsx

# If not in PATH, see Installation Issues above

# Or edit workflow to use absolute paths
# In n8n, edit Phase 2 workflow
# Change command from: httpx -l file
# To: /home/user/go/bin/httpx -l file
```

---

### No Hosts Marked as Live

**Symptom**: Phase 2 completes but finds 0 live hosts

**Diagnosis**:

```bash
# Test manually
echo "www.example.com" > /tmp/test.txt
httpx -l /tmp/test.txt -silent -json

# Check DNS resolution
dnsx -l /tmp/test.txt -silent -json -a
```

**Possible Causes**:

1. **Subdomains don't resolve**
   - Phase 1 found invalid/expired subdomains
   - Check Phase 1 output quality

2. **Network/firewall blocking probes**
   - Try from different network
   - Check if target blocks automated probes

3. **httpx/dnsx misconfigured**
   - Update tools: `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`

---

### Missing IP Addresses in Phase 2 Output

**Symptom**: Phase 3 fails because `ip_addresses` field is missing

**Solution**:

```bash
# Verify Phase 2 workflow includes IP resolution
# Open Phase 2 workflow in n8n
# Check dnsx command includes: -a flag (for A records)

# Verify output format
jq '.hosts[0].ip_addresses' /tmp/recon/example.com/phase2_data.json

# If null, Phase 2 workflow needs updating
# See WORKFLOWS.md for correct Phase 2 output format
```

---

## Phase 3 Issues

### Workers Not Starting

**Symptom**: Phase 3 Manager runs but workers never start

**Diagnosis**:

```bash
# Check worker spawn
ps aux | grep nuclei

# Check Execute Workflow node configuration
# Open Phase 3 Manager in n8n
# Find "Execute Workflow" node
# Verify:
# - mode: "each"
# - waitForSubWorkflow: false
```

**Solution**:

```bash
# Ensure Phase 3 Worker workflow exists
# Open n8n UI → Workflows
# Find: "Recon - Phase 3 Worker (Nuclei Scan)"

# Phase 3 Worker should be INACTIVE (gray toggle)
# It's spawned programmatically, not triggered manually

# Check sharding output
# In n8n, check execution of Phase 3 Manager
# Look at "IP-Centric Sharding" node output
# Should have 5 items (one per worker)
```

---

### Workers Hang/Never Complete

**Symptom**: Phase 3 workers start but never finish

**Diagnosis**:

```bash
# Check if nuclei is running
ps aux | grep nuclei

# Check nuclei isn't stuck
# Kill long-running nuclei processes
pkill nuclei

# Check worker marker files
ls -la /tmp/phase3_done_*_worker_*.marker

# Check nuclei output files
tail -f /tmp/phase3_results_*_worker_1.jsonl
```

**Solutions**:

1. **Nuclei hanging on specific template**
   ```bash
   # Reduce timeout in worker workflow
   # Edit Phase 3 Worker in n8n
   # Change: -timeout 8
   # To: -timeout 5
   ```

2. **Target blocking/rate limiting**
   ```bash
   # Reduce rate limit
   # Edit: -rl 15
   # To: -rl 5
   ```

3. **Out of memory**
   ```bash
   # Check memory usage
   free -h

   # Reduce worker count (edit Manager workflow)
   # Change: const workerCount = 5;
   # To: const workerCount = 3;
   ```

---

### Report Shows Few Findings Despite Large JSONL

**Symptom**: `phase3_all_results.jsonl` is 500KB but report shows only 7 findings

**Cause**: JSONL parsing issue (fixed in v6.3)

**Diagnosis**:

```bash
# Check processing stats in HTML report footer
# Should show:
# "Processing Stats: X raw lines | Y findings extracted | Z skipped"

# Manually check JSONL format
head -5 /tmp/recon/example.com/phase3_all_results.jsonl | jq .

# Count entries with required fields
grep -c '"info"' /tmp/recon/example.com/phase3_all_results.jsonl
grep -c '"host"' /tmp/recon/example.com/phase3_all_results.jsonl
```

**Solution**:

```bash
# Update to v6.3 or later
# Re-import Phase 3 Manager workflow from:
# "Recon - Phase 3 Main Manager.json"

# The "Generate Final Report" node should use:
# Dynamic binary property access (see examples/binary-data-parsing.js)
```

---

### All IPs Showing as "unknown"

**Symptom**: Worker sharding fails, all hosts assigned to one worker

**Cause**: Phase 2 IP field mismatch

**Solution**:

```bash
# Check Phase 2 output field name
jq '.hosts[0] | keys' /tmp/recon/example.com/phase2_data.json

# Should include: "ip_addresses"
# If different field name, update sharding code
# In Phase 3 Manager, "IP-Centric Sharding" node
# Update: let ip = host.ip_addresses || host.ip || ...
```

---

## Performance Issues

### Phase 3 Taking Too Long

**Symptom**: Phase 3 runs for 60+ minutes on 100 hosts

**Solutions**:

1. **Check worker parallelization**
   ```bash
   # Should see 5 nuclei processes simultaneously
   ps aux | grep nuclei | grep -v grep | wc -l

   # If only 1-2, workers aren't running in parallel
   # Check Execute Workflow node: waitForSubWorkflow: false
   ```

2. **Increase rate limits** (if safe)
   ```bash
   # Edit Phase 3 Worker
   # Change: -rl 15
   # To: -rl 30
   ```

3. **Reduce template scope**
   ```bash
   # Edit Phase 3 Worker
   # Change: -as (automatic scan)
   # To: -s critical,high (only high-severity)
   ```

---

### High CPU/Memory Usage

**Symptom**: System becomes unresponsive during Phase 3

**Solutions**:

```bash
# Reduce worker count
# Edit Phase 3 Manager: const workerCount = 3;

# Reduce nuclei concurrency
# Edit Phase 3 Worker:
# Change: -c 10
# To: -c 5

# Reduce bulk size
# Change: -bs 2
# To: -bs 1
```

---

### Disk Space Issues

**Symptom**: `/tmp` full, workflows fail

**Solution**:

```bash
# Check disk space
df -h /tmp

# Clean up old results
rm -rf /tmp/recon/old_domain_*

# Change output directory (see CONFIGURATION.md)
# Move to larger partition: /home/user/recon_results
```

---

## Output Issues

### Missing Output Files

**Symptom**: Workflow completes but files not in `/tmp/recon/`

**Diagnosis**:

```bash
# Check if directory exists
ls -la /tmp/recon/

# Check permissions
ls -ld /tmp/recon/
# Should be readable/writable by your user

# Check n8n user permissions
ps aux | grep n8n
# Note the user, ensure they can write to /tmp/recon/
```

**Solution**:

```bash
# Create directory with proper permissions
sudo mkdir -p /tmp/recon
sudo chown $USER:$USER /tmp/recon
chmod 755 /tmp/recon

# Or change output location to home directory
# See CONFIGURATION.md
```

---

### Corrupted JSON Output

**Symptom**: `jq` fails to parse output files

**Diagnosis**:

```bash
# Check file validity
jq . /tmp/recon/example.com/phase2_data.json

# If error, check for truncation
tail -20 /tmp/recon/example.com/phase2_data.json

# Check file size
ls -lh /tmp/recon/example.com/phase2_data.json
```

**Solution**:

```bash
# If file is truncated, workflow may have crashed
# Check n8n logs for errors
tail -100 ~/.n8n/logs/n8n.log | grep -i error

# Re-run the phase
./recon_orchestrator.py
```

---

### HTML Report Not Rendering

**Symptom**: HTML report opens but shows errors

**Solution**:

```bash
# Check HTML validity
file /tmp/recon/example.com/phase3_report.html

# Open in browser with dev console
firefox /tmp/recon/example.com/phase3_report.html
# Press F12 to see JavaScript errors

# If issues, check workflow's "Generate Final Report" node
# Ensure HTML is properly formatted
```

---

## Getting Help

### Collecting Debug Information

Before asking for help, collect this information:

```bash
# System info
uname -a
python3 --version
n8n --version

# Tool versions
subfinder -version
httpx -version
dnsx -version
nuclei -version

# n8n status
curl http://localhost:5678/healthz
ps aux | grep n8n

# Recent logs
tail -100 ~/.n8n/logs/n8n.log

# Output directory contents
ls -laR /tmp/recon/example.com/

# Worker status (if Phase 3 issue)
ls -la /tmp/phase3_*
ps aux | grep nuclei
```

### Enabling Verbose Logging

```bash
# Run orchestrator with Python debug output
python3 -u recon_orchestrator.py

# Enable n8n debug logs
N8N_LOG_LEVEL=debug n8n start

# Add logging to workflows
# In n8n Code nodes, add:
console.log("Debug info:", JSON.stringify(data));
```

### Common Log Locations

```bash
# n8n logs
~/.n8n/logs/n8n.log

# Orchestrator output (if redirected)
/tmp/recon_orchestrator.log

# System logs
/var/log/syslog | grep n8n
```

### Workflow Validation

```bash
# Test each phase independently

# Phase 1:
curl -X POST http://localhost:5678/webhook/recon-phase1 \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Phase 2:
curl -X POST http://localhost:5678/webhook/recon-phase2 \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "subdomains": ["www.example.com"]}'

# Phase 3:
# Requires Phase 2 data to exist first
curl -X POST http://localhost:5678/webhook/recon-phase3-parallel \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

---

## Still Having Issues?

1. **Check workflow_configuration.md** for architecture details
2. **Review WORKFLOWS.md** for technical implementation
3. **Consult CONFIGURATION.md** for customization options
4. **Review n8n documentation** at https://docs.n8n.io
5. **Check tool documentation**:
   - Subfinder: https://github.com/projectdiscovery/subfinder
   - httpx: https://github.com/projectdiscovery/httpx
   - dnsx: https://github.com/projectdiscovery/dnsx
   - Nuclei: https://github.com/projectdiscovery/nuclei

---

## Known Issues

### v6.3 and Earlier

1. **JSONL Parsing** - Fixed in v6.3 (binary data access)
2. **IP Field Mapping** - Fixed in v6.1 (ip_addresses field)
3. **Sequential Workers** - Fixed in v6.2 (true parallel execution)

### Current Limitations

1. **Worker Count** - Fixed at 5 (configurable but requires workflow edit)
2. **Output Format** - JSON/HTML only (no CSV/XML export built-in)
3. **API Authentication** - Not supported for subfinder API keys in workflow
4. **Resume Capability** - Cannot resume interrupted scans

---

**Last Updated**: 2025-12-11
