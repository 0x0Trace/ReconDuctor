# Final Workflow Configuration - Updated 11 December 2025 (19:25 UTC)

## âœ… Active Workflows (5 Total - TRUE PARALLEL ARCHITECTURE)

### 1. **Recon Automation - Phase 1: Subdomain Enumeration**
- **Workflow ID:** `p7dqxf5jY9Pb4vNH`
- **Created:** 3 December 2025
- **Status:** âœ… Active
- **Webhook:** `POST http://localhost:5678/webhook/recon-phase1`
- **Purpose:** Subdomain discovery using crt.sh + subfinder
- **Auto-chains to:** Phase 2 (JSON webhook)
- **Output:** Sends JSON with subdomains array to Phase 2

---

### 2. **Recon Automation - Phase 2: Live Host Validation**
- **Workflow ID:** `buLRNQbEx1NYjsua`
- **Created:** 5 December 2025
- **Status:** âœ… Active
- **Webhook:** `POST http://localhost:5678/webhook/recon-phase2`
- **Purpose:** Live host validation with httpx + dnsx + technology fingerprinting
- **Output Files:**
  - `/tmp/recon/{domain}/phase2_data.json` - All discovered hosts **with tech fingerprints AND IP addresses**
  - `/tmp/recon/{domain}/phase2_report.html` - HTML report
  - `/tmp/recon/{domain}/phase2_summary.txt` - Statistics

**CRITICAL Phase 2 Requirements:**
1. Technology detection (httpx fingerprinting)
2. **IP address field must be `ip_addresses`** - Required for IP-Centric Sharding

---

### 3. **Recon - Phase 3 Main Manager** ðŸš€ TRUE PARALLEL ARCHITECTURE
- **Workflow ID:** `YiTd4X1k1CF4rNLo`
- **Created:** 11 December 2025
- **Updated:** 11 December 2025 (19:25 UTC) - **FIXED JSONL PARSING**
- **Status:** âœ… Active
- **Webhook:** `POST http://localhost:5678/webhook/recon-phase3-parallel`
- **Purpose:** Orchestrates TRUE PARALLEL nuclei scans using IP-based clustering
- **Architecture:** Fixed 5-Worker Pool with IP-Centric Sharding + Fire-and-Forget Workers
- **Node Count:** 15 nodes

#### ðŸ”¥ TRUE PARALLEL EXECUTION (v6.2+)

**Execute Workflow Configuration:**
```javascript
{
  "mode": "each",                    // One execution per item (5 items = 5 executions)
  "waitForSubWorkflow": false        // Fire-and-forget - DON'T wait for completion
}
```

**How TRUE Parallel Works:**
1. IP-Centric Sharding outputs 5 items (one per worker batch)
2. Execute Workflow node spawns 5 **INDEPENDENT** sub-workflow executions
3. **CRITICAL:** `waitForSubWorkflow: false` means Manager continues immediately
4. All 5 workers start simultaneously - TRUE PARALLEL
5. Manager's "Wait For All Workers" polls for marker files
6. Workers complete independently, writing marker files when done

#### IP-Centric Sharding Algorithm:

```javascript
// IMPORTANT: Phase 2 uses 'ip_addresses' field!
let ip = host.ip_addresses || host.ip || host.resolved_ip || host.a || 'unknown';

// Handle array of IPs (take first)
if (Array.isArray(ip)) {
  ip = ip[0] || 'unknown';
}

// Normalize - handle comma-separated IPs
ip = String(ip).trim();
if (ip.includes(',')) {
  ip = ip.split(',')[0].trim();
}
```

#### Execution Flow:

```
Webhook Trigger
    â†“
Extract Domain + Read Phase 2 Data
    â†“
IP-Centric Sharding (outputs 5 items)
    â†“
Check If Empty (filters empty workers)
    â†“
Execute Workers (Parallel) â† TRUE PARALLEL HERE
    â”œâ”€â”€ Worker 1 (starts immediately) â”€â”€â†’ nuclei scan â”€â”€â†’ marker file
    â”œâ”€â”€ Worker 2 (starts immediately) â”€â”€â†’ nuclei scan â”€â”€â†’ marker file
    â”œâ”€â”€ Worker 3 (starts immediately) â”€â”€â†’ nuclei scan â”€â”€â†’ marker file
    â”œâ”€â”€ Worker 4 (starts immediately) â”€â”€â†’ nuclei scan â”€â”€â†’ marker file
    â””â”€â”€ Worker 5 (starts immediately) â”€â”€â†’ nuclei scan â”€â”€â†’ marker file
    â†“ (continues immediately - doesn't wait!)
Wait For All Workers (polls marker files)
    â†“
Aggregate All Results
    â†“
Read Aggregated Results (JSONL)
    â†“
Generate Final Report â† v6.3 FIX HERE
```

---

### 4. **Recon - Phase 3 Worker (Nuclei Scan)** âš™ï¸ WAF-SAFE MODE
- **Workflow ID:** `sCC4a3A0w8hYYqL9`
- **Created:** 11 December 2025
- **Updated:** 11 December 2025 (17:59 UTC) - **WAF-SAFE NUCLEI CONFIG**
- **Status:** ðŸŸ¡ Inactive (spawned by Manager)
- **Type:** Sub-workflow (Execute Workflow Trigger)
- **Purpose:** IP-clustered scanner with strict rate limits

#### ðŸ›¡ï¸ WAF-SAFE Nuclei Configuration:

```bash
nuclei \
  -l "$TARGETS_FILE" \
  -as \                    # Automatic scan (smart template selection)
  -rl 15 \                 # Max 15 requests/second (CRITICAL!)
  -bs 2 \                  # Bulk size: 2 hosts at a time
  -c 10 \                  # 10 concurrent templates per host
  -timeout 8 \             # 8 second timeout per request
  -retries 1 \             # Single retry on failure
  -H "User-Agent: Mozilla/5.0 ..." \  # Spoof browser UA
  -etags fuzz,dos,fuzzing,intrusive,sqli,xss,rce,bruteforce \
  -s critical,high,medium \
  -silent -jsonl \
  -ni -nc                  # No interactsh, no color
```

#### Worker File Output Pattern:

```
/tmp/phase3_targets_{timestamp}_worker_{N}.txt    # Target URLs
/tmp/phase3_results_{timestamp}_worker_{N}.jsonl  # Nuclei findings
/tmp/phase3_done_{timestamp}_worker_{N}.marker    # Completion signal
```

---

### 5. **Recon Automation - Phase 3-Quick: Fast Triage** ðŸ“‹ LEGACY
- **Workflow ID:** `CLnf1Suju12xnda8`
- **Created:** 10 December 2025
- **Status:** âœ… Active (backward compatibility)
- **Webhook:** `POST http://localhost:5678/webhook/recon-phase3-quick`
- **Purpose:** Fast CVE + exposure triage scan (sequential, single worker)

---

## ðŸ“Š File Structure

```
/tmp/recon/{domain}/
â”œâ”€â”€ phase2_data.json              # Phase 2: Hosts with IPs + tech (INPUT)
â”œâ”€â”€ phase2_report.html            # Phase 2: Live host report
â”‚
â”œâ”€â”€ phase3_report.html            # Phase 3 Manager: Final consolidated report
â”œâ”€â”€ phase3_data.json              # Phase 3 Manager: All findings JSON
â”œâ”€â”€ phase3_all_results.jsonl      # Phase 3 Manager: Raw aggregated results
â””â”€â”€ phase3_summary.txt            # Phase 3 Manager: Statistics

/tmp/
â”œâ”€â”€ phase3_targets_{timestamp}_worker_1.txt    # Worker 1 targets (temp)
â”œâ”€â”€ phase3_results_{timestamp}_worker_1.jsonl  # Worker 1 results (temp)
â”œâ”€â”€ phase3_done_{timestamp}_worker_1.marker    # Worker 1 completion marker
... (up to worker_5)
```

---

## ðŸš€ Quick Reference

### Trigger Phase 3 Manager (True Parallel Mode)

```bash
curl -X POST http://localhost:5678/webhook/recon-phase3-parallel \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Monitor Parallel Worker Progress

```bash
# Watch marker files during execution
watch -n 2 'echo "=== Worker Completion ===" && ls -la /tmp/phase3_done_*_worker_*.marker 2>/dev/null'

# Count active nuclei processes (should be up to 5 simultaneously!)
watch -n 1 'ps aux | grep nuclei | grep -v grep'

# Check individual worker status
for i in 1 2 3 4 5; do
  echo "Worker $i: $(cat /tmp/phase3_done_*_worker_$i.marker 2>/dev/null || echo 'running...')"
done
```

### Debug JSONL Processing

```bash
# Check raw line count vs report findings
wc -l /tmp/recon/{domain}/phase3_all_results.jsonl

# View first few entries to check format
head -5 /tmp/recon/{domain}/phase3_all_results.jsonl | jq .

# Check for entries with info.severity
grep -c '"severity"' /tmp/recon/{domain}/phase3_all_results.jsonl
```

---

## âœ… Summary of Changes (11 December 2025)

### v6.3 - JSONL PARSING FIX (19:25 UTC) ðŸ”§

**Problem:** Report only showed 7 findings despite 496KB JSONL file (thousands of lines)

**Root Cause:** Binary data access path was incorrect in Generate Final Report node
```javascript
// WRONG (v6.2)
const jsonlContent = Buffer.from(fileData.data.data, 'base64').toString('utf-8');

// CORRECT (v6.3) 
const propName = Object.keys(binaryObj)[0];
const jsonlContent = Buffer.from(binaryObj[propName].data, 'base64').toString('utf-8');
```

**Changes:**
1. **Fixed binary parsing**: Dynamically get property name from n8n binary object
2. **Added debug info**: Report now shows processing stats (raw lines, extracted, skipped)
3. **Added console logging**: Helps debug parsing issues in execution logs

**Report Debug Section:**
The HTML report now includes at the bottom:
```
Processing Stats: X raw lines | Y findings extracted | Z parse errors | W skipped (no info/host)
```

### v6.2 - TRUE PARALLEL EXECUTION (18:30 UTC)

**Critical Changes:**
1. **`mode: "each"`** - Each sharding output item spawns separate sub-workflow
2. **`waitForSubWorkflow: false`** - Fire-and-forget, Manager continues immediately
3. All 5 workers now start **SIMULTANEOUSLY** - TRUE PARALLEL

### v6.1 - Bug Fixes (18:25 UTC)

**Fixed Issues:**
1. **IP Address Field Mismatch**: Code now correctly reads `ip_addresses` from Phase 2
2. **Execute Workflow Mappings**: All 10 input fields properly mapped with expressions

### v6.0 - IP-Centric Architecture (17:58 UTC)

**Problem Solved:**
- WAF blocks from tech-based parallel scanning
- Multiple workers hitting same load balancer IP simultaneously
- Unlimited worker spawning causing resource exhaustion

**Solution Implemented:**
1. **IP-Centric Sharding**: Group hosts by IP, never split clusters
2. **Fixed 5-Worker Pool**: Maximum 5 parallel scans
3. **WAF-Safe Rate Limits**: 15 req/s (down from 100)
4. **Nuclei Automatic Scan**: `-as` flag for smart template selection
5. **User-Agent Spoofing**: Mimics Chrome browser

---

## ðŸ”§ n8n Implementation Details

### Why Fire-and-Forget with File Sync?

The combination of `mode: "each"` + `waitForSubWorkflow: false` + file-based synchronization provides:

1. **TRUE Parallel Execution**: All workers start at the same time
2. **Decoupled Lifecycle**: Worker failures don't block Manager
3. **Flexible Timeout**: Manager polls for markers with configurable timeout
4. **Resource Efficiency**: No blocking threads waiting on sub-workflows

### Binary Data Access in n8n Code Nodes

n8n's readWriteFile node outputs binary data with this structure:
```javascript
$input.item.binary = {
  "data": {                    // Property name (could be anything)
    "data": "base64string...",  // Actual base64 content
    "mimeType": "text/plain",
    "fileName": "file.txt"
  }
}
```

**Correct access pattern:**
```javascript
const binaryObj = $input.item.binary;
const propName = Object.keys(binaryObj)[0];  // Get "data" or whatever it's named
const content = Buffer.from(binaryObj[propName].data, 'base64').toString('utf-8');
```

### Nuclei JSONL Output Format

Each line is a JSON object with this structure:
```json
{
  "template-id": "apache-detect",
  "info": {
    "name": "Apache HTTP Server Detection",
    "severity": "info",
    "tags": ["tech", "apache"],
    "description": "...",
    "reference": ["https://..."],
    "classification": {
      "cve-id": "CVE-2021-xxxx",
      "cvss-score": 9.8
    }
  },
  "host": "https://example.com",
  "matched-at": "https://example.com/path",
  "extracted-results": ["version 2.4.51"]
}
```

**Note:** Some entries (like tech detections) may not have all fields.
The parser checks for `f.info && f.host` to filter valid findings.

---

## ðŸ” Troubleshooting

### Report Shows Few Findings Despite Large JSONL?

1. Check the "Processing Stats" in the HTML report footer
2. If "skipped" is high, entries may lack `info` or `host` fields
3. Sample the JSONL to see actual format:
   ```bash
   head -3 /tmp/recon/{domain}/phase3_all_results.jsonl | jq .
   ```

### Workers Not Starting in Parallel?

1. Check Execute Workflow node configuration:
   - `mode` must be `"each"` (not `"once"`)
   - `options.waitForSubWorkflow` must be `false`

2. Check sharding output:
   ```bash
   # Should output 5 items (one per worker)
   echo "Items: $(grep -c workerIndex <execution_log>)"
   ```

### All IPs Showing as "unknown"?

1. Check Phase 2 output field name - must be `ip_addresses`
2. Check IP-Centric Sharding code includes `ip_addresses` in field lookup

### Workers Not Completing?

1. Check nuclei is installed and in PATH
2. Check rate limits aren't causing timeouts
3. Monitor individual worker logs in n8n executions

---

**Last Updated:** 11 December 2025, 19:25 UTC  
**Architecture Version:** 6.3 (JSONL Parsing Fix)  
**Status:** âœ… Production Ready  
**Total Workflows:** 5 (3 active main + 1 manager + 1 worker)