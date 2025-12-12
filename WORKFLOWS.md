# Workflow Architecture Documentation

Detailed technical documentation of Reconductor's n8n workflow architecture.

---

## Table of Contents

- [Overview](#overview)
- [Workflow Pipeline](#workflow-pipeline)
- [Phase 1: Subdomain Enumeration](#phase-1-subdomain-enumeration)
- [Phase 2: Live Host Validation](#phase-2-live-host-validation)
- [Phase 3: Parallel Vulnerability Scanning](#phase-3-parallel-vulnerability-scanning)
- [Data Flow](#data-flow)
- [Architecture Evolution](#architecture-evolution)
- [Technical Implementation Details](#technical-implementation-details)

---

## Overview

Reconductor uses a multi-phase n8n workflow architecture to perform comprehensive reconnaissance:

- **5 Active Workflows**: 3 main phases + 1 manager + 1 worker
- **True Parallel Execution**: 5 simultaneous workers for vulnerability scanning
- **IP-Centric Sharding**: Intelligent host clustering to prevent WAF blocks
- **Fire-and-Forget Workers**: Non-blocking parallel execution model

### Active Workflows

| Workflow | ID | Status | Purpose |
|----------|-----|--------|---------|
| Phase 1: Subdomain Enumeration | `p7dqxf5jY9Pb4vNH` | Active | Discover subdomains |
| Phase 2: Live Host Validation | `buLRNQbEx1NYjsua` | Active | Validate live hosts |
| Phase 3 Main Manager | `YiTd4X1k1CF4rNLo` | Active | Orchestrate parallel scans |
| Phase 3 Worker | `sCC4a3A0w8hYYqL9` | Inactive | Execute nuclei scans |

**Note**: Phase 3 Worker is spawned by the Manager and should remain inactive in the UI.

---

## Workflow Pipeline

```
┌─────────────────────────────────────────────────────────────┐
│                    PHASE 1: DISCOVERY                        │
│  ┌──────────┐    ┌──────────┐    ┌──────────────────────┐  │
│  │ Webhook  │───▶│ Subfinder│───▶│ crt.sh SSL Cert Logs │  │
│  │ Trigger  │    │  Search  │    │                      │  │
│  └──────────┘    └──────────┘    └──────────────────────┘  │
│                          │                                   │
│                          ▼                                   │
│              ┌───────────────────────┐                       │
│              │ Deduplicate Subdomains│                       │
│              └───────────────────────┘                       │
└──────────────────────────┬───────────────────────────────────┘
                           │ JSON Webhook
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    PHASE 2: VALIDATION                       │
│  ┌──────────┐    ┌──────────┐    ┌─────────────────────┐   │
│  │  Receive │───▶│  dnsx    │───▶│ httpx + Tech Detect │   │
│  │ Subdomains│   │ DNS Probe│    │                     │   │
│  └──────────┘    └──────────┘    └─────────────────────┘   │
│                                              │               │
│                                              ▼               │
│                          ┌────────────────────────────┐     │
│                          │ Merge Results + Write Files│     │
│                          │  - phase2_data.json        │     │
│                          │  - phase2_report.html      │     │
│                          └────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
                           │ Manual Trigger
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              PHASE 3: PARALLEL VULNERABILITY SCANNING        │
│  ┌──────────┐    ┌──────────────────┐    ┌──────────────┐  │
│  │ Webhook  │───▶│ Read Phase 2 Data│───▶│ IP-Centric   │  │
│  │ Trigger  │    │                  │    │   Sharding   │  │
│  └──────────┘    └──────────────────┘    └──────────────┘  │
│                                                  │           │
│                                                  ▼           │
│                          ┌───────────────────────────────┐  │
│                          │ Execute Workflow (mode: each) │  │
│                          │ waitForSubWorkflow: false     │  │
│                          └───────────────────────────────┘  │
│                          │                                  │
│         ┌────────────────┼────────────────┬────────────┐   │
│         ▼                ▼                ▼            ▼   │
│   ┌─────────┐      ┌─────────┐      ┌─────────┐  ┌─────┐ │
│   │Worker 1 │      │Worker 2 │ ...  │Worker 5 │  │ Wait│ │
│   │ Nuclei  │      │ Nuclei  │      │ Nuclei  │  │ For │ │
│   │  Scan   │      │  Scan   │      │  Scan   │  │ All │ │
│   └────┬────┘      └────┬────┘      └────┬────┘  └──┬──┘ │
│        │                │                 │           │    │
│        ▼                ▼                 ▼           ▼    │
│   ┌────────────────────────────────────────────────────┐  │
│   │ Aggregate Results → Generate HTML Report          │  │
│   │  - phase3_report.html                             │  │
│   │  - phase3_data.json                               │  │
│   │  - phase3_all_results.jsonl                       │  │
│   └────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Subdomain Enumeration

**Workflow ID**: `p7dqxf5jY9Pb4vNH`
**Webhook**: `POST /webhook/recon-phase1`
**Auto-chains to**: Phase 2

### Purpose

Discover all subdomains for a target domain using multiple sources.

### Data Sources

1. **Subfinder**: Queries 30+ passive sources (crt.sh, VirusTotal, Censys, etc.)
2. **crt.sh Direct**: SSL certificate transparency logs

### Node Flow

1. **Webhook Trigger** - Receives `{"domain": "example.com"}`
2. **Run Subfinder** - Execute command: `subfinder -d {domain} -silent -all`
3. **Query crt.sh** - Direct API call for SSL cert data
4. **Parse crt.sh Response** - Extract domains from JSON
5. **Merge & Deduplicate** - Combine results from both sources
6. **Send to Phase 2** - HTTP POST with subdomain array

### Output Format

JSON sent to Phase 2:

```json
{
  "domain": "example.com",
  "subdomains": [
    "www.example.com",
    "api.example.com",
    "mail.example.com"
  ],
  "source": "phase1",
  "timestamp": "2025-12-11T12:00:00Z"
}
```

---

## Phase 2: Live Host Validation

**Workflow ID**: `buLRNQbEx1NYjsua`
**Webhook**: `POST /webhook/recon-phase2`
**Triggered by**: Phase 1 (automatic)

### Purpose

Validate which subdomains are live and gather additional intelligence:
- DNS resolution (A, CNAME records)
- HTTP/HTTPS availability
- Technology fingerprinting
- Status codes and titles

### Tools Used

1. **dnsx**: DNS resolution and record enumeration
2. **httpx**: HTTP probing with technology detection

### Node Flow

1. **Webhook Trigger** - Receives subdomain array from Phase 1
2. **Write Subdomains to File** - Create temporary input file
3. **Run dnsx** - DNS validation: `dnsx -l {file} -silent -json -a -cname`
4. **Run httpx** - HTTP probing: `httpx -l {file} -silent -json -tech-detect -status-code -title`
5. **Parse Results** - Merge DNS + HTTP data
6. **Classify Hosts** - Categorize: both, httpOnly, dnsOnly
7. **Generate Report** - Create HTML report
8. **Write Output Files**:
   - `phase2_data.json` - Structured data with IP addresses
   - `phase2_report.html` - Human-readable report
   - `phase2_summary.txt` - Statistics

### Output Format

See [examples/phase2-output-format.json](examples/phase2-output-format.json) for complete structure.

**Critical Fields** for Phase 3:
- `ip_addresses`: Required for IP-centric sharding
- `tech`: Technology stack array
- `url`: Full HTTP(S) URL

---

## Phase 3: Parallel Vulnerability Scanning

**Manager Workflow ID**: `YiTd4X1k1CF4rNLo`
**Worker Workflow ID**: `sCC4a3A0w8hYYqL9`
**Webhook**: `POST /webhook/recon-phase3-parallel`

### Architecture: Manager-Worker Model

Phase 3 uses a **manager-worker architecture** for true parallel execution.

### Manager Workflow

**Purpose**: Orchestrate parallel nuclei scans across 5 workers.

#### Node Flow

1. **Webhook Trigger** - Receives `{"domain": "example.com"}`
2. **Extract Domain** - Parse domain from payload
3. **Read Phase 2 Data** - Load `/tmp/recon/{domain}/phase2_data.json`
4. **IP-Centric Sharding** - Distribute hosts across 5 workers by IP
5. **Check If Empty** - Filter out empty worker batches
6. **Execute Workers (Parallel)** - Spawn worker sub-workflows
7. **Wait For All Workers** - Poll for completion markers
8. **Aggregate Results** - Combine all worker JSONL files
9. **Read Aggregated Results** - Load combined findings
10. **Generate Final Report** - Create HTML/JSON reports

#### IP-Centric Sharding Algorithm

See [examples/ip-centric-sharding.js](examples/ip-centric-sharding.js) for complete code.

**Key Principles**:
- Group hosts by IP address (never split IP clusters)
- Fixed 5-worker pool (prevents resource exhaustion)
- Round-robin distribution for load balancing

**Field Priority**:
```javascript
let ip = host.ip_addresses || host.ip || host.resolved_ip || host.a || 'unknown';
```

### Worker Workflow

**Purpose**: Execute WAF-safe nuclei scan on assigned host cluster.

#### Node Flow

1. **Execute Workflow Trigger** - Receives worker data from manager
2. **Parse Worker Data** - Extract targets, worker ID, timestamp
3. **Write Target File** - Create `/tmp/phase3_targets_{timestamp}_worker_{N}.txt`
4. **Run Nuclei Scan** - Execute nuclei with WAF-safe parameters
5. **Write Results** - Save to `/tmp/phase3_results_{timestamp}_worker_{N}.jsonl`
6. **Write Completion Marker** - Create `/tmp/phase3_done_{timestamp}_worker_{N}.marker`

#### Nuclei Configuration (WAF-Safe)

See [examples/nuclei-command.sh](examples/nuclei-command.sh) for complete command.

**Key Parameters**:
- `-rl 15`: Rate limit of 15 requests/second
- `-bs 2`: Bulk size of 2 hosts
- `-c 10`: 10 concurrent templates per host
- `-timeout 8`: 8-second timeout
- `-retries 1`: Single retry on failure
- `-etags fuzz,dos,fuzzing,intrusive,sqli,xss,rce,bruteforce`: Exclude dangerous templates
- `-s critical,high,medium`: Severity filter

### True Parallel Execution

**Execute Workflow Configuration**:

```javascript
{
  "mode": "each",                    // One execution per sharding output item
  "waitForSubWorkflow": false        // Fire-and-forget (non-blocking)
}
```

**How It Works**:

1. IP-Centric Sharding outputs **5 items** (one per worker batch)
2. Execute Workflow node spawns **5 independent sub-workflow executions**
3. `waitForSubWorkflow: false` means Manager continues **immediately**
4. All 5 workers start **simultaneously** - TRUE PARALLEL
5. Manager's "Wait For All Workers" polls for marker files
6. Workers complete independently, writing marker files when done

**Synchronization**: File-based with polling

```bash
# Manager polls for these files
/tmp/phase3_done_{timestamp}_worker_1.marker
/tmp/phase3_done_{timestamp}_worker_2.marker
/tmp/phase3_done_{timestamp}_worker_3.marker
/tmp/phase3_done_{timestamp}_worker_4.marker
/tmp/phase3_done_{timestamp}_worker_5.marker
```

---

## Data Flow

### Phase 1 → Phase 2

**Method**: HTTP POST (JSON webhook)

**Payload**:
```json
{
  "domain": "example.com",
  "subdomains": ["sub1.example.com", "sub2.example.com"]
}
```

### Phase 2 → Phase 3

**Method**: File-based (JSON file)

**File**: `/tmp/recon/{domain}/phase2_data.json`

**Required Fields**:
- `ip_addresses`: For IP-centric sharding
- `url`: Target URL for nuclei
- `tech`: Technology stack (optional, for filtering)

### Phase 3 Workers → Manager

**Method**: File-based (JSONL + marker files)

**Worker Output**:
- Results: `/tmp/phase3_results_{timestamp}_worker_{N}.jsonl`
- Marker: `/tmp/phase3_done_{timestamp}_worker_{N}.marker`

**Manager Input**:
- Aggregated: `/tmp/recon/{domain}/phase3_all_results.jsonl`

---

## Architecture Evolution

### v6.3 - JSONL Parsing Fix (2025-12-11)

**Problem**: Report showed only 7 findings despite 496KB JSONL file.

**Root Cause**: Incorrect binary data access path.

**Fix**: Dynamic property name extraction from n8n binary object.

See [examples/binary-data-parsing.js](examples/binary-data-parsing.js) for before/after code.

### v6.2 - True Parallel Execution (2025-12-11)

**Changes**:
1. `mode: "each"` - Each item spawns separate execution
2. `waitForSubWorkflow: false` - Non-blocking
3. All 5 workers start simultaneously

**Result**: True parallel execution achieved.

### v6.1 - IP Field Mapping Fix (2025-12-11)

**Problem**: Workers couldn't read IP addresses from Phase 2 data.

**Fix**: Updated field lookup to use `ip_addresses` (Phase 2 output field).

### v6.0 - IP-Centric Architecture (2025-12-11)

**Problem**: Tech-based parallel scanning triggered WAF blocks.

**Solution**:
1. IP-centric sharding (group by IP, never split)
2. Fixed 5-worker pool (resource control)
3. WAF-safe rate limits (15 req/s)
4. User-agent spoofing

---

## Technical Implementation Details

### Binary Data Access in n8n

n8n's file operations output binary data with this structure:

```javascript
$input.item.binary = {
  "data": {                    // Property name (dynamic)
    "data": "base64string...",  // Base64 content
    "mimeType": "text/plain",
    "fileName": "file.txt"
  }
}
```

**Correct Access Pattern**:

```javascript
const binaryObj = $input.item.binary;
const propName = Object.keys(binaryObj)[0];  // Dynamic property name
const content = Buffer.from(binaryObj[propName].data, 'base64').toString('utf-8');
```

### Nuclei JSONL Output Format

Each line is a complete JSON object:

```json
{
  "template-id": "apache-detect",
  "info": {
    "name": "Apache HTTP Server Detection",
    "severity": "info",
    "tags": ["tech", "apache"],
    "description": "...",
    "classification": {
      "cve-id": "CVE-2021-12345",
      "cvss-score": 9.8
    }
  },
  "host": "https://example.com",
  "matched-at": "https://example.com/path",
  "extracted-results": ["version 2.4.51"]
}
```

**Parsing Logic**: Filter for entries with `f.info && f.host` to ensure valid findings.

### File Synchronization Pattern

**Why Fire-and-Forget + File Sync?**

1. **True Parallel Execution**: All workers start at same time
2. **Decoupled Lifecycle**: Worker failures don't block manager
3. **Flexible Timeout**: Manager polls with configurable timeout
4. **Resource Efficiency**: No blocking threads

**Implementation**:

```javascript
// Manager: Wait for completion
const pollInterval = 5000; // 5 seconds
const maxWait = 900000;    // 15 minutes

while (elapsed < maxWait) {
  const completed = checkMarkerFiles(workerCount, timestamp);
  if (completed === workerCount) break;
  await sleep(pollInterval);
}
```

---

## Workflow Files Reference

| File | Description | Size |
|------|-------------|------|
| `Recon Automation - Phase 1_ Subdomain Enumeration.json` | Phase 1 workflow | 18KB |
| `Recon Automation - Phase 2_ Live Host Validation.json` | Phase 2 workflow | 33KB |
| `Recon - Phase 3 Main Manager.json` | Phase 3 manager | 31KB |
| `Recon - Phase 3 Worker (Nuclei Scan).json` | Phase 3 worker | 7KB |

---

## Monitoring Workflows

### View Active Executions

```bash
# Watch marker files
watch -n 2 'ls -la /tmp/phase3_done_*_worker_*.marker 2>/dev/null'

# Count active nuclei processes
watch -n 1 'ps aux | grep nuclei | grep -v grep'

# Check individual worker status
for i in 1 2 3 4 5; do
  echo "Worker $i: $(cat /tmp/phase3_done_*_worker_$i.marker 2>/dev/null || echo 'running...')"
done
```

### Debug JSONL Processing

```bash
# Check line count
wc -l /tmp/recon/{domain}/phase3_all_results.jsonl

# View first entries
head -5 /tmp/recon/{domain}/phase3_all_results.jsonl | jq .

# Count findings with severity
grep -c '"severity"' /tmp/recon/{domain}/phase3_all_results.jsonl
```

---

## Best Practices

1. **Always run Phase 1 & 2 before Phase 3** - Phase 3 requires Phase 2 data
2. **Monitor worker count** - Ensure exactly 5 workers are spawning
3. **Check marker files** - Verify all workers complete successfully
4. **Review rate limits** - Adjust based on target infrastructure
5. **Update nuclei templates** - Run `nuclei -update-templates` regularly

---

## References

- Original workflow configuration: [workflow_configuration.md](workflow_configuration.md)
- n8n Execute Workflow documentation: https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.executeworkflow/
- Nuclei documentation: https://docs.projectdiscovery.io/tools/nuclei/overview

---

**Last Updated**: 2025-12-11
**Architecture Version**: 6.3
