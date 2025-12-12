#!/bin/bash
#
# WAF-Safe Nuclei Scanning Command
#
# This is the nuclei command used by Phase 3 Worker workflow.
# Parameters are carefully tuned to avoid triggering WAF/IDS systems.
#

nuclei \
  -l "$TARGETS_FILE" \
  -as \
  -rl 15 \
  -bs 2 \
  -c 10 \
  -timeout 8 \
  -retries 1 \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -etags fuzz,dos,fuzzing,intrusive,sqli,xss,rce,bruteforce \
  -s critical,high,medium \
  -silent \
  -jsonl \
  -ni \
  -nc \
  -o "$RESULTS_FILE"

# Parameter Explanation:
#
# -l "$TARGETS_FILE"         : Input file with target URLs (one per line)
# -as                         : Automatic scan (smart template selection based on tech stack)
# -rl 15                      : Rate limit - max 15 requests per second
# -bs 2                       : Bulk size - scan 2 hosts at a time
# -c 10                       : Concurrency - 10 concurrent templates per host
# -timeout 8                  : Timeout - 8 seconds per request
# -retries 1                  : Retry count - retry once on failure
# -H "User-Agent: ..."        : Spoof user-agent to mimic legitimate browser
# -etags ...                  : Exclude dangerous/intrusive template tags
# -s critical,high,medium     : Filter by severity (exclude low/info)
# -silent                     : Suppress banner and verbose output
# -jsonl                      : Output in JSON Lines format (one JSON per line)
# -ni                         : No interactsh server (avoid external callbacks)
# -nc                         : No color codes in output
# -o "$RESULTS_FILE"          : Output file path
#
# Excluded Template Tags:
# - fuzz       : Fuzzing tests (resource intensive)
# - dos        : Denial of service checks (dangerous)
# - fuzzing    : General fuzzing (resource intensive)
# - intrusive  : Intrusive scans (may cause damage)
# - sqli       : SQL injection tests (may trigger WAF)
# - xss        : XSS tests (may trigger WAF)
# - rce        : Remote code execution (may trigger WAF)
# - bruteforce : Brute force attacks (may trigger rate limits)
#
# Rate Limiting Strategy:
# - 15 req/s per worker × 5 workers = 75 req/s total
# - Bulk size of 2 means 2 hosts are scanned simultaneously per worker
# - With 10 concurrent templates, effective rate per worker is ~30-50 req/s
# - The -rl 15 limit acts as a hard cap to prevent bursts
#
# WAF Evasion Techniques:
# 1. User-Agent spoofing (mimics Chrome browser)
# 2. Rate limiting (appears as normal user traffic)
# 3. Template filtering (excludes obviously malicious patterns)
# 4. No interactsh (avoids suspicious external callbacks)
#
# Tuning Guidelines:
# - Increase -rl for faster scans (may trigger WAF)
# - Decrease -rl for stealth mode (slower but safer)
# - Increase -bs for more parallel hosts (higher resource usage)
# - Increase -c for more concurrent templates (higher load per host)
# - Adjust -timeout based on target response times
