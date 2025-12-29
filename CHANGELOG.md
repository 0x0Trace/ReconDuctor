# Changelog

All notable changes to ReconDuctor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **GAU now runs automatically in Phase 2** - Historical URL mining runs in parallel with HTTP probing, no longer requires `--gau` flag
- **Removed `--gau` flag** - GAU is now part of the default scan pipeline
- **AI URL filtering moved to `--ai-triage`** - When AI triage is enabled, GAU URLs are filtered and ranked by exploit likelihood

### Added
- **Standalone `gau` command** - Run GAU independently: `reconductor gau example.com`
  - `--ai` flag for AI-powered URL ranking
  - Useful if GAU was missed during Phase 2 or for re-running
- **AI-powered URL filtering** (`gau_filter_agent.py`) - Ranks URLs by vulnerability priority:
  1. RCE/Command injection (`cmd=`, `exec=`, `shell=`)
  2. SSRF/Open redirect (`url=`, `redirect=`, `callback=`)
  3. LFI/Path traversal (`file=`, `path=`, `include=`)
  4. SQLi (`id=`, `uid=`, `page=`, `limit=`)
  5. Auth endpoints, Debug paths, Sensitive files, API endpoints
- **GAU section in main report.html** - Shows URL stats, category badges, and sample high-value URLs
- **AI Selected stat** - When `--ai-triage` is used, shows count of AI-filtered URLs
- **Deduplication in URL filtering** - Prevents similar endpoints from flooding results
- **Improved prompt engineering** - Better JSON output reliability and priority-based ranking

### Fixed
- **GAU provider format** - Fixed `--providers` flag to use comma-separated format
- **Removed `--fp` flag** - Was too aggressive, filtering out most URLs
- **Prompt length handling** - Iterative truncation with domain suffix stripping

### Performance
- **Parallel execution** - GAU, HTTP probing, and subjack now run concurrently in Phase 2
- **Fast providers by default** - Uses OTX and URLScan (Wayback often returns 503)

## [2.0.0] - 2024-12-28

### Added
- Initial v2 release
- Multi-source subdomain enumeration (subfinder, crt.sh, Shodan)
- AI-powered wordlist generation (`--ai`)
- AI-powered vulnerability triage (`--ai-triage`)
- Historical URL mining with GAU
- Screenshot capture with gowitness
- Port scanning with naabu
- Parallel Nuclei vulnerability scanning
- Origin IP discovery via Shodan
- Subdomain takeover detection with subjack
- Rich CLI interface with real-time progress
- SQLite checkpoint database for crash recovery
- Multi-provider LLM support (Claude, OpenAI, Ollama, Gemini, Groq)

### Security
- Secure temp file handling
- Input validation and sanitization
- Rate limiting with adaptive backoff
- Scope validation for target restrictions
