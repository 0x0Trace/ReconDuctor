# Reconductor Documentation Index

Complete guide to all Reconductor documentation with organized navigation.

---

## Quick Navigation

### New to Reconductor?

Start here for a smooth onboarding experience:

1. [Main README](../README.md) - Project overview and features
2. [Installation Guide](getting-started/INSTALLATION.md) - Step-by-step setup
3. [Usage Guide](getting-started/USAGE.md) - Your first scan and common workflows

### Looking for Specific Information?

- **Setup & Installation** → [Getting Started](#getting-started)
- **Configuration** → [Configuration](#configuration)
- **Technical Details** → [Architecture](#architecture)
- **Troubleshooting** → [Guides](#guides)
- **Contributing** → [Contributing](#contributing)

---

## Documentation Structure

```
docs/
├── INDEX.md (you are here)           # Complete documentation navigation
│
├── getting-started/                  # For new users and common tasks
│   ├── INSTALLATION.md               # Complete installation guide
│   └── USAGE.md                      # Practical examples and workflows
│
├── configuration/                    # Customization and settings
│   └── CONFIGURATION.md              # Tool paths, scanning parameters, etc.
│
├── architecture/                     # Technical architecture
│   ├── WORKFLOWS.md                  # n8n workflow details
│   └── workflow_configuration_detailed.md  # Original technical specs
│
├── guides/                           # How-to guides
│   └── TROUBLESHOOTING.md            # Common issues and solutions
│
└── contributing/                     # For contributors
    └── CONTRIBUTING.md               # Development guide
```

---

## Getting Started

Essential documentation for new users.

| Document | Description | Est. Reading Time |
|----------|-------------|-------------------|
| [INSTALLATION.md](getting-started/INSTALLATION.md) | Complete setup instructions for n8n, Python, and reconnaissance tools | 15-20 min |
| [USAGE.md](getting-started/USAGE.md) | Practical usage examples, operation modes, and common workflows | 10-15 min |

**Quick Start Path**:
1. Install prerequisites → [INSTALLATION.md](getting-started/INSTALLATION.md)
2. Run your first scan → [USAGE.md](getting-started/USAGE.md)
3. Review output files → [USAGE.md - Output Files](getting-started/USAGE.md#mode-1-full-scan-recommended-for-new-targets)

---

## Configuration

Customize Reconductor to fit your needs.

| Document | Description | For |
|----------|-------------|-----|
| [CONFIGURATION.md](configuration/CONFIGURATION.md) | Complete configuration guide | All users |

**Key Configuration Topics**:
- **Tool Paths** - Custom installation locations
- **n8n Settings** - URL, timeouts, webhooks
- **Scanning Parameters** - Nuclei templates, rate limits, worker count
- **Output Directories** - Custom result locations
- **Environment Variables** - System-wide settings

---

## Architecture

Technical documentation for understanding the system.

| Document | Description | For |
|----------|-------------|-----|
| [WORKFLOWS.md](architecture/WORKFLOWS.md) | Complete workflow architecture and data flow | Developers, advanced users |
| [workflow_configuration_detailed.md](architecture/workflow_configuration_detailed.md) | Original technical specifications (archive) | Developers |

**Architecture Topics**:
- Phase 1: Subdomain Enumeration
- Phase 2: Live Host Validation
- Phase 3: Parallel Vulnerability Scanning
- IP-Centric Sharding Algorithm
- Worker Pool Management
- Data Flow Between Phases

---

## Guides

Problem-solving and troubleshooting resources.

| Document | Description | For |
|----------|-------------|-----|
| [TROUBLESHOOTING.md](guides/TROUBLESHOOTING.md) | Common issues and solutions | All users |

**Troubleshooting Topics**:
- Installation issues
- n8n connection problems
- Workflow execution errors
- Phase-specific issues
- Performance optimization
- Output file problems

---

## Contributing

Resources for contributors and developers.

| Document | Description | For |
|----------|-------------|-----|
| [CONTRIBUTING.md](contributing/CONTRIBUTING.md) | Contribution guidelines and development setup | Contributors |

**Contributing Topics**:
- Code of conduct
- Development environment setup
- Workflow development
- Testing procedures
- Documentation updates
- Submitting changes

---

## Documentation by User Role

### First-Time Users

**Goal**: Get Reconductor up and running quickly.

1. [INSTALLATION.md](getting-started/INSTALLATION.md) - Install all dependencies
2. [USAGE.md - Basic Usage](getting-started/USAGE.md#basic-usage) - Run your first scan
3. [TROUBLESHOOTING.md](guides/TROUBLESHOOTING.md) - If you encounter issues

### Bug Bounty Hunters

**Goal**: Efficient reconnaissance for bug bounty programs.

1. [USAGE.md - Bug Bounty Workflow](getting-started/USAGE.md#workflow-4-bug-bounty-workflow) - Complete workflow
2. [CONFIGURATION.md - Scanning Parameters](configuration/CONFIGURATION.md#scanning-parameters) - Optimize scanning
3. [USAGE.md - Filtering Results](getting-started/USAGE.md#filtering-results) - Extract critical findings
4. [USAGE.md - Scheduled Rescans](getting-started/USAGE.md#workflow-3-scheduled-rescans) - Continuous monitoring

### Security Researchers

**Goal**: Deep technical understanding and customization.

1. [WORKFLOWS.md](architecture/WORKFLOWS.md) - Complete architecture
2. [CONFIGURATION.md - Advanced Configuration](configuration/CONFIGURATION.md#advanced-configuration) - Deep customization
3. [USAGE.md - Advanced Usage](getting-started/USAGE.md#advanced-usage) - Complex scenarios
4. [workflow_configuration_detailed.md](architecture/workflow_configuration_detailed.md) - Technical specs

### Developers & Contributors

**Goal**: Understand internals and contribute improvements.

1. [WORKFLOWS.md](architecture/WORKFLOWS.md) - Architecture deep dive
2. [CONTRIBUTING.md](contributing/CONTRIBUTING.md) - Development setup
3. [workflow_configuration_detailed.md](architecture/workflow_configuration_detailed.md) - Original specs
4. [CONFIGURATION.md - n8n Workflow Configuration](configuration/CONFIGURATION.md#n8n-workflow-configuration) - Workflow customization

### System Administrators

**Goal**: Deploy and maintain Reconductor infrastructure.

1. [INSTALLATION.md](getting-started/INSTALLATION.md) - Deployment
2. [CONFIGURATION.md - Environment Variables](configuration/CONFIGURATION.md#environment-variables) - System config
3. [CONFIGURATION.md - Output Directory](configuration/CONFIGURATION.md#output-directory-configuration) - Storage management
4. [TROUBLESHOOTING.md - Performance Issues](guides/TROUBLESHOOTING.md#performance-issues) - Optimization

---

## Documentation by Topic

### Installation & Setup

| Topic | Document | Section |
|-------|----------|---------|
| System requirements | [INSTALLATION.md](getting-started/INSTALLATION.md) | System Requirements |
| Installing n8n | [INSTALLATION.md](getting-started/INSTALLATION.md) | Install n8n |
| Installing recon tools | [INSTALLATION.md](getting-started/INSTALLATION.md) | Install Reconnaissance Tools |
| Python dependencies | [INSTALLATION.md](getting-started/INSTALLATION.md) | Install Python Dependencies |
| Importing workflows | [INSTALLATION.md](getting-started/INSTALLATION.md) | Import n8n Workflows |
| Quick install script | [INSTALLATION.md](getting-started/INSTALLATION.md) | Quick Setup Script |

### Usage & Operations

| Topic | Document | Section |
|-------|----------|---------|
| Running the orchestrator | [USAGE.md](getting-started/USAGE.md) | Basic Usage |
| Full scan workflow | [USAGE.md](getting-started/USAGE.md) | Mode 1: Full Scan |
| Discovery only | [USAGE.md](getting-started/USAGE.md) | Mode 2: Discovery Only |
| Vulnerability scanning | [USAGE.md](getting-started/USAGE.md) | Mode 3: Vuln Scan Only |
| Webhook usage | [USAGE.md](getting-started/USAGE.md) | API/Webhook Usage |
| Monitoring progress | [USAGE.md](getting-started/USAGE.md) | Monitoring and Debugging |
| Filtering results | [USAGE.md](getting-started/USAGE.md) | Filtering Results |

### Configuration & Customization

| Topic | Document | Section |
|-------|----------|---------|
| Orchestrator settings | [CONFIGURATION.md](configuration/CONFIGURATION.md) | Orchestrator Configuration |
| Tool paths | [CONFIGURATION.md](configuration/CONFIGURATION.md) | Tool Path Configuration |
| n8n webhooks | [CONFIGURATION.md](configuration/CONFIGURATION.md) | n8n Workflow Configuration |
| Output directories | [CONFIGURATION.md](configuration/CONFIGURATION.md) | Output Directory Configuration |
| Nuclei parameters | [CONFIGURATION.md](configuration/CONFIGURATION.md) | Phase 3: Vulnerability Scanning |
| Worker pool size | [CONFIGURATION.md](configuration/CONFIGURATION.md) | Worker Pool Configuration |

### Architecture & Technical Details

| Topic | Document | Section |
|-------|----------|---------|
| Workflow overview | [WORKFLOWS.md](architecture/WORKFLOWS.md) | Overview |
| Phase 1 architecture | [WORKFLOWS.md](architecture/WORKFLOWS.md) | Phase 1: Subdomain Enumeration |
| Phase 2 architecture | [WORKFLOWS.md](architecture/WORKFLOWS.md) | Phase 2: Live Host Validation |
| Phase 3 architecture | [WORKFLOWS.md](architecture/WORKFLOWS.md) | Phase 3: Parallel Vulnerability Scanning |
| Data flow | [WORKFLOWS.md](architecture/WORKFLOWS.md) | Data Flow |
| IP-centric sharding | [WORKFLOWS.md](architecture/WORKFLOWS.md) | IP-Centric Sharding Algorithm |
| Original specifications | [workflow_configuration_detailed.md](architecture/workflow_configuration_detailed.md) | Full document |

### Troubleshooting & Support

| Topic | Document | Section |
|-------|----------|---------|
| Installation problems | [TROUBLESHOOTING.md](guides/TROUBLESHOOTING.md) | Installation Issues |
| n8n connectivity | [TROUBLESHOOTING.md](guides/TROUBLESHOOTING.md) | n8n Connection Issues |
| Workflow errors | [TROUBLESHOOTING.md](guides/TROUBLESHOOTING.md) | Workflow Execution Issues |
| Phase 3 workers | [TROUBLESHOOTING.md](guides/TROUBLESHOOTING.md) | Phase 3 Issues |
| Performance tuning | [TROUBLESHOOTING.md](guides/TROUBLESHOOTING.md) | Performance Issues |
| Output file issues | [TROUBLESHOOTING.md](guides/TROUBLESHOOTING.md) | Output Issues |

---

## Quick Reference Cards

### Installation Quick Reference

```bash
# Quick Install Script
./quick-install.sh

# Manual Installation
# 1. Install Go
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

# 2. Install reconnaissance tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 3. Install n8n
sudo npm install -g n8n

# 4. Start n8n
n8n start
```

See: [INSTALLATION.md](getting-started/INSTALLATION.md)

### Usage Quick Reference

```bash
# Run full scan
./recon_orchestrator.py  # Select mode 1

# Discovery only
./recon_orchestrator.py  # Select mode 2

# Rescan existing target
./recon_orchestrator.py  # Select mode 3

# Manual webhook trigger
curl -X POST http://localhost:5678/webhook/recon-phase1 \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

See: [USAGE.md](getting-started/USAGE.md)

### Troubleshooting Quick Reference

```bash
# Check n8n health
curl http://localhost:5678/healthz

# Check tools
which subfinder httpx dnsx nuclei

# Check outputs
ls -la /tmp/recon/example.com/

# Check worker status
ls /tmp/phase3_done_*
ps aux | grep nuclei

# View n8n logs
tail -f ~/.n8n/logs/n8n.log
```

See: [TROUBLESHOOTING.md](guides/TROUBLESHOOTING.md)

---

## External Resources

### Official Tool Documentation

- [n8n Documentation](https://docs.n8n.io)
- [Nuclei Documentation](https://docs.projectdiscovery.io/tools/nuclei/overview)
- [Subfinder GitHub](https://github.com/projectdiscovery/subfinder)
- [httpx GitHub](https://github.com/projectdiscovery/httpx)
- [dnsx GitHub](https://github.com/projectdiscovery/dnsx)

### Related Projects

- [ProjectDiscovery Tools](https://github.com/projectdiscovery)
- [n8n Workflow Library](https://n8n.io/workflows)

---

## Document Status

| Document | Status | Last Updated | Location |
|----------|--------|--------------|----------|
| README.md | Current | 2025-12-11 | Project root |
| INSTALLATION.md | Current | 2025-12-11 | getting-started/ |
| USAGE.md | Current | 2025-12-11 | getting-started/ |
| CONFIGURATION.md | Current | 2025-12-11 | configuration/ |
| WORKFLOWS.md | Current | 2025-12-11 | architecture/ |
| TROUBLESHOOTING.md | Current | 2025-12-11 | guides/ |
| CONTRIBUTING.md | Current | 2025-12-11 | contributing/ |
| workflow_configuration_detailed.md | Archive | 2025-12-11 | architecture/ |
| INDEX.md | Current | 2025-12-12 | docs/ |

---

## Documentation Maintenance

### Adding New Documentation

1. Create document in the appropriate subdirectory
2. Update this INDEX.md with links and descriptions
3. Add cross-references from related documents
4. Update the main README.md if it's a major addition

### Updating Existing Documentation

1. Update the document content
2. Update the "Last Updated" date in the document footer
3. Update the Document Status table in this INDEX
4. Update cross-references if structure changes

### Documentation Guidelines

- Use clear, descriptive headings
- Include table of contents for documents with 3+ sections
- Add code examples where applicable
- Link to related documentation
- Keep README.md concise - detailed docs go in /docs
- Use relative links for internal documentation

---

## Need Help?

Can't find what you're looking for?

1. **Use browser search** (Ctrl+F) to search this index
2. **Check** [TROUBLESHOOTING.md](guides/TROUBLESHOOTING.md) for common issues
3. **Review** the [main README](../README.md) for project overview
4. **Check** n8n workflow execution logs in the n8n UI

---

**Documentation Index Version**: 2.0
**Last Updated**: 2025-12-12
**Total Documentation Files**: 8
