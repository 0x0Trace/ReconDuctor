# Reconductor Documentation Index

Complete guide to all Reconductor documentation.

---

## Quick Navigation

### Getting Started
- [Main README](../README.md) - Project overview and quick start
- [Installation Guide](../INSTALLATION.md) - Complete setup instructions
- [Quick Install Script](../quick-install.sh) - Automated installation

### Usage
- [Usage Guide](../USAGE.md) - Practical examples and common workflows
- [Configuration Guide](../CONFIGURATION.md) - Customize settings and paths

### Technical Documentation
- [Workflow Architecture](../WORKFLOWS.md) - Technical workflow details
- [Detailed Configuration](workflow_configuration_detailed.md) - Original technical docs
- [Troubleshooting Guide](../TROUBLESHOOTING.md) - Common issues and solutions

### Contributing
- [Contributing Guide](../CONTRIBUTING.md) - How to contribute

---

## Documentation Structure

```
reconductor/
│
├── README.md                      # Start here - Project overview
├── INSTALLATION.md                # Step-by-step installation
├── CONFIGURATION.md               # Customize tool paths and settings
├── USAGE.md                       # Practical examples and workflows
├── WORKFLOWS.md                   # Technical architecture details
├── TROUBLESHOOTING.md             # Issue resolution guide
├── CONTRIBUTING.md                # Contribution guidelines
├── quick-install.sh               # Automated installer
│
├── docs/                          # Additional documentation
│   ├── INDEX.md                   # This file
│   └── workflow_configuration_detailed.md  # Original technical docs
│
└── examples/                      # Code examples
    ├── ip-centric-sharding.js     # Sharding algorithm
    ├── nuclei-command.sh          # WAF-safe nuclei config
    ├── binary-data-parsing.js     # n8n binary data handling
    └── phase2-output-format.json  # Phase 2 data structure
```

---

## Documentation by Topic

### Installation & Setup

| Document | Description | Audience |
|----------|-------------|----------|
| [INSTALLATION.md](../INSTALLATION.md) | Complete installation guide | All users |
| [quick-install.sh](../quick-install.sh) | Automated installer | Linux users |
| README.md → Prerequisites | System requirements | All users |

### Configuration & Customization

| Document | Description | Audience |
|----------|-------------|----------|
| [CONFIGURATION.md](../CONFIGURATION.md) | Full configuration guide | All users |
| CONFIGURATION.md → Tool Paths | Custom tool locations | Advanced users |
| CONFIGURATION.md → Scanning Parameters | Nuclei tuning | Security testers |
| [workflow_configuration_detailed.md](workflow_configuration_detailed.md) | Original technical specs | Developers |

### Usage & Examples

| Document | Description | Audience |
|----------|-------------|----------|
| [USAGE.md](../USAGE.md) | Practical usage examples | All users |
| USAGE.md → Common Workflows | Real-world scenarios | Bug bounty hunters |
| USAGE.md → API/Webhook Usage | Programmatic access | Automation engineers |
| USAGE.md → Monitoring | Progress tracking | All users |

### Architecture & Development

| Document | Description | Audience |
|----------|-------------|----------|
| [WORKFLOWS.md](../WORKFLOWS.md) | Complete architecture | Developers |
| WORKFLOWS.md → Phase 3 Architecture | Parallel execution model | Developers |
| WORKFLOWS.md → Data Flow | Inter-phase communication | Developers |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Development guide | Contributors |
| [examples/](../examples/) | Code samples | Developers |

### Troubleshooting

| Document | Description | Audience |
|----------|-------------|----------|
| [TROUBLESHOOTING.md](../TROUBLESHOOTING.md) | Common issues | All users |
| TROUBLESHOOTING.md → Installation Issues | Setup problems | New users |
| TROUBLESHOOTING.md → Phase 3 Issues | Worker problems | Advanced users |

---

## Documentation by User Role

### First-Time Users

1. Start with [README.md](../README.md)
2. Follow [INSTALLATION.md](../INSTALLATION.md)
3. Try examples in [USAGE.md](../USAGE.md)
4. Refer to [TROUBLESHOOTING.md](../TROUBLESHOOTING.md) if issues occur

### Bug Bounty Hunters

1. [USAGE.md](../USAGE.md) → Bug Bounty Workflow
2. [CONFIGURATION.md](../CONFIGURATION.md) → Scanning Parameters
3. [USAGE.md](../USAGE.md) → Filtering Results
4. [USAGE.md](../USAGE.md) → Exporting Results

### Security Researchers

1. [WORKFLOWS.md](../WORKFLOWS.md) → Architecture Overview
2. [CONFIGURATION.md](../CONFIGURATION.md) → Advanced Configuration
3. [USAGE.md](../USAGE.md) → Advanced Usage
4. [examples/nuclei-command.sh](../examples/nuclei-command.sh) → Nuclei tuning

### Developers

1. [WORKFLOWS.md](../WORKFLOWS.md) → Complete Architecture
2. [CONTRIBUTING.md](../CONTRIBUTING.md) → Development Guide
3. [workflow_configuration_detailed.md](workflow_configuration_detailed.md) → Technical Specs
4. [examples/](../examples/) → Code Samples

### System Administrators

1. [INSTALLATION.md](../INSTALLATION.md) → Installation
2. [CONFIGURATION.md](../CONFIGURATION.md) → Environment Variables
3. [CONFIGURATION.md](../CONFIGURATION.md) → Output Directory
4. [TROUBLESHOOTING.md](../TROUBLESHOOTING.md) → Performance Issues

---

## Quick Reference Cards

### Installation Quick Reference

```bash
# Quick Install
./quick-install.sh

# Manual Install
# 1. Install Go
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

# 2. Install tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# 3. Install n8n
sudo npm install -g n8n

# 4. Start n8n
n8n start
```

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

### Troubleshooting Quick Reference

```bash
# Check n8n
curl http://localhost:5678/healthz

# Check tools
which subfinder httpx dnsx nuclei

# Check outputs
ls -la /tmp/recon/example.com/

# Check workers
ps aux | grep nuclei
ls /tmp/phase3_done_*

# View logs
tail -f ~/.n8n/logs/n8n.log
```

---

## Code Examples Index

### JavaScript (n8n Code Nodes)

- [ip-centric-sharding.js](../examples/ip-centric-sharding.js) - Host distribution algorithm
- [binary-data-parsing.js](../examples/binary-data-parsing.js) - n8n binary data handling

### Shell Scripts

- [nuclei-command.sh](../examples/nuclei-command.sh) - WAF-safe nuclei configuration
- [quick-install.sh](../quick-install.sh) - Installation automation

### JSON Examples

- [phase2-output-format.json](../examples/phase2-output-format.json) - Phase 2 data structure

---

## Document Status

| Document | Status | Last Updated | Version |
|----------|--------|--------------|---------|
| README.md | Current | 2025-12-11 | 6.3 |
| INSTALLATION.md | Current | 2025-12-11 | 1.0 |
| CONFIGURATION.md | Current | 2025-12-11 | 1.0 |
| USAGE.md | Current | 2025-12-11 | 1.0 |
| WORKFLOWS.md | Current | 2025-12-11 | 6.3 |
| TROUBLESHOOTING.md | Current | 2025-12-11 | 1.0 |
| CONTRIBUTING.md | Current | 2025-12-11 | 1.0 |
| workflow_configuration_detailed.md | Archive | 2025-12-11 | 6.3 |

---

## External Resources

### Tool Documentation

- [n8n Documentation](https://docs.n8n.io)
- [Subfinder GitHub](https://github.com/projectdiscovery/subfinder)
- [httpx GitHub](https://github.com/projectdiscovery/httpx)
- [dnsx GitHub](https://github.com/projectdiscovery/dnsx)
- [Nuclei Documentation](https://docs.projectdiscovery.io/tools/nuclei/overview)

### Related Projects

- [ProjectDiscovery Tools](https://github.com/projectdiscovery)
- [n8n Workflow Library](https://n8n.io/workflows)

---

## Documentation Maintenance

### Adding New Documentation

1. Create document in appropriate location
2. Update this INDEX.md
3. Link from relevant existing docs
4. Update README.md if major addition

### Updating Existing Documentation

1. Update document content
2. Update "Last Updated" date
3. Increment version if major changes
4. Update INDEX.md if structure changes

---

## Need Help?

Can't find what you're looking for?

1. Use Ctrl+F to search this index
2. Check [TROUBLESHOOTING.md](../TROUBLESHOOTING.md)
3. Review [FAQ section in USAGE.md](../USAGE.md)
4. Check workflow execution logs in n8n

---

**Last Updated**: 2025-12-11
**Index Version**: 1.0
