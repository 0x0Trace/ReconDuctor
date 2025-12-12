# Contributing to Reconductor

Thank you for considering contributing to Reconductor! This guide will help you get started.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Workflow Development](#workflow-development)
- [Testing](#testing)
- [Documentation](#documentation)
- [Submitting Changes](#submitting-changes)

---

## Code of Conduct

- Be respectful and professional
- Focus on constructive feedback
- Help maintain a welcoming environment
- Use this tool responsibly and ethically

---

## Getting Started

1. **Understand the Architecture**
   - Read [WORKFLOWS.md](../architecture/WORKFLOWS.md) for technical details
   - Review [workflow_configuration_detailed.md](../architecture/workflow_configuration_detailed.md)
   - Understand the manager-worker model

2. **Set Up Development Environment**
   - Follow [INSTALLATION.md](../getting-started/INSTALLATION.md)
   - Import workflows into n8n
   - Test with a small domain

3. **Find Issues to Work On**
   - Check existing issues (if using issue tracker)
   - Look for "TODO" comments in code
   - Identify performance improvements
   - Enhance documentation

---

## How to Contribute

### Reporting Bugs

When reporting bugs, include:

1. **System Information**
   ```bash
   uname -a
   python3 --version
   n8n --version
   subfinder -version
   httpx -version
   dnsx -version
   nuclei -version
   ```

2. **Steps to Reproduce**
   - Exact commands run
   - Domain/target used (if not sensitive)
   - Expected vs actual behavior

3. **Logs and Output**
   ```bash
   # n8n logs
   tail -100 ~/.n8n/logs/n8n.log

   # Orchestrator output
   # Copy full terminal output

   # File listings
   ls -laR /tmp/recon/domain/
   ```

4. **Workflow Configuration**
   - Workflow IDs
   - Any custom modifications
   - Screenshots if applicable

### Suggesting Enhancements

Enhancement suggestions should include:

1. **Use Case**: Why is this needed?
2. **Proposed Solution**: How would it work?
3. **Alternatives**: Other ways to achieve this?
4. **Impact**: What would this improve?

### Documentation Improvements

Documentation contributions are always welcome:

- Fix typos or unclear wording
- Add missing examples
- Improve installation instructions
- Update troubleshooting guides
- Add new use cases to USAGE.md

---

## Development Setup

### Fork and Clone

```bash
# Fork the repository (if using Git)
# Clone your fork
git clone https://github.com/yourusername/reconductor.git
cd reconductor

# Create feature branch
git checkout -b feature/your-feature-name
```

### Development Environment

```bash
# Install all dependencies
./quick-install.sh

# Start n8n
n8n start

# Import workflows
# Via n8n UI at http://localhost:5678
```

### Testing Environment

Use test domains for development:

```bash
# Safe test domains
- example.com
- test.com
- google.com (for Phase 1/2 only)

# Avoid testing on:
- Production systems without permission
- Sensitive targets
- Third-party services
```

---

## Workflow Development

### Modifying Workflows

1. **Make Changes in n8n UI**
   - Open workflow in n8n
   - Make modifications
   - Test thoroughly

2. **Export Updated Workflow**
   - Click "..." menu → "Download"
   - Replace old JSON file
   - Update documentation

3. **Document Changes**
   - Update WORKFLOWS.md if architecture changed
   - Update CONFIGURATION.md if new settings
   - Update workflow_configuration_detailed.md
   - Add to version history in README.md

### Workflow Naming Conventions

- **Nodes**: Use descriptive names (e.g., "Run Nuclei Scan" not "Execute1")
- **Variables**: Use camelCase (e.g., `workerCount`, `targetFile`)
- **Constants**: Use UPPER_SNAKE_CASE (e.g., `MAX_WORKERS`, `TIMEOUT_MS`)

### Code Style for n8n Nodes

```javascript
// Good: Clear, commented, error-handled
const hosts = $input.all();
const workerCount = 5;

// Validate input
if (!hosts || hosts.length === 0) {
  throw new Error('No hosts provided');
}

// Process with error handling
try {
  const results = hosts.map(host => {
    // Process host
    return processedHost;
  });

  return results;
} catch (error) {
  console.error('Processing failed:', error);
  throw error;
}
```

### Testing Workflows

```bash
# Test each phase independently

# Phase 1
curl -X POST http://localhost:5678/webhook/recon-phase1 \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Phase 2
curl -X POST http://localhost:5678/webhook/recon-phase2 \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "subdomains": ["www.example.com"]}'

# Phase 3
curl -X POST http://localhost:5678/webhook/recon-phase3-parallel \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Verify outputs
ls -la /tmp/recon/example.com/
jq . /tmp/recon/example.com/phase2_data.json
```

---

## Testing

### Manual Testing Checklist

Before submitting changes, test:

- [ ] Phase 1 discovers subdomains
- [ ] Phase 2 validates hosts and includes IP addresses
- [ ] Phase 3 workers start in parallel (5 nuclei processes)
- [ ] All workers complete and create marker files
- [ ] Final report includes all findings
- [ ] Output files are valid JSON/JSONL
- [ ] HTML reports render correctly
- [ ] Orchestrator handles all 3 modes
- [ ] Error handling works (test with invalid domain)
- [ ] Timeouts work correctly

### Test Domains

```bash
# Small target (fast testing)
example.com  # ~5-10 subdomains

# Medium target
github.com   # ~50-100 subdomains

# Large target (only if needed)
google.com   # 1000+ subdomains (Phase 1/2 only!)
```

### Performance Testing

```bash
# Measure execution time
time ./recon_orchestrator.py

# Monitor resource usage
htop  # CPU/memory
iotop # Disk I/O

# Count parallel workers
watch -n 1 'ps aux | grep nuclei | grep -v grep | wc -l'
```

---

## Documentation

### Documentation Standards

- Use clear, concise language
- Include code examples
- Add command outputs where helpful
- Use proper Markdown formatting
- Link between related docs

### Updating Documentation

When making changes, update relevant docs:

| Change Type | Update These Files |
|-------------|-------------------|
| New feature | README.md, USAGE.md, WORKFLOWS.md |
| Configuration | CONFIGURATION.md, README.md |
| Bug fix | TROUBLESHOOTING.md, WORKFLOWS.md |
| Installation | INSTALLATION.md, README.md |
| Architecture | WORKFLOWS.md, docs/workflow_configuration_detailed.md |

### Documentation Structure

```
/home/zerotrace/projects/reconductor/
├── README.md                          # Main overview
├── INSTALLATION.md                    # Setup guide
├── CONFIGURATION.md                   # Customization
├── USAGE.md                           # Examples
├── WORKFLOWS.md                       # Architecture
├── TROUBLESHOOTING.md                 # Issues
├── CONTRIBUTING.md                    # This file
├── docs/
│   └── workflow_configuration_detailed.md  # Technical details
└── examples/
    ├── ip-centric-sharding.js         # Code examples
    ├── nuclei-command.sh
    ├── binary-data-parsing.js
    └── phase2-output-format.json
```

---

## Submitting Changes

### Before Submitting

1. **Test Thoroughly**
   - Run all 3 modes
   - Test error conditions
   - Verify documentation accuracy

2. **Update Documentation**
   - Add/update relevant docs
   - Include examples
   - Update version history

3. **Clean Up**
   ```bash
   # Remove test files
   rm -rf /tmp/recon/test*

   # Remove temp files
   rm -f /tmp/phase3_*

   # Check for debug code
   grep -r "console.log" *.js
   ```

### Commit Guidelines

```bash
# Use descriptive commit messages
git commit -m "Add support for custom worker count in Phase 3"

# Not:
git commit -m "Update file"

# For bug fixes:
git commit -m "Fix JSONL parsing in Phase 3 report generation (v6.3)"

# For documentation:
git commit -m "docs: Add troubleshooting guide for Phase 3 workers"
```

### Commit Message Format

```
<type>: <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `perf`: Performance improvement
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance tasks

Example:
```
feat: Add support for custom nuclei templates

- Add configuration option for template directory
- Update Phase 3 Worker to use custom templates
- Document in CONFIGURATION.md

Closes #123
```

---

## Pull Request Process

1. **Create Pull Request**
   - Use descriptive title
   - Reference related issues
   - Explain what and why

2. **PR Description Template**
   ```markdown
   ## Changes
   - List of changes made

   ## Testing
   - How was this tested?
   - Test results

   ## Documentation
   - [ ] Updated README.md (if needed)
   - [ ] Updated relevant guides
   - [ ] Added examples (if applicable)

   ## Checklist
   - [ ] Code tested with example.com
   - [ ] Documentation updated
   - [ ] No debug code left
   - [ ] Workflows exported
   ```

3. **Review Process**
   - Address review comments
   - Update documentation if requested
   - Test suggested changes

---

## Areas for Contribution

### High Priority

1. **Performance Improvements**
   - Optimize worker allocation
   - Improve nuclei template selection
   - Reduce memory usage

2. **Feature Additions**
   - Resume capability for interrupted scans
   - CSV export format
   - Email notifications
   - Slack/Discord webhooks

3. **Testing**
   - Automated testing framework
   - CI/CD pipeline
   - Integration tests

### Medium Priority

1. **Documentation**
   - Video tutorials
   - More examples
   - Architecture diagrams
   - API documentation

2. **Tools Integration**
   - Additional recon tools
   - Custom tool plugins
   - Tool version management

3. **UI Improvements**
   - Web dashboard
   - Progress visualization
   - Interactive reports

### Low Priority

1. **Convenience Features**
   - Docker deployment
   - Configuration file support
   - Preset scan profiles

---

## Questions?

If you have questions about contributing:

1. Check existing documentation
2. Review closed issues
3. Ask in discussions (if available)
4. Open a new issue with "Question:" prefix

---

## Recognition

Contributors will be recognized in:
- README.md contributor section
- Release notes
- Documentation credits

---

**Thank you for contributing to Reconductor!**

Your contributions help make reconnaissance automation better for everyone.

---

**Last Updated**: 2025-12-11
