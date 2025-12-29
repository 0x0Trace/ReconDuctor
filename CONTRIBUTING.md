# Contributing to ReconDuctor v2

Thank you for your interest in contributing to ReconDuctor! This document provides guidelines for contributing to the project.

## Getting Started

### Development Setup

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/reconductor/reconductor-v2.git
   cd reconductor-v2
   ```

2. **Create a virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -e .  # Install in development mode
   ```

4. **Install external tools**
   See README.md for the full list of required tools (subfinder, httpx, nuclei, etc.)

5. **Set up API keys (for AI features)**
   ```bash
   export ANTHROPIC_API_KEY="sk-ant-..."
   ```

## Project Structure

```
reconductor/
|-- core/           # Core framework (orchestrator, config, database)
|-- models/         # Data models (subdomain, host, finding, scan)
|-- modules/        # Feature modules
|   |-- subdomain/  # Enumeration (passive, puredns, alterx)
|   |-- validation/ # HTTP probing, DNS, port scanning
|   |-- scanning/   # Nuclei, takeover detection
|   |-- recon/      # Shodan, GAU, screenshots
|   +-- ai/         # AI agents (wordlist, triage, GAU URL filter)
|-- utils/          # Utilities (executor, parser, tempfiles)
+-- cli.py          # CLI interface
```

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/reconductor/reconductor-v2/issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Tool versions (`reconductor check-tools`)
   - Python version (`python --version`)

### Suggesting Features

1. Open an issue with the `enhancement` label
2. Describe the feature and its use case
3. Explain how it fits into the existing workflow

### Submitting Pull Requests

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow the existing code style
   - Add docstrings for new functions/classes
   - Update README if adding new features

3. **Test your changes**
   ```bash
   # Run existing tests
   pytest tests/

   # Test manually
   reconductor scan example.com --passive-only
   ```

4. **Commit with clear messages**
   ```bash
   git commit -m "Add: Feature description"
   git commit -m "Fix: Bug description"
   git commit -m "Refactor: What was refactored"
   ```

5. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

## Code Style

### Python Style

- Follow PEP 8
- Use type hints for function parameters and return values
- Maximum line length: 100 characters
- Use descriptive variable names

### Example

```python
async def fetch_urls(
    self,
    domain: str,
    include_subs: bool = True,
    timeout: int = 60,
) -> GauResult:
    """
    Fetch historical URLs for a domain.

    Args:
        domain: Target domain
        include_subs: Include subdomains
        timeout: Request timeout in seconds

    Returns:
        GauResult with categorized URLs
    """
    logger.info(f"Fetching historical URLs for {domain}")
    # ... implementation
```

### Tool Wrappers

When adding new external tool integrations:

1. Create a wrapper class in the appropriate module
2. Use `ToolExecutor` for running commands
3. Implement `is_available()` static method
4. Handle errors gracefully with logging
5. Parse output into structured data models

Example structure:
```python
class NewToolWrapper:
    def __init__(self, executor: Optional[ToolExecutor] = None):
        self.executor = executor or get_executor()

    async def run(self, targets: list[str]) -> ToolResult:
        if not self.is_available():
            logger.warning("Tool not available")
            return ToolResult(errors=["Tool not found"])

        # Build command, execute, parse results
        ...

    @staticmethod
    def is_available() -> bool:
        return get_executor().check_tool_available("tool-name")
```

### AI Agents

When adding new AI agents:

1. Create agent in `modules/ai/`
2. Use appropriate Claude model (haiku for fast, sonnet for complex)
3. Include clear system prompts with examples
4. Handle API errors and fallbacks
5. Add to orchestrator if part of scan pipeline

Existing AI agents:
- `wordlist_agent.py` - Generates domain-aware wordlists for bruteforce
- `triage_agent.py` - Analyzes Nuclei findings and prioritizes vulnerabilities
- `gau_filter_agent.py` - Filters and ranks historical URLs by exploit likelihood

## Testing

### Running Tests

```bash
# All tests
pytest tests/

# Specific test file
pytest tests/test_gau_wrapper.py

# With coverage
pytest --cov=reconductor tests/
```

### Writing Tests

- Place tests in `tests/` directory
- Use pytest fixtures for common setup
- Mock external API calls
- Test both success and error cases

## Documentation

- Update README.md for user-facing changes
- Update DOCUMENTATION.md for detailed technical docs
- Update CHANGELOG.md for version changes (follows [Keep a Changelog](https://keepachangelog.com/))
- Add docstrings to all public functions/classes
- Include usage examples in docstrings

## Questions?

- Open an issue for questions
- Check existing issues and documentation first

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
