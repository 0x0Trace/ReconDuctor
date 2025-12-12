# Installation Guide

Complete installation instructions for Reconductor and all dependencies.

---

## Table of Contents

- [System Requirements](#system-requirements)
- [1. Install n8n](#1-install-n8n)
- [2. Install Reconnaissance Tools](#2-install-reconnaissance-tools)
- [3. Install Python Dependencies](#3-install-python-dependencies)
- [4. Import n8n Workflows](#4-import-n8n-workflows)
- [5. Verify Installation](#5-verify-installation)
- [Quick Setup Script](#quick-setup-script)

---

## System Requirements

### Minimum Requirements

- **OS**: Linux/Unix-based system (Ubuntu 20.04+, Debian 10+, or similar)
- **RAM**: 4GB minimum, 8GB+ recommended
- **Disk Space**: 10GB+ for tools and results
- **CPU**: 2+ cores recommended for parallel scanning

### Required Software

- **Node.js**: v18.x or v20.x (for n8n)
- **Python**: 3.6 or higher
- **Go**: 1.19+ (for reconnaissance tools)
- **curl**: For HTTP requests
- **jq**: (Optional) For JSON parsing and debugging

---

## 1. Install n8n

n8n is the workflow automation platform that powers Reconductor.

### Option A: Using npm (Recommended)

```bash
# Install Node.js v20 (if not already installed)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install n8n globally
sudo npm install -g n8n

# Verify installation
n8n --version
```

### Option B: Using Docker

```bash
# Pull n8n Docker image
docker pull n8nio/n8n

# Run n8n in Docker
docker run -d \
  --name n8n \
  -p 5678:5678 \
  -v ~/.n8n:/home/node/.n8n \
  n8nio/n8n
```

### Start n8n

```bash
# Start n8n (npm installation)
n8n start

# Or with custom settings
n8n start --tunnel

# Access n8n UI at: http://localhost:5678
```

**Important**: Keep n8n running in the background for Reconductor to work.

---

## 2. Install Reconnaissance Tools

Reconductor requires several open-source reconnaissance tools.

### Install Go (if not installed)

```bash
# Download and install Go 1.21
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

# Add to PATH (add to ~/.bashrc or ~/.zshrc for persistence)
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Verify installation
go version
```

### Install Subfinder (Subdomain Enumeration)

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Verify installation
subfinder -version
```

**Configuration** (Optional but recommended):

```bash
# Create config directory
mkdir -p ~/.config/subfinder

# Add API keys for better results (optional)
cat > ~/.config/subfinder/provider-config.yaml << EOF
shodan:
  - YOUR_SHODAN_API_KEY
virustotal:
  - YOUR_VIRUSTOTAL_API_KEY
censys:
  - YOUR_CENSYS_API_ID:YOUR_CENSYS_SECRET
EOF
```

### Install httpx (HTTP Probe)

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Verify installation
httpx -version
```

### Install dnsx (DNS Toolkit)

```bash
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Verify installation
dnsx -version
```

### Install Nuclei (Vulnerability Scanner)

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Verify installation
nuclei -version

# Update nuclei templates (IMPORTANT!)
nuclei -update-templates
```

**Note**: Nuclei templates are updated regularly. Run `nuclei -update-templates` periodically to get the latest vulnerability checks.

### Install Additional Tools

```bash
# Install curl (usually pre-installed)
sudo apt-get install -y curl

# Install jq for JSON parsing (optional but useful)
sudo apt-get install -y jq
```

---

## 3. Install Python Dependencies

Reconductor's orchestrator script requires Python 3.6+ and the `requests` library.

```bash
# Check Python version
python3 --version

# Install pip if not already installed
sudo apt-get install -y python3-pip

# Install requests library
pip3 install requests

# Or use a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install requests
```

---

## 4. Import n8n Workflows

Import the 4 workflow files into your n8n instance.

### Method 1: Via n8n UI (Recommended)

1. Open n8n at `http://localhost:5678`
2. For each workflow JSON file:
   - Click **"Workflows"** → **"Add Workflow"** → **"Import from File"**
   - Select the workflow file
   - Click **"Import"**
   - Click **"Save"** to activate

### Workflows to Import (in order)

1. `Recon Automation - Phase 1_ Subdomain Enumeration.json`
2. `Recon Automation - Phase 2_ Live Host Validation.json`
3. `Recon - Phase 3 Main Manager.json`
4. `Recon - Phase 3 Worker (Nuclei Scan).json`

### Method 2: Via n8n CLI

```bash
# Copy workflows to n8n directory
cp "Recon Automation - Phase 1_ Subdomain Enumeration.json" ~/.n8n/workflows/
cp "Recon Automation - Phase 2_ Live Host Validation.json" ~/.n8n/workflows/
cp "Recon - Phase 3 Main Manager.json" ~/.n8n/workflows/
cp "Recon - Phase 3 Worker (Nuclei Scan).json" ~/.n8n/workflows/

# Restart n8n to load workflows
# (Stop n8n with Ctrl+C, then run: n8n start)
```

### Activate Workflows

After importing, ensure the following workflows are **Active**:

- Recon Automation - Phase 1: Subdomain Enumeration
- Recon Automation - Phase 2: Live Host Validation
- Recon - Phase 3 Main Manager

**Note**: The Phase 3 Worker should remain **Inactive** (it's spawned by the Manager).

---

## 5. Verify Installation

### Test n8n Connectivity

```bash
# Check n8n health
curl http://localhost:5678/healthz

# Expected output: {"status":"ok"}
```

### Test Tool Installations

```bash
# Test all reconnaissance tools
subfinder -version
httpx -version
dnsx -version
nuclei -version

# All should display version numbers without errors
```

### Test Python Orchestrator

```bash
# Make orchestrator executable
chmod +x recon_orchestrator.py

# Run orchestrator (will check n8n connectivity)
./recon_orchestrator.py

# You should see the Reconductor banner and mode selection menu
```

### Quick Test Run

```bash
# Test Phase 1 webhook
curl -X POST http://localhost:5678/webhook/recon-phase1 \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Check if results appear in /tmp/recon/example.com/
ls -la /tmp/recon/example.com/
```

---

## Quick Setup Script

For a faster installation, use this automated script:

```bash
#!/bin/bash
# quick-install.sh - Automated Reconductor installation

set -e

echo "=== Reconductor Quick Installation ==="
echo ""

# Check if running as non-root
if [ "$EUID" -eq 0 ]; then
   echo "Please run as non-root user (sudo will be used when needed)"
   exit 1
fi

# Update system
echo "[1/6] Updating system packages..."
sudo apt-get update -qq

# Install Go
echo "[2/6] Installing Go 1.21..."
if ! command -v go &> /dev/null; then
    wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    rm go1.21.5.linux-amd64.tar.gz

    # Add to PATH
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
else
    echo "  Go already installed: $(go version)"
fi

# Install Node.js and n8n
echo "[3/6] Installing Node.js and n8n..."
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

if ! command -v n8n &> /dev/null; then
    sudo npm install -g n8n
fi

# Install reconnaissance tools
echo "[4/6] Installing reconnaissance tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update nuclei templates
echo "[5/6] Updating nuclei templates..."
nuclei -update-templates -silent

# Install Python dependencies
echo "[6/6] Installing Python dependencies..."
sudo apt-get install -y python3-pip curl jq
pip3 install requests

# Make orchestrator executable
chmod +x recon_orchestrator.py

echo ""
echo "=== Installation Complete! ==="
echo ""
echo "Next steps:"
echo "  1. Start n8n: n8n start"
echo "  2. Import workflows via UI: http://localhost:5678"
echo "  3. Run orchestrator: ./recon_orchestrator.py"
echo ""
echo "See INSTALLATION.md for detailed configuration options."
```

Save as `quick-install.sh`, make it executable, and run:

```bash
chmod +x quick-install.sh
./quick-install.sh
```

---

## Path Configuration

By default, Reconductor expects tools to be in your `$PATH`. If you installed tools in custom locations, see [CONFIGURATION.md](../configuration/CONFIGURATION.md) for path customization.

---

## Troubleshooting

### Command Not Found: subfinder/httpx/dnsx/nuclei

**Solution**: Add Go bin directory to PATH

```bash
export PATH=$PATH:$HOME/go/bin

# Make permanent
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### n8n Connection Refused

**Solution**: Ensure n8n is running

```bash
# Check if n8n is running
ps aux | grep n8n

# Start n8n if not running
n8n start
```

### Permission Denied: /tmp/recon/

**Solution**: Create directory with proper permissions

```bash
sudo mkdir -p /tmp/recon
sudo chown $USER:$USER /tmp/recon
chmod 755 /tmp/recon
```

### Nuclei Templates Not Found

**Solution**: Update nuclei templates

```bash
nuclei -update-templates
```

---

## Next Steps

After installation:

1. Read [CONFIGURATION.md](../configuration/CONFIGURATION.md) to customize paths and settings
2. Review [WORKFLOWS.md](../architecture/WORKFLOWS.md) to understand the architecture
3. Check [USAGE.md](USAGE.md) for usage examples
4. Run your first scan with `./recon_orchestrator.py`

---

**Need Help?** Check [TROUBLESHOOTING.md](../guides/TROUBLESHOOTING.md) for common issues and solutions.
