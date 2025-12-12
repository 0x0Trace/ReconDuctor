#!/bin/bash
#
# Reconductor Quick Installation Script
#
# This script automates the installation of Reconductor and all dependencies.
# Run as a non-root user (sudo will be used when needed).
#
# Usage: ./quick-install.sh
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "${BLUE}=================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=================================================${NC}"
}

print_step() {
    echo -e "\n${GREEN}[$(date +%H:%M:%S)] $1${NC}"
}

print_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

print_success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
   print_error "Please run as non-root user (sudo will be used when needed)"
   exit 1
fi

print_header "Reconductor Quick Installation"
echo ""
echo "This script will install:"
echo "  - Go 1.21.5"
echo "  - Node.js 20.x and n8n"
echo "  - Reconnaissance tools (subfinder, httpx, dnsx, nuclei)"
echo "  - Python dependencies"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

# Update system
print_step "[1/6] Updating system packages..."
sudo apt-get update -qq || {
    print_warning "apt-get update failed, continuing anyway..."
}

# Install Go
print_step "[2/6] Installing Go 1.21.5..."
if command -v go &> /dev/null; then
    print_warning "Go already installed: $(go version)"
else
    GO_VERSION="1.21.5"
    GO_ARCH="linux-amd64"
    GO_TAR="go${GO_VERSION}.${GO_ARCH}.tar.gz"

    wget -q --show-progress https://go.dev/dl/${GO_TAR}
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf ${GO_TAR}
    rm ${GO_TAR}

    # Add to PATH
    if ! grep -q '/usr/local/go/bin' ~/.bashrc; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        echo 'export GOPATH=$HOME/go' >> ~/.bashrc
        echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    fi

    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin

    print_success "Go installed: $(go version)"
fi

# Install Node.js and n8n
print_step "[3/6] Installing Node.js and n8n..."
if ! command -v node &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
    print_success "Node.js installed: $(node --version)"
else
    print_warning "Node.js already installed: $(node --version)"
fi

if ! command -v n8n &> /dev/null; then
    sudo npm install -g n8n
    print_success "n8n installed: $(n8n --version)"
else
    print_warning "n8n already installed: $(n8n --version)"
fi

# Install reconnaissance tools
print_step "[4/6] Installing reconnaissance tools..."

tools=("subfinder" "httpx" "dnsx" "nuclei")
tool_packages=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
)

for i in "${!tools[@]}"; do
    tool="${tools[$i]}"
    package="${tool_packages[$i]}"

    if command -v $tool &> /dev/null; then
        print_warning "$tool already installed"
    else
        echo "  Installing $tool..."
        go install -v $package
        print_success "$tool installed"
    fi
done

# Update nuclei templates
print_step "[5/6] Updating nuclei templates..."
if command -v nuclei &> /dev/null; then
    nuclei -update-templates -silent
    print_success "Nuclei templates updated"
else
    print_error "Nuclei not found in PATH after installation"
fi

# Install Python dependencies
print_step "[6/6] Installing Python dependencies..."
if ! command -v python3 &> /dev/null; then
    sudo apt-get install -y python3 python3-pip
fi

sudo apt-get install -y curl jq

if command -v pip3 &> /dev/null; then
    pip3 install requests --user
    print_success "Python requests library installed"
else
    print_error "pip3 not found"
fi

# Make orchestrator executable
if [ -f "recon_orchestrator.py" ]; then
    chmod +x recon_orchestrator.py
    print_success "Orchestrator made executable"
else
    print_warning "recon_orchestrator.py not found in current directory"
fi

# Final summary
print_header "Installation Complete!"
echo ""
echo "Installed components:"
echo "  $(go version)"
echo "  Node.js $(node --version)"
echo "  n8n $(n8n --version)"
echo ""

# Verify tool installations
echo "Reconnaissance tools:"
for tool in subfinder httpx dnsx nuclei; do
    if command -v $tool &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool"
    else
        echo -e "  ${RED}✗${NC} $tool (not found - check PATH)"
    fi
done

echo ""
echo "Next steps:"
echo "  1. Source your bashrc: ${YELLOW}source ~/.bashrc${NC}"
echo "  2. Start n8n: ${YELLOW}n8n start${NC}"
echo "  3. Import workflows via UI: ${YELLOW}http://localhost:5678${NC}"
echo "  4. Run orchestrator: ${YELLOW}./recon_orchestrator.py${NC}"
echo ""
echo "Documentation:"
echo "  - Installation guide: INSTALLATION.md"
echo "  - Configuration guide: CONFIGURATION.md"
echo "  - Usage examples: USAGE.md"
echo ""

# Check if PATH needs to be reloaded
if ! command -v subfinder &> /dev/null; then
    print_warning "Tools not in PATH. Run: ${YELLOW}source ~/.bashrc${NC}"
fi

print_success "Installation script completed successfully!"
