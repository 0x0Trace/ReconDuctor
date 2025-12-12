#!/bin/bash
#
# Reconductor Quick Installation Script
#
# Installs:
#  - Go 1.25.5
#  - Node.js 24.x via NVM and n8n
#  - ProjectDiscovery tools (subfinder, httpx, dnsx, nuclei)
#  - Python deps (requests)
#
# Run as a non-root user (sudo will be used when needed).
#
# Usage: ./quick-install.sh
#

set -euo pipefail

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
if [ "${EUID}" -eq 0 ]; then
  print_error "Please run as non-root user (sudo will be used when needed)"
  exit 1
fi

# Detect user shell RC file (best-effort)
detect_rc_file() {
  local shell_name
  shell_name="$(basename "${SHELL:-bash}")"
  case "$shell_name" in
    zsh)  echo "$HOME/.zshrc" ;;
    bash) echo "$HOME/.bashrc" ;;
    *)    echo "$HOME/.profile" ;;
  esac
}

RC_FILE="$(detect_rc_file)"

append_line_if_missing() {
  local line="$1"
  local file="$2"
  mkdir -p "$(dirname "$file")" 2>/dev/null || true
  touch "$file"
  if ! grep -qxF "$line" "$file"; then
    echo "$line" >> "$file"
  fi
}

# Banner
print_header "Reconductor Quick Installation"
echo ""
echo "This script will install:"
echo "  - Go 1.25.5"
echo "  - Node.js 24.x (via NVM) and n8n"
echo "  - Reconnaissance tools (subfinder, httpx, dnsx, nuclei)"
echo "  - Python dependencies"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo
if [[ ! "${REPLY}" =~ ^[Yy]$ ]]; then
  exit 1
fi

# [1/6] Update + prerequisites
print_step "[1/6] Updating system packages + installing prerequisites..."
sudo apt-get update -qq || print_warning "apt-get update failed, continuing anyway..."

# Core tooling needed early (curl/wget/tar/etc.)
sudo apt-get install -y \
  curl wget tar ca-certificates gnupg jq git \
  python3 python3-pip >/dev/null

print_success "Prerequisites installed"

# [2/6] Install Go
print_step "[2/6] Installing Go 1.25.5..."

GO_VERSION="1.25.5"

# Map architecture to Go arch
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) GO_ARCH="linux-amd64" ;;
  aarch64|arm64) GO_ARCH="linux-arm64" ;;
  armv6l) GO_ARCH="linux-armv6l" ;;
  i386|i686) GO_ARCH="linux-386" ;;
  *)
    print_error "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

GO_TAR="go${GO_VERSION}.${GO_ARCH}.tar.gz"
GO_URL="https://go.dev/dl/${GO_TAR}"

install_go() {
  wget -q --show-progress "$GO_URL"
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf "${GO_TAR}"
  rm -f "${GO_TAR}"

  # Persist PATH/GOPATH in the user's rc file
  append_line_if_missing 'export PATH="$PATH:/usr/local/go/bin"' "$RC_FILE"
  append_line_if_missing 'export GOPATH="$HOME/go"' "$RC_FILE"
  append_line_if_missing 'export PATH="$PATH:$GOPATH/bin"' "$RC_FILE"

  # Apply for current shell
  export PATH="$PATH:/usr/local/go/bin"
  export GOPATH="${GOPATH:-$HOME/go}"
  export PATH="$PATH:$GOPATH/bin"
  hash -r
}

if command -v go >/dev/null 2>&1; then
  print_warning "Go already installed: $(go version)"
  # Still ensure GOPATH/PATH for current run
  export GOPATH="${GOPATH:-$HOME/go}"
  export PATH="$PATH:/usr/local/go/bin:$GOPATH/bin"
  hash -r
else
  install_go
  print_success "Go installed: $(go version)"
fi

# [3/6] Install Node.js 24 via NVM + n8n
print_step "[3/6] Installing Node.js 24.x (via NVM) and n8n..."

# Install/Load NVM
export NVM_DIR="$HOME/.nvm"
if [ ! -s "$NVM_DIR/nvm.sh" ]; then
  # NVM installer will usually add sourcing lines to the user's rc; we still enforce it below.
  curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
fi

# Ensure rc sources NVM (idempotent)
append_line_if_missing 'export NVM_DIR="$HOME/.nvm"' "$RC_FILE"
append_line_if_missing '[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"' "$RC_FILE"
append_line_if_missing '[ -s "$NVM_DIR/bash_completion" ] && . "$NVM_DIR/bash_completion"' "$RC_FILE"

# Load NVM in current shell
# shellcheck disable=SC1090
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"

if ! command -v nvm >/dev/null 2>&1; then
  print_error "nvm failed to load. Open a new terminal or run: source \"$RC_FILE\""
  exit 1
fi

# Install and set Node 24 as default
nvm install 24
nvm alias default 24
nvm use 24

print_success "Node.js installed: $(node --version)"
print_success "npm version: $(npm --version)"

# Install n8n globally (under NVM-managed Node, no sudo)
if ! command -v n8n >/dev/null 2>&1; then
  npm install -g n8n
  hash -r
  print_success "n8n installed: $(n8n --version)"
else
  print_warning "n8n already installed: $(n8n --version)"
fi

# [4/6] Install recon tools
print_step "[4/6] Installing reconnaissance tools..."

# Ensure Go env is usable even if Go was preinstalled
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:/usr/local/go/bin:$GOPATH/bin"
hash -r

tools=("subfinder" "httpx" "dnsx" "nuclei" "anew")
tool_packages=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/tomnomnom/anew@latest"
)

for i in "${!tools[@]}"; do
  tool="${tools[$i]}"
  package="${tool_packages[$i]}"

  if command -v "$tool" >/dev/null 2>&1; then
    print_warning "$tool already installed"
  else
    echo "  Installing $tool..."
    go install -v "$package"
    hash -r
    print_success "$tool installed"
  fi
done

# [5/6] Update nuclei templates
print_step "[5/6] Updating nuclei templates..."
if command -v nuclei >/dev/null 2>&1; then
  nuclei -update-templates -silent
  print_success "Nuclei templates updated"
else
  print_error "Nuclei not found in PATH after installation (check GOPATH/bin in PATH)"
fi

# [6/6] Python deps
print_step "[6/6] Installing Python dependencies..."
if command -v pip3 >/dev/null 2>&1; then
  pip3 install --user requests >/dev/null
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
command -v go >/dev/null 2>&1 && echo "  $(go version)" || true
command -v node >/dev/null 2>&1 && echo "  Node.js $(node --version)" || true
command -v n8n  >/dev/null 2>&1 && echo "  n8n $(n8n --version)" || true
echo ""

# Verify tool installations
echo "Reconnaissance tools:"
for tool in subfinder httpx dnsx nuclei; do
  if command -v "$tool" >/dev/null 2>&1; then
    echo -e "  ${GREEN}✓${NC} $tool"
  else
    echo -e "  ${RED}✗${NC} $tool (not found - check PATH)"
  fi
done

echo ""
echo "Config persisted in: ${YELLOW}${RC_FILE}${NC}"
echo ""
echo "Next steps:"
echo -e "  1. Reload your shell config: ${YELLOW}source \"${RC_FILE}\"${NC}"
echo -e "  2. Start n8n: ${YELLOW}n8n start${NC}"
echo -e "  3. Import workflows via UI: ${YELLOW}http://localhost:5678${NC}"
echo -e "  4. Run orchestrator: ${YELLOW}./recon_orchestrator.py${NC}"
echo ""
echo "Documentation:"
echo "  - Installation guide: INSTALLATION.md"
echo "  - Configuration guide: CONFIGURATION.md"
echo "  - Usage examples: USAGE.md"
echo ""

# PATH sanity hint
if ! command -v subfinder >/dev/null 2>&1; then
  print_warning "Tools not in PATH yet. Run: source \"${RC_FILE}\""
fi

print_success "Installation script completed successfully!"
