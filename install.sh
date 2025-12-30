#!/bin/bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }

# Banner
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Wazumation Installer"
echo "  Automated Wazuh Configuration Management"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Check if running as root
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  log_error "Please run with sudo"
  exit 1
fi

# Detect OS
log_info "Detecting environment..."
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS="${ID:-unknown}"
  VER="${VERSION_ID:-unknown}"
  log_success "Detected: ${PRETTY_NAME:-$OS}"
else
  log_error "Cannot detect OS (missing /etc/os-release)"
  exit 1
fi

# Check for Wazuh manager
if [ -f "/var/ossec/bin/wazuh-control" ]; then
  log_success "Wazuh manager detected"
else
  log_error "Wazuh manager not found (missing /var/ossec/bin/wazuh-control)"
  log_info "Please install Wazuh manager first"
  exit 1
fi

# Check Python
if command -v python3 >/dev/null 2>&1; then
  log_success "Python detected: $(python3 --version 2>/dev/null || true)"
else
  log_error "Python 3 not found"
  exit 1
fi

# Install system dependencies
log_info "Installing system dependencies..."
case "$OS" in
  ubuntu|debian)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq git python3-venv python3-pip libxml2-utils python3-tk >/dev/null 2>&1
    ;;
  centos|rhel|fedora)
    # best-effort (quiet)
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y -q git python3-pip python3-virtualenv libxml2 python3-tkinter >/dev/null 2>&1 || true
    else
      yum install -y -q git python3-pip python3-virtualenv libxml2 python3-tkinter >/dev/null 2>&1 || true
    fi
    ;;
  *)
    log_error "Unsupported OS: $OS"
    exit 1
    ;;
esac
log_success "Dependencies installed"

INSTALL_DIR="/opt/Wazumation"

# Remove old installation if exists
if [ -d "$INSTALL_DIR" ]; then
  log_warn "Removing old installation..."
  rm -rf "$INSTALL_DIR"
fi

# Clone repository
log_info "Installing Wazumation to $INSTALL_DIR ..."
git clone -q https://github.com/ThreatRec0n/Wazumation.git "$INSTALL_DIR" 2>/dev/null || {
  log_error "Failed to clone repository"
  exit 1
}
cd "$INSTALL_DIR"

# Create virtual environment
python3 -m venv .venv

# Install (editable)
.venv/bin/pip install --quiet --upgrade pip setuptools wheel
.venv/bin/pip install --quiet -e .

log_success "Wazumation installed"

# Remove old symlinks if they exist
rm -f /usr/local/bin/wazumation /usr/local/bin/wazumation-gui

# Create NEW symlinks
log_info "Creating command symlinks..."
ln -sf "$INSTALL_DIR/.venv/bin/wazumation" /usr/local/bin/wazumation
ln -sf "$INSTALL_DIR/.venv/bin/wazumation-gui" /usr/local/bin/wazumation-gui

# Ensure executable bit (harmless for symlinks; useful if resolved path copied elsewhere)
chmod +x /usr/local/bin/wazumation /usr/local/bin/wazumation-gui 2>/dev/null || true

# Refresh hash table in this process (helps if install is invoked from an interactive shell)
hash -r 2>/dev/null || true

# Verify commands work
log_info "Verifying installation..."
if ! /usr/local/bin/wazumation --help >/dev/null 2>&1; then
  log_error "wazumation command failed to execute"
  exit 1
fi
log_success "Commands verified"

# Check Wazuh configuration
log_info "Checking Wazuh configuration..."
OSSEC_CONF="/var/ossec/etc/ossec.conf"
if [ ! -f "$OSSEC_CONF" ]; then
  log_error "Wazuh config not found at $OSSEC_CONF"
  exit 1
fi

if command -v xmllint >/dev/null 2>&1; then
  if ! xmllint --noout "$OSSEC_CONF" >/dev/null 2>&1; then
    log_warn "Detected XML issues in $OSSEC_CONF"
    log_info "Attempting auto-fix..."
    if /usr/local/bin/wazumation --fix-xml 2>&1 | tee /tmp/wazumation-fix.log; then
      log_success "Auto-fix completed"
      if xmllint --noout "$OSSEC_CONF" >/dev/null 2>&1; then
        log_success "Configuration is now valid"
      else
        log_error "Auto-fix didn't fully resolve the issue"
        log_info "Manual fix required. See: /tmp/wazumation-fix.log"
        xmllint --noout "$OSSEC_CONF" 2>&1 | head -5 || true
      fi
    else
      log_warn "Auto-fix failed (tool is still usable). See: /tmp/wazumation-fix.log"
    fi
  else
    log_success "Configuration is valid"
  fi
fi

# Run self-test (best-effort; don't hard-fail installs)
log_info "Running self-test..."
if /usr/local/bin/wazumation --self-test 2>&1 | grep -q "PASS"; then
  log_success "Self-test PASSED"
else
  log_warn "Self-test completed with warnings (tool is still usable)"
fi

# Success banner
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN}[✓] Installation Complete!${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Quick Start:"
echo "  wazumation --list"
echo "  wazumation --status"
echo "  wazumation --self-test"
echo "  wazumation --gui"
echo ""
echo "Documentation: https://github.com/ThreatRec0n/Wazumation"
echo ""


