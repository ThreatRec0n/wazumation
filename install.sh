#!/bin/bash
###############################################################################
# Wazumation One-Line Installer
# Usage:
#   curl -sSL https://raw.githubusercontent.com/ThreatRec0n/Wazumation/main/install.sh | sudo bash
###############################################################################

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_error() { echo -e "${RED}[✗]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Wazumation Installer"
echo "  Automated Wazuh Configuration Management"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

log_info "Detecting environment..."

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  log_error "Please run as root (use sudo)"
  exit 1
fi

if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS="${ID:-unknown}"
  log_success "Detected: ${PRETTY_NAME:-$OS}"
else
  log_error "Cannot detect OS (missing /etc/os-release)"
  exit 1
fi

WAZUH_CONTROL="/var/ossec/bin/wazuh-control"
if [ ! -f "$WAZUH_CONTROL" ]; then
  log_error "Wazuh manager not detected (missing $WAZUH_CONTROL)"
  log_info "Install Wazuh first: https://documentation.wazuh.com/"
  exit 1
fi
log_success "Wazuh manager detected"

if ! command -v python3 >/dev/null 2>&1; then
  log_error "Python 3 is required"
  exit 1
fi
log_success "Python detected: $(python3 --version 2>/dev/null || true)"

log_info "Installing system dependencies..."
case "$OS" in
  ubuntu|debian)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq git python3-venv python3-pip libxml2-utils python3-tk
    ;;
  rhel|centos|fedora)
    # best-effort
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y git python3-pip python3-virtualenv libxml2 python3-tkinter || true
    else
      yum install -y git python3-pip python3-virtualenv libxml2 python3-tkinter || true
    fi
    ;;
  *)
    log_warn "Unsupported OS ($OS). Continuing with best-effort install (git/python3 required)."
    ;;
esac
log_success "Dependencies installed"

INSTALL_DIR="/opt/Wazumation"
log_info "Installing Wazumation to $INSTALL_DIR ..."

rm -rf "$INSTALL_DIR"
git clone -q https://github.com/ThreatRec0n/Wazumation.git "$INSTALL_DIR"
cd "$INSTALL_DIR"

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements.txt >/dev/null
python -m pip install -e . >/dev/null

ln -sf "$INSTALL_DIR/.venv/bin/wazumation" /usr/local/bin/wazumation
ln -sf "$INSTALL_DIR/.venv/bin/wazumation-gui" /usr/local/bin/wazumation-gui

log_success "Wazumation installed"

log_info "Checking Wazuh configuration..."
OSSEC_CONF="/var/ossec/etc/ossec.conf"
if command -v xmllint >/dev/null 2>&1 && [ -f "$OSSEC_CONF" ]; then
  if ! xmllint --noout "$OSSEC_CONF" >/dev/null 2>&1; then
    log_warn "Detected XML issues in $OSSEC_CONF"
    log_info "Attempting auto-fix..."

    # Run the fix command (keep output on screen + save to log)
    if wazumation --fix-xml 2>&1 | tee /tmp/wazumation-fix.log; then
      log_success "Auto-fix completed"
      if xmllint --noout "$OSSEC_CONF" >/dev/null 2>&1; then
        log_success "Configuration is now valid"
      else
        log_error "Auto-fix didn't fully resolve the issue"
        log_info "Manual fix required. See: /tmp/wazumation-fix.log"
        xmllint --noout "$OSSEC_CONF" 2>&1 | head -5 || true
      fi
    else
      log_error "Auto-fix failed"
      log_info "Manual fix required. See: /tmp/wazumation-fix.log"
    fi
  else
    log_success "Configuration is valid"
  fi
fi

log_info "Running self-test..."
if wazumation --self-test >/dev/null 2>&1; then
  log_success "Self-test PASSED"
else
  log_warn "Self-test failed. Run: wazumation --self-test (see output) and fix ossec.conf if needed."
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log_success "Installation Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Quick Start:"
echo "  wazumation --list"
echo "  wazumation --status"
echo "  wazumation --self-test"
echo "  wazumation --gui"
echo ""


