#!/bin/bash
#
# IMMEDIATE FIX: Wazuh XML Error Auto-Healer
# Fixes common "ERROR: (1226): Error reading XML file 'etc/ossec.conf': (line 0)"
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/ThreatRec0n/Wazumation/main/fix_wazuh_now.sh | sudo bash
# Or (after install):
#   sudo bash fix_wazuh_now.sh
#
# Notes:
# - Uses Wazumation's built-in XMLHealer (`wazumation --fix-xml`)
# - Rolls back to backup on failure
# - Does NOT overwrite with a minimal config unless you set NUCLEAR=1
#

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo "============================================================"
echo "Wazuh XML Error Auto-Healer (Wazumation)"
echo "============================================================"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  log_error "Please run as root or with sudo"
  exit 1
fi

CONFIG_FILE="/var/ossec/etc/ossec.conf"
if [ ! -f "$CONFIG_FILE" ]; then
  log_error "Config file not found: $CONFIG_FILE"
  exit 1
fi

BACKUP_FILE="/var/ossec/etc/ossec.conf.backup.$(date +%Y%m%d_%H%M%S)"

log_info "Creating backup: $BACKUP_FILE"
cp "$CONFIG_FILE" "$BACKUP_FILE"

if ! command -v wazumation >/dev/null 2>&1; then
  log_warn "wazumation command not found. Attempting to run via /usr/local/bin/wazumation ..."
fi

WAZUMATION_BIN="${WAZUMATION_BIN:-wazumation}"
if [ -x "/usr/local/bin/wazumation" ]; then
  WAZUMATION_BIN="/usr/local/bin/wazumation"
fi

log_info "Healing XML configuration via: $WAZUMATION_BIN --fix-xml"
set +e
HEAL_OUT="$($WAZUMATION_BIN --fix-xml 2>&1)"
HEAL_RC=$?
set -e
echo "$HEAL_OUT"
if [ $HEAL_RC -ne 0 ]; then
  log_warn "Healer returned non-zero (continuing to restart attempt)."
fi

log_info "Reloading systemd daemon (best-effort)..."
systemctl daemon-reload >/dev/null 2>&1 || true

log_info "Restarting wazuh-manager (start if stopped)..."
if systemctl is-active --quiet wazuh-manager; then
  systemctl restart wazuh-manager
else
  systemctl start wazuh-manager
fi

sleep 3

log_info "Checking service status..."
if systemctl is-active --quiet wazuh-manager; then
  log_success "wazuh-manager is running"

  # Quick scan for XML/1226 errors
  if journalctl -u wazuh-manager -n 30 --no-pager 2>/dev/null | grep -Ei "error.*1226|error.*xml" >/dev/null; then
    log_warn "Still seeing XML-related errors in recent logs."
    log_info "Showing last 30 lines:"
    journalctl -u wazuh-manager -n 30 --no-pager 2>/dev/null | tail -30 || true

    if [ "${NUCLEAR:-0}" = "1" ]; then
      log_warn "NUCLEAR=1 set. Writing minimal config (last resort)."
      cat > "$CONFIG_FILE" << 'MINIMAL_EOF'
<?xml version="1.0" encoding="UTF-8"?>
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
  </global>
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
  </remote>
  <alerts>
    <log_alert_level>3</log_alert_level>
  </alerts>
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <list>etc/lists/audit-keys</list>
  </ruleset>
  <authd>
    <disabled>no</disabled>
    <port>1515</port>
  </authd>
</ossec_config>
MINIMAL_EOF
      systemctl daemon-reload >/dev/null 2>&1 || true
      systemctl restart wazuh-manager || true
      sleep 3
      if systemctl is-active --quiet wazuh-manager; then
        log_success "Emergency recovery successful with minimal config"
        log_warn "You will need to restore/reapply your real configuration."
      else
        log_error "Emergency recovery failed; restoring backup."
        cp "$BACKUP_FILE" "$CONFIG_FILE"
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl restart wazuh-manager || true
        exit 1
      fi
    else
      log_warn "Not applying minimal config automatically. Re-run with NUCLEAR=1 only if you accept losing config content."
    fi
  fi

  echo ""
  echo "============================================================"
  echo -e "${GREEN}✓ FIX COMPLETE${NC}"
  echo "============================================================"
  echo "Service Status: $(systemctl is-active wazuh-manager 2>/dev/null || echo unknown)"
  echo "Backup saved: $BACKUP_FILE"
  echo ""
  exit 0
else
  log_error "Service failed to start"
  log_info "Recent errors:"
  journalctl -u wazuh-manager -n 40 --no-pager 2>/dev/null | grep -i error || true
  log_info "Restoring backup: $BACKUP_FILE"
  cp "$BACKUP_FILE" "$CONFIG_FILE"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl restart wazuh-manager >/dev/null 2>&1 || true
  exit 1
fi


