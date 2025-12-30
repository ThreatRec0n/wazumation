# 🛡️ Wazumation

**Professional Wazuh Configuration Automation Tool**

One-command installation. Zero manual configuration. Enterprise-ready.

---

## ⚡ Quick Install

```bash
curl -sSL https://raw.githubusercontent.com/ThreatRec0n/Wazumation/main/install.sh | sudo bash
```

**That's it.** The installer will:
- ✅ Detect your environment automatically
- ✅ Install all dependencies
- ✅ Auto-fix XML configuration issues
- ✅ Run self-tests to verify functionality
- ✅ Make commands globally available

---

## 🎯 What is Wazumation?

Wazumation automates the complex process of configuring Wazuh SIEM. Instead of manually editing XML files and worrying about syntax errors, you get:

- **Feature-based configuration** - Enable/disable security features with one click
- **Automatic validation** - Never break your Wazuh config again
- **Change tracking** - Full audit trail of all modifications
- **Rollback capability** - Undo changes if needed
- **Modern GUI** - Visual interface for those who prefer it
- **CLI power** - Full command-line control for automation

---

## 📋 Requirements

- **Wazuh Manager** - Must be installed (this tool manages Wazuh config, not installation)
- **Ubuntu/Debian** - 20.04+ (other Linux distros may work)
- **Python** - 3.9+ (automatically installed if missing)
- **Root access** - Required for config file modifications

---

## 🚀 Features

### Available Security Configurations

| Feature ID | Description | What It Does |
|------------|-------------|--------------|
| `fim-enhanced` | Enhanced File Integrity Monitoring | Adds real-time file change detection with whodata |
| `auditd-monitoring` | Linux Audit Log Collection | Monitors system calls and security events |
| `vuln-detector` | Vulnerability Detection | Scans for CVEs in installed packages |
| `sca-cis` | CIS Benchmark Compliance | Checks compliance with security standards |
| `localfile-nginx` | Nginx Log Collection | Ingests and analyzes web server logs |
| `email-alerts` | Email Notifications | Sends alerts for critical events |

### Core Capabilities

- ✅ **Idempotent** - Running the same command multiple times is safe
- ✅ **Reversible** - Disable features as easily as you enable them
- ✅ **XML-aware** - Never corrupts your ossec.conf
- ✅ **Auto-backup** - Creates backups before every change
- ✅ **Audit logging** - Complete history of all modifications
- ✅ **Self-testing** - Built-in verification that everything works

---

## 📖 How It Works

### The Problem Wazumation Solves

Manually configuring Wazuh requires:
1. Understanding complex XML structure
2. Finding the right sections in ossec.conf
3. Not breaking XML syntax
4. Knowing which options conflict
5. Restarting services correctly
6. Verifying changes worked

**One mistake = broken security monitoring.**

### The Wazumation Solution

1. **You:** "Enable vulnerability detection"
2. **Wazumation:** 
   - Validates current config
   - Creates backup
   - Applies changes safely
   - Validates new config
   - Reloads Wazuh
   - Verifies changes applied
   - Updates audit log

**Result:** Working configuration in seconds, not hours.

---

## 💻 Command Line Usage

### List Available Features

```bash
wazumation --list
```

**Output:**
```
auditd-monitoring    Auditd monitoring (Linux)
email-alerts         Email alerts
fim-enhanced         File Integrity Monitoring enhancements
localfile-nginx      Nginx access log ingestion
sca-cis              CIS hardening / SCA enablement
vuln-detector        Vulnerability detector enablement
```

### Check Current Status

```bash
wazumation --status
```

**Output:**
```
Config: /var/ossec/etc/ossec.conf
State file: /var/lib/wazumation/state.json

Detected feature state (live config):
  auditd-monitoring: disabled
  email-alerts: disabled
  fim-enhanced: disabled
  localfile-nginx: disabled
  sca-cis: enabled
  vuln-detector: enabled
```

### Enable a Feature

```bash
# Dry run first (see what would change)
wazumation --enable fim-enhanced --dry-run

# Actually apply it
wazumation --enable fim-enhanced --approve-features
```

**What happens:**
1. ✅ Validates ossec.conf
2. ✅ Creates backup: `/var/ossec/etc/ossec.conf.backup.TIMESTAMP`
3. ✅ Applies changes to XML
4. ✅ Validates modified config
5. ✅ Reloads Wazuh service
6. ✅ Verifies changes detected
7. ✅ Logs to audit trail

### Disable a Feature

```bash
wazumation --disable vuln-detector --approve-features
```

**Safety:** Only removes what Wazumation added. Won't touch manual configurations.

### Enable Multiple Features

```bash
wazumation --enable fim-enhanced,auditd-monitoring,vuln-detector --approve-features
```

### View Configuration Diff

```bash
wazumation --diff-feature localfile-nginx
```

Shows exactly what will change in the XML.

### Run Self-Test

```bash
wazumation --self-test
```

**Tests performed:**
1. Applies a test configuration
2. Verifies detection works
3. Reverts changes
4. Confirms baseline restored
5. Validates Wazuh config
6. Checks backup system
7. Tests XML rejection (invalid syntax)

**Output on success:**
```
Config: /var/ossec/etc/ossec.conf
PASS: Tool synced

Phase: Preflight
Phase: Apply
Phase: Detect
Phase: Revert
Phase: Confirm
Phase: Safety gate

All phases passed!
```

### View Audit Log

```bash
wazumation audit
```

Shows complete history of all changes made by Wazumation.

### Verify Audit Integrity

```bash
wazumation verify
```

Checks that audit log hasn't been tampered with.

### Fix XML Issues

```bash
wazumation --fix-xml
```

Automatically fixes common XML problems like extra content after closing tags.

---

## 🎨 Graphical Interface (GUI)

### Launch GUI

```bash
wazumation --gui
```

### GUI Features

#### 1. Feature List (Left Panel)
- Shows all available features
- Current status indicated by color:
  - 🔴 Red = Disabled
  - 🟢 Green = Enabled
  - 🟠 Orange = Partially enabled
- Click to select features

#### 2. Feature Details (Right Panel)
- **Title** - Feature name
- **Description** - What it does
- **Detected status** - Current state
- **Configuration** - Required settings (if any)

#### 3. Service Status (Top Right)
Shows real-time Wazuh service state:
- 🟢 **Wazuh: RUNNING** - Service active
- 🔴 **Wazuh: STOPPED** - Service not running
- 🟠 **Wazuh: FAILED** - Service error

Auto-updates every 5 seconds.

#### 4. Action Buttons

- **Refresh** - Reload current status
- **Enable Selected** - Activate checked features
- **Disable Selected** - Deactivate checked features
- **Diff** - Show what will change
- **Apply** - Execute changes
- **Self Test** - Run verification

#### 5. Options

- ☑️ **Approve apply** - Must check to apply changes (safety gate)
- ☐ **Dry run** - Preview changes without applying

#### 6. Log Output (Bottom Panel)

Real-time output showing:
- Operations being performed
- Success/failure status
- Detailed error messages if issues occur

### GUI Self-Test

Click "Self Test" button to verify tool is working correctly.

**PASS popup means:**
- ✅ Tool can apply changes
- ✅ Detection works correctly
- ✅ Revert functionality works
- ✅ Validation is functioning
- ✅ Backup system operational

### Common GUI Workflows

#### Enable a Security Feature

1. Launch GUI: `wazumation --gui`
2. Select feature from list (e.g., "fim-enhanced")
3. Review details in right panel
4. Check "Approve apply" box
5. Click "Enable Selected"
6. Watch log output for progress
7. Status auto-refreshes when complete

#### Disable a Feature

1. Select enabled feature (green status)
2. Check "Approve apply"
3. Click "Disable Selected"
4. Confirm in dialog
5. Changes applied automatically

#### Preview Changes (Dry Run)

1. Select feature
2. Check "Dry run" box
3. Click "Enable Selected"
4. Review log output (no changes made)
5. Uncheck "Dry run" to actually apply

---

## 🔧 Advanced Usage

### Configuration Files

**Main config:**
- `/var/ossec/etc/ossec.conf` - Wazuh configuration (managed)

**Wazumation state:**
- `/var/lib/wazumation/state.json` - Current feature state
- `/var/lib/wazumation/feature_plans/*.json` - Change plans
- `/var/lib/wazumation/backups/*.conf` - Config backups
- `/var/lib/wazumation/audit.db` - Audit log database

### Custom Data Directory

```bash
wazumation --data-dir /custom/path --enable fim-enhanced --approve-features
```

### Specify Config Path

```bash
wazumation --config /path/to/ossec.conf --status
```

(Usually not needed - auto-discovery works)

### Verbose Output

```bash
wazumation --enable vuln-detector --approve-features --verbose
```

Shows detailed operation logs.

---

## 🛡️ Safety Features

### 1. Validation Before Changes

Every operation validates XML syntax before writing.

**If validation fails:**
- ❌ Changes are NOT applied
- 🔍 Detailed error shown
- 💡 Suggestions provided

### 2. Automatic Backups

Before **every** modification:
```
/var/ossec/etc/ossec.conf → /var/ossec/etc/ossec.conf.backup.TIMESTAMP
```

Restore if needed:
```bash
sudo cp /var/ossec/etc/ossec.conf.backup.1234567890 /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
```

### 3. Idempotency

Running the same command multiple times is safe:

```bash
wazumation --enable fim-enhanced --approve-features
# Run again
wazumation --enable fim-enhanced --approve-features
```

**Result:** No duplicate entries. Config unchanged.

### 4. Marker-Based Removal

When disabling features, only Wazumation-added content is removed.

Your manual configurations are **never touched**.

### 5. Rollback Capability

If something goes wrong:

```bash
# Check audit log
wazumation audit

# Find the change
# Restore from backup
sudo cp /var/ossec/etc/ossec.conf.backup.TIMESTAMP /var/ossec/etc/ossec.conf
```

---

## 🐛 Troubleshooting

### Self-Test Fails

**Symptom:**
```
FAIL: Tool not synced
```

**Solutions:**

1. **Check XML syntax:**
```bash
xmllint --noout /var/ossec/etc/ossec.conf
```

2. **Auto-fix common issues:**
```bash
wazumation --fix-xml
```

3. **Check Wazuh service:**
```bash
sudo systemctl status wazuh-manager
```

### Service Won't Restart

**Symptom:**
```
Failed to service_restart wazuh-manager
```

**Solutions:**

1. **Check service status:**
```bash
sudo systemctl status wazuh-manager
sudo journalctl -xeu wazuh-manager
```

2. **Start service manually:**
```bash
sudo systemctl start wazuh-manager
```

3. **Check config validity:**
```bash
sudo /var/ossec/bin/wazuh-control info -t
```

### GUI Won't Launch

**Symptom:**
```
ModuleNotFoundError: No module named 'tkinter'
```

**Solution:**
```bash
sudo apt-get install python3-tk
```

### Permission Denied

**Symptom:**
```
Permission denied: '/var/ossec/etc/ossec.conf'
```

**Solution:**
Run with sudo:
```bash
sudo wazumation --enable fim-enhanced --approve-features
```

### Feature Appears Enabled But Isn't Working

**Check detection:**
```bash
wazumation --status
```

**Check actual config:**
```bash
sudo grep -A 20 "<syscheck>" /var/ossec/etc/ossec.conf
```

**Restart Wazuh:**
```bash
sudo systemctl restart wazuh-manager
```

---

## 📊 Comparison to Manual Configuration

### Manual Wazuh Configuration

```xml
<!-- You have to find the right section -->
<ossec_config>
  <syscheck>
    <!-- Add these options in the right place -->
    <scan_on_start>yes</scan_on_start>
    <frequency>43200</frequency>
    <!-- Don't mess up the XML -->
    <whodata>yes</whodata>
    <!-- Hope you didn't break anything -->
  </syscheck>
</ossec_config>
```

**Then:**
1. Validate XML manually
2. Backup (if you remembered)
3. Restart service
4. Hope it works
5. Check logs if it doesn't
6. Restore backup if broken
7. Try again...

**Time:** 15-30 minutes  
**Error rate:** High  
**Anxiety level:** Maximum

### Wazumation

```bash
wazumation --enable fim-enhanced --approve-features
```

**Time:** 5 seconds  
**Error rate:** Zero  
**Anxiety level:** None  
**Coffee consumed:** Less ☕

---

## 🔐 Security Considerations

### Privileges Required

Wazumation needs root/sudo because it:
- Reads `/var/ossec/etc/ossec.conf`
- Writes to `/var/ossec/etc/ossec.conf`
- Restarts `wazuh-manager` service
- Creates backups in protected directories

### What Wazumation Touches

**Modifies:**
- `/var/ossec/etc/ossec.conf` (with backups)
- `/var/lib/wazumation/*` (state files)

**Never Modifies:**
- Wazuh binaries
- Wazuh rules
- Wazuh decoders
- Agent configurations
- Other system files

### Audit Trail

Every change is logged:
- When it happened
- Who ran it
- What changed
- Success/failure
- Config checksums

View with:
```bash
wazumation audit
```

Verify integrity:
```bash
wazumation verify
```

---

## 🤝 Contributing

We welcome contributions! Areas for improvement:

- **More features** - Additional Wazuh configurations
- **Better detection** - Smarter config parsing
- **UI enhancements** - More visual feedback
- **Platform support** - CentOS, RHEL, etc.
- **Documentation** - Tutorials, examples
- **Testing** - More edge cases

---

## 📜 License

MIT License - See LICENSE file for details.

---

## 🙏 Credits

Built for the Wazuh community by security professionals who got tired of manually editing XML files.

**Wazuh** is an open-source SIEM platform: https://wazuh.com

---

## 📞 Support

### Issues or Bugs

Report on GitHub: https://github.com/ThreatRec0n/Wazumation/issues

### Feature Requests

Open a GitHub issue with the `enhancement` label.

### Questions

Check existing issues or open a discussion.

---

## 🎓 Learn More

- **Wazuh Documentation**: https://documentation.wazuh.com/
- **OSSEC Config Reference**: https://www.ossec.net/docs/
- **CIS Benchmarks**: https://www.cisecurity.org/cis-benchmarks

---

**Made with ☕ and frustration with manual XML editing.**

