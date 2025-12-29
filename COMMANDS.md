# Wazumation CLI Commands Reference

## Basic Usage

All commands require `--config` to specify the Wazuh configuration file path (default: `/var/ossec/etc/ossec.conf`).

## Commands

### One-time: sync authoritative plugin list (repo checkout)

If you are running from a fresh source checkout and `data/wazuh_sections.json` is missing, generate it:

```bash
python3 tools/sync_wazuh_sections.py
```

### `list-plugins` - List supported ossec.conf sections

Prints every supported section/plugin name derived from the official Wazuh ossec.conf reference index.

```bash
python -m wazumation.cli.main list-plugins
```

Output format: `<section>`

---

### `read` - Read Current Configuration

Reads and displays the current configuration state for a module.

```bash
wazumation read <section> --config /path/to/ossec.conf
```

**Example:**
```bash
wazumation read syscheck --config test_ossec.conf
```

**Output:** JSON representation of current state

---

### `plan` - Create Change Plan

Creates a change plan by comparing current state with desired state.

```bash
wazumation plan <section> --config /path/to/ossec.conf \
  --desired <desired_state.json> --output <plan.json> --data-dir <dir>
```

**Example:**
```bash
wazumation plan syscheck --config test_ossec.conf \
  --desired examples/syscheck_desired.json --output my_plan.json --data-dir ./.wazumation_test
```

**Output:**
- Creates `plan.json` file
- Prints plan ID and summary

**Desired State JSON Format:**
See `examples/` directory for examples. Each plugin has its own format.

---

### `diff` - Show Plan Diff

Displays a unified diff preview of all changes in a plan.

```bash
wazumation diff <plan.json> --data-dir <dir>
```

**Example:**
```bash
wazumation diff my_plan.json
```

**Output:** Unified diff showing file changes and service operations

---

### `apply` - Apply Change Plan

Applies a change plan. Requires `--approve` flag for safety.

```bash
wazumation apply <plan.json> --approve [--dry-run] --config /path/to/ossec.conf --data-dir <dir>
```

**Example (dry-run):**
```bash
wazumation apply my_plan.json --approve --dry-run --config test_ossec.conf --data-dir ./.wazumation_test
```

**Example (real apply):**
```bash
wazumation apply my_plan.json --approve --config test_ossec.conf --data-dir ./.wazumation_test
```

**Safety Features:**
- `--approve` flag required (no accidental applies)
- `--dry-run` mode for testing
- Automatic backups before changes
- Validation before and after apply
- Automatic rollback on failure
- Service restarts only on Linux with systemctl

---

### `audit` - View Audit Log

Queries the immutable audit log.

```bash
wazumation audit [--module <module>] [--user <user>] [--limit <n>]
```

**Example:**
```bash
wazumation audit --module syscheck --limit 50
```

**Output:** List of audit entries with timestamp, user, action, module, result

---

### `verify` - Verify Audit Chain Integrity

Verifies the cryptographic hash chain of the audit log.

```bash
wazumation verify --data-dir <dir>
```

**Output:**
- `[OK] Audit chain integrity verified` - Chain is valid
- `[FAIL] Audit chain integrity failed:` - Chain is broken (tampering detected)

---

## Global Options

- `--config <path>` - Path to ossec.conf (default: `/var/ossec/etc/ossec.conf`)
- `--data-dir <path>` - Data directory for audit logs and backups (default: `~/.wazumation`)
- `--dry-run` - Dry run mode (no actual changes)
- `--verbose, -v` - Verbose output

---

## Example Workflow

```bash
# 1. Read current state
wazumation read syscheck --config /var/ossec/etc/ossec.conf > current.json

# 2. Create desired state file (edit current.json or create new)
cat > desired.json <<EOF
{
  "disabled": "yes",
  "frequency": "86400"
}
EOF

# 3. Create plan
wazumation plan syscheck --config /var/ossec/etc/ossec.conf \
  --desired desired.json --output plan.json --data-dir ~/.wazumation

# 4. Review diff
wazumation diff plan.json --data-dir ~/.wazumation

# 5. Test apply (dry-run)
wazumation apply plan.json --approve --dry-run --config /var/ossec/etc/ossec.conf --data-dir ~/.wazumation

# 6. Apply for real
wazumation apply plan.json --approve --config /var/ossec/etc/ossec.conf --data-dir ~/.wazumation

# 7. Verify audit log
wazumation audit --module syscheck

# 8. Verify chain integrity
wazumation verify --data-dir ~/.wazumation
```


