## 1. Project Overview

Wazumation is a local-only Python tool that sanitizes, validates, and parses Wazuh (OSSEC) XML configuration files such as `ossec.conf`.

In real Wazuh environments, `ossec.conf` can become malformed (for example, trailing non-XML content after `</ossec_config>` or multiple `<ossec_config>` blocks). Malformed XML can break Wazuh configuration loading and cause service instability. This tool exists to make those problems detectable and avoidable by producing a clean XML block and structured output that automation can consume.

## 2. Use Cases

1) Validating Wazuh `ossec.conf` files before deployment
2) Preventing XML whitespace and trailing data issues that break parsers
3) Parsing Wazuh configuration into structured data (JSON) for automation
4) CI/CD and automation workflows for Wazuh environments

## Feature Selection (CLI + optional GUI)

Wazumation includes a feature selection mode that can enable or disable a curated set of common Wazuh configuration “features” on the **local Wazuh manager** by editing the real config files safely and idempotently.

### Feature CLI commands

1) List available features:

```bash
wazumation --list
```

2) Show current feature status:

```bash
wazumation --status
```

3) Enable one or more features (comma-separated):

```bash
wazumation --enable fim-enhanced,vuln-detector --approve-features
```

4) Disable one or more features (comma-separated):

```bash
wazumation --disable vuln-detector --approve-features
```

5) Show last recorded diff for an enabled feature:

```bash
wazumation --diff-feature fim-enhanced
```

6) Launch the GUI selector:

```bash
wazumation --gui
```

### Safety model for features

1) Changes are only applied to the **local machine**.
2) A change requires explicit approval using `--approve-features` (or use `--dry-run`).
3) File writes are atomic and backed up before modification.
4) If validation fails or service restart fails, the tool rolls back automatically.

### Backups and state

1) Backups are written under the selected `--data-dir` (default is `~/.wazumation` in current CLI).
2) Feature state is stored in `/var/lib/wazumation/state.json` when possible, otherwise `~/.wazumation/state.json`.

## 3. What This Tool Is NOT

1) Not a Wazuh replacement
2) Not an agent or manager installer
3) Not a live config editor

## 4. Prerequisites

1) Python 3.10+
2) A Python virtual environment
3) `lxml`
4) `xmllint` (from `libxml2-utils`)

## 5. Installation (exact commands)

1) Clone and enter repo:

```bash
git clone https://github.com/<YOUR_GITHUB_USERNAME>/wazumation.git
cd wazumation
```

2) Create and activate venv:

```bash
python3 -m venv venv
source venv/bin/activate
```

3) Install dependencies in the venv:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## 6. Validation and Testing

1) Create a clean config for testing parsing:

```bash
sed -n '1,/<\\/ossec_config>/p' /var/ossec/etc/ossec.conf > /tmp/ossec_fixed.conf
```

2) Validate XML:

```bash
xmllint --noout /tmp/ossec_fixed.conf
```

No output means success.

3) Run the test suite:

```bash
python -m pytest -q
```

Expected output includes:

```text
32 passed
```

4) Validate syscheck parsing (JSON output, no traceback):

```bash
wazumation read syscheck --config /tmp/ossec_fixed.conf
```

5) Generate the authoritative section list (one-time in a source checkout):

```bash
python tools/sync_wazuh_sections.py
```

Expected output:

```text
[OK] Wrote 43 sections to data/wazuh_sections.json
```

## 7. Screenshots

This repository includes a proof screenshot of a passing test run:

![pytest success proof](screenshots/pytest-success.png)

This screenshot proves that the test suite was executed from an activated virtual environment using `python -m pytest -q` and that it completed successfully with `32 passed`.

## 8. Troubleshooting

### 8.1 Missing lxml

1) Symptom:

```text
ModuleNotFoundError: No module named 'lxml'
```

2) Fix (install into the active venv):

```bash
source venv/bin/activate
python -m pip install lxml
```

### 8.2 pytest not found

1) Symptom:

```text
pytest: command not found
```

2) Wrong path we tried:

```bash
sudo apt install python3-pytest
pytest -q
```

3) Fix (install into the active venv):

```bash
source venv/bin/activate
python -m pip install pytest
python -m pytest -q
```

### 8.3 XML trailing whitespace / extra content errors

1) Symptom (commonly seen with `lxml` on real `ossec.conf`):

```text
lxml.etree.XMLSyntaxError: Extra content at the end of the document
```

2) Fix (extract a clean first block and re-validate):

```bash
sed -n '1,/<\\/ossec_config>/p' /var/ossec/etc/ossec.conf > /tmp/ossec_fixed.conf
xmllint --noout /tmp/ossec_fixed.conf
wazumation read syscheck --config /tmp/ossec_fixed.conf
```

### 8.4 Virtual environment not activated

1) Symptom:

```text
Installed packages are missing or the wrong pytest/python is being used.
```

2) Fix:

```bash
source venv/bin/activate
which python
python -m pytest --version
```

## 9. License

MIT

