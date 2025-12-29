## Wazumation

Wazumation is a local-only Python tool that reads and safely manages Wazuh `ossec.conf` configuration.

## Installation and first-time validation (Ubuntu 24, Python 3.12)

This section documents the exact workflow we used during setup and validation.
We cloned the repository into `/opt/wazumation` and created the virtual environment at `/opt/wazumation/venv` by running the steps below from the repository root.

### 1) Clone and enter repo

```bash
git clone https://github.com/<YOUR_GITHUB_USERNAME>/wazumation.git
cd wazumation
```

### 2) Create and activate venv

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3) Install the required python deps in the venv

```bash
python -m pip install --upgrade pip
python -m pip install pytest lxml
```

### 4) Confirm interpreter and packages

```bash
which python
python -c "import lxml; print(lxml.__version__)"
python -m pytest --version
```

### 5) Run tests using the venv python

```bash
python -m pytest -q
```

Expected result:

```text
32 passed in 17.96s
```

### Proof screenshot

This repository includes a proof screenshot of the passing test suite:

![pytest success proof](screenshots/pytest-success.png)

### 6) Create a clean ossec conf to test parsing

```bash
sed -n '1,/<\\/ossec_config>/p' /var/ossec/etc/ossec.conf > /tmp/ossec_fixed.conf
```

### 7) Validate XML

```bash
xmllint --noout /tmp/ossec_fixed.conf
```

No output means success.

### 8) Run the wazumation syscheck reader and show JSON output

```bash
wazumation read syscheck --config /tmp/ossec_fixed.conf
```

The output is JSON and no traceback should appear.

### 9) Generate the authoritative Wazuh section list (one-time in a source checkout)

```bash
python tools/sync_wazuh_sections.py
```

Expected output:

```text
[OK] Wrote 43 sections to data/wazuh_sections.json
```

## Troubleshooting

### 1) pytest not found

Symptom:

```bash
pytest -q
```

Result:

```text
pytest: command not found
```

Wrong path we tried:

```bash
sudo apt install python3-pytest
pytest -q
```

Why it failed:

```text
Installing pytest via apt does not reliably install it into your Python venv.
```

Correct fix:

```bash
source venv/bin/activate
python -m pip install pytest
python -m pytest -q
```

### 2) ModuleNotFoundError: lxml

Symptom:

```bash
python -m pytest -q
```

Result:

```text
ModuleNotFoundError: No module named 'lxml'
```

Correct fix:

```bash
source venv/bin/activate
python -m pip install lxml
python -m pytest -q
```

## Repo hygiene

1) `requirements.txt` includes the minimum required packages used in validation.
2) `.gitignore` excludes virtual environments, caches, and common Python build artifacts.

