"""Service health monitor (best-effort) for Wazuh manager.

This is intentionally lightweight and safe:
- Never loops forever
- Uses existing service manager + XML healer hooks
- Works as an optional helper for "zero-touch" recovery flows
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import List, Optional, Tuple

from wazumation.core.xml_healer import XMLHealer
from wazumation.features.service_manager import WazuhServiceManager


class ServiceHealthMonitor:
    def __init__(self, *, config_path: Path = Path("/var/ossec/etc/ossec.conf"), validator=None):
        self.config_path = Path(config_path)
        self.validator = validator

    def diagnose(self, *, lines: int = 80) -> str:
        """Return recent systemd logs for wazuh-manager (best-effort)."""
        if os.name != "posix":
            return "diagnose: not supported on non-posix"
        try:
            r = subprocess.run(
                ["journalctl", "-u", "wazuh-manager", "-n", str(lines), "--no-pager"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
        except Exception as e:
            return f"diagnose failed: {e}"

    def ensure_healthy(self, *, max_attempts: int = 3) -> Tuple[bool, List[str]]:
        """Ensure wazuh-manager is running; attempt repair if not."""
        notes: List[str] = []

        for attempt in range(max_attempts):
            status = WazuhServiceManager.get_status()
            notes.append(f"Attempt {attempt + 1}: status={status}")
            if status == "running":
                return True, notes

            # If logs indicate XML parse error, heal config.
            diag = self.diagnose(lines=50)
            if "Error reading XML file" in diag or "(1226)" in diag or "XML" in diag:
                heal = XMLHealer(self.config_path, validator=self.validator).heal()
                notes.extend([f"xml-heal: {x}" for x in heal.fixes])

            ok, msg = WazuhServiceManager.restart()
            notes.append(("restart: ok: " if ok else "restart: fail: ") + msg)

            # exponential backoff
            time.sleep(2 ** attempt)

        # Final status
        status = WazuhServiceManager.get_status()
        notes.append(f"final status={status}")
        return status == "running", notes


