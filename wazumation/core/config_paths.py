"""Production config path detection for Wazuh manager ossec.conf (no fixture defaults)."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

from wazumation.features.state import FeatureState


COMMON_PATHS = [
    Path("/var/ossec/etc/ossec.conf"),
    Path("/usr/local/ossec/etc/ossec.conf"),
    Path("/opt/ossec/etc/ossec.conf"),
]


def detect_ossec_conf_path(*, config_override: Optional[Path], state_path: Path) -> Path:
    """
    Detect the real Wazuh manager ossec.conf path and persist it to the state file.

    Order:
      1) CLI override --config (if provided)
      2) env var WAZUMATION_CONFIG
      3) stored state: ossec_conf_path (if exists)
      4) common Wazuh paths
      5) parse /etc/ossec-init.conf for DIRECTORY-like values
      6) find /var -maxdepth 4 -name ossec.conf
    """
    tried: List[str] = []

    def _accept(p: Path) -> Optional[Path]:
        if not p:
            return None
        tried.append(str(p))
        if p.exists() and p.is_file():
            _persist(p)
            return p
        return None

    def _persist(p: Path) -> None:
        try:
            st = FeatureState.load(state_path)
            st.ossec_conf_path = str(p)
            st.save(state_path, touch_last_applied=False)
        except Exception:
            # Best-effort persistence; detection can still proceed.
            pass

    # 1) explicit override
    if config_override is not None:
        p = Path(config_override)
        if p.exists():
            _persist(p)
            return p
        raise RuntimeError(f"Config file not found: {p}")

    # 2) env var
    env_path = os.environ.get("WAZUMATION_CONFIG")
    if env_path:
        p = Path(env_path)
        if p.exists():
            _persist(p)
            return p
        tried.append(f"$WAZUMATION_CONFIG={env_path}")

    # 3) state
    try:
        st = FeatureState.load(state_path)
        if st.ossec_conf_path:
            p = Path(st.ossec_conf_path)
            tried.append(f"state:{p}")
            if p.exists():
                return p
    except Exception:
        pass

    # 4) common
    for p in COMMON_PATHS:
        found = _accept(p)
        if found:
            return found

    # 5) parse /etc/ossec-init.conf
    init_conf = Path("/etc/ossec-init.conf")
    tried.append(str(init_conf))
    if init_conf.exists():
        try:
            txt = init_conf.read_text(encoding="utf-8", errors="replace")
            # Common formats include DIRECTORY="/var/ossec"
            m = re.search(r'^\s*(DIRECTORY|OSSEC_DIR|OSSEC_HOME)\s*=\s*"?([^"\n]+)"?\s*$', txt, re.MULTILINE)
            if m:
                base = Path(m.group(2).strip())
                p = base / "etc" / "ossec.conf"
                found = _accept(p)
                if found:
                    return found
        except Exception:
            pass

    # 6) find under /var (linux)
    if os.name == "posix":
        try:
            tried.append("find:/var")
            r = subprocess.run(
                ["find", "/var", "-maxdepth", "4", "-name", "ossec.conf"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if r.stdout:
                first = r.stdout.splitlines()[0].strip()
                if first:
                    p = Path(first)
                    if p.exists():
                        _persist(p)
                        return p
        except Exception:
            pass

    raise RuntimeError(
        "Wazumation could not locate a Wazuh manager ossec.conf. "
        "This tool runs on Wazuh manager nodes only. "
        f"Tried: {', '.join(tried)}"
    )


