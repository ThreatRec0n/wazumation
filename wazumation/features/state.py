"""Local state tracking for enabled/disabled features (reversible changes)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def default_state_path() -> Path:
    # Prefer a system location on Linux when running with permissions, else fallback to user home.
    if os.name == "posix":
        p = Path("/var/lib/wazumation/state.json")
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            return p
        except Exception:
            pass
    return Path.home() / ".wazumation" / "state.json"


@dataclass
class FeatureState:
    enabled: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    last_applied_at: Optional[str] = None
    modified_files: List[str] = field(default_factory=list)
    ossec_conf_path: Optional[str] = None

    @classmethod
    def load(cls, path: Path) -> "FeatureState":
        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            enabled=data.get("enabled", {}),
            last_applied_at=data.get("last_applied_at"),
            modified_files=data.get("modified_files", []),
            ossec_conf_path=data.get("ossec_conf_path"),
        )

    def save(self, path: Path, *, touch_last_applied: bool = True) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if touch_last_applied:
            self.last_applied_at = datetime.now(timezone.utc).isoformat()
        path.write_text(
            json.dumps(
                {
                    "enabled": self.enabled,
                    "last_applied_at": self.last_applied_at,
                    "modified_files": self.modified_files,
                    "ossec_conf_path": self.ossec_conf_path,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )


