"""Syscheck (FIM) configuration plugin."""

from typing import Dict, Any, List, Tuple
from wazumation.wazuh.plugins.base_plugin import BaseWazuhPlugin


class SyscheckPlugin(BaseWazuhPlugin):
    """Plugin for syscheck (File Integrity Monitoring) configuration."""

    def __init__(self):
        """Initialize syscheck plugin."""
        super().__init__("syscheck", "syscheck", ["manager", "agent"])

    def get_default_state(self) -> Dict[str, Any]:
        """Return default syscheck configuration."""
        return {
            "children": {
                "disabled": {"text": "no"},
                "frequency": {"text": "43200"},
                "scan_on_start": {"text": "yes"},
                "auto_ignore": {"text": "no"},
                "directories": [
                    {
                        "attributes": {"check_all": "yes"},
                        "text": "/etc,/usr/bin,/usr/sbin",
                    }
                ],
            },
        }

    def get_schema(self) -> Dict[str, Any]:
        """Return schema for syscheck section."""
        return {
            "type": "object",
            "properties": {
                "disabled": {"type": "string", "enum": ["yes", "no"]},
                "frequency": {"type": "string"},
                "scan_on_start": {"type": "string", "enum": ["yes", "no"]},
                "auto_ignore": {"type": "string", "enum": ["yes", "no"]},
            },
        }

    def _normalize_state(self, section_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize syscheck section."""
        normalized = {}
        if "attributes" in section_data:
            normalized.update(section_data["attributes"])
        if "children" in section_data:
            for key, value in section_data["children"].items():
                if isinstance(value, list):
                    normalized[key] = value
                elif isinstance(value, dict) and "text" in value:
                    normalized[key] = value["text"]
                else:
                    normalized[key] = value
        return normalized

    def _denormalize_state(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Convert normalized state back to XML."""
        children: Dict[str, Any] = {}
        for key, value in state.items():
            if isinstance(value, list):
                children[key] = value
            elif isinstance(value, str):
                children[key] = {"text": value}
            else:
                children[key] = value
        return {"children": children} if children else {}

    def validate(self, state: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate syscheck configuration."""
        errors = []
        if "disabled" in state and state["disabled"] not in ["yes", "no"]:
            errors.append("disabled must be 'yes' or 'no'")
        if "frequency" in state:
            try:
                freq = int(state["frequency"])
                if freq < 60:
                    errors.append("frequency must be at least 60 seconds")
            except ValueError:
                errors.append("frequency must be a number")
        return len(errors) == 0, errors

