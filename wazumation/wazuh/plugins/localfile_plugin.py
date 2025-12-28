"""Localfile configuration plugin."""

from typing import Dict, Any, List, Tuple
from wazumation.wazuh.plugins.base_plugin import BaseWazuhPlugin


class LocalfilePlugin(BaseWazuhPlugin):
    """Plugin for localfile (log file monitoring) configuration."""

    def __init__(self):
        """Initialize localfile plugin."""
        super().__init__("localfile", "localfile", ["manager", "agent"])

    def get_default_state(self) -> Dict[str, Any]:
        """Return default localfile configuration."""
        return {
            "children": {
                "log_format": {"text": "syslog"},
                "location": {"text": "/var/log/messages"},
            }
        }

    def get_schema(self) -> Dict[str, Any]:
        """Return schema for localfile section."""
        return {
            "type": "object",
            "properties": {
                "log_format": {
                    "type": "string",
                    "enum": ["syslog", "snort-full", "snort-fast", "squid", "apache", "iis", "mysql_query", "mysql_error", "postgresql", "ms_audit", "command"],
                },
                "location": {"type": "string"},
            },
        }

    def _normalize_state(self, section_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize localfile section."""
        normalized = {}
        if "children" in section_data:
            for key, value in section_data["children"].items():
                if isinstance(value, dict) and "text" in value:
                    normalized[key] = value["text"]
                else:
                    normalized[key] = value
        return normalized

    def _denormalize_state(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Convert normalized state back to XML."""
        children = {}
        for key, value in state.items():
            if isinstance(value, str):
                children[key] = {"text": value}
            else:
                children[key] = value
        return {"children": children}

    def validate(self, state: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate localfile configuration."""
        errors = []
        valid_formats = [
            "syslog",
            "snort-full",
            "snort-fast",
            "squid",
            "apache",
            "iis",
            "mysql_query",
            "mysql_error",
            "postgresql",
            "ms_audit",
            "command",
        ]
        if "log_format" in state and state["log_format"] not in valid_formats:
            errors.append(f"log_format must be one of: {', '.join(valid_formats)}")
        if "location" in state and not state["location"]:
            errors.append("location cannot be empty")
        return len(errors) == 0, errors

