"""Logging configuration plugin."""

from typing import Dict, Any, List, Tuple
from wazumation.wazuh.plugins.base_plugin import BaseWazuhPlugin


class LoggingPlugin(BaseWazuhPlugin):
    """Plugin for logging configuration."""

    def __init__(self):
        """Initialize logging plugin."""
        super().__init__("logging", "logging", ["manager", "agent"])

    def get_default_state(self) -> Dict[str, Any]:
        """Return default logging configuration."""
        return {
            "children": {
                "log_format": {"text": "plain"},
                "log_level": {"text": "2"},
            }
        }

    def get_schema(self) -> Dict[str, Any]:
        """Return schema for logging section."""
        return {
            "type": "object",
            "properties": {
                "log_format": {"type": "string", "enum": ["plain", "json"]},
                "log_level": {"type": "string", "enum": ["0", "1", "2", "3"]},
            },
        }

    def _normalize_state(self, section_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize logging section."""
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
        """Validate logging configuration."""
        errors = []
        if "log_format" in state and state["log_format"] not in ["plain", "json"]:
            errors.append("log_format must be 'plain' or 'json'")
        if "log_level" in state and state["log_level"] not in ["0", "1", "2", "3"]:
            errors.append("log_level must be 0, 1, 2, or 3")
        return len(errors) == 0, errors

