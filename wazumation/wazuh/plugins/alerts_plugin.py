"""Alerts configuration plugin."""

from typing import Dict, Any, List, Tuple
from wazumation.wazuh.plugins.base_plugin import BaseWazuhPlugin


class AlertsPlugin(BaseWazuhPlugin):
    """Plugin for alerts configuration."""

    def __init__(self):
        """Initialize alerts plugin."""
        super().__init__("alerts", "alerts", ["manager"])

    def get_default_state(self) -> Dict[str, Any]:
        """Return default alerts configuration."""
        return {
            "children": {
                "log_alert_level": {"text": "3"},
                "email_alert_level": {"text": "12"},
            }
        }

    def get_schema(self) -> Dict[str, Any]:
        """Return schema for alerts section."""
        return {
            "type": "object",
            "properties": {
                "log_alert_level": {"type": "string"},
                "email_alert_level": {"type": "string"},
            },
        }

    def _normalize_state(self, section_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize alerts section."""
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
        """Validate alerts configuration."""
        errors = []
        if "log_alert_level" in state:
            try:
                level = int(state["log_alert_level"])
                if level < 0 or level > 16:
                    errors.append("log_alert_level must be between 0 and 16")
            except ValueError:
                errors.append("log_alert_level must be a number")
        if "email_alert_level" in state:
            try:
                level = int(state["email_alert_level"])
                if level < 0 or level > 16:
                    errors.append("email_alert_level must be between 0 and 16")
            except ValueError:
                errors.append("email_alert_level must be a number")
        return len(errors) == 0, errors

