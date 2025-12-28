"""Global configuration plugin."""

from typing import Dict, Any, List, Tuple
from wazumation.wazuh.plugins.base_plugin import BaseWazuhPlugin


class GlobalPlugin(BaseWazuhPlugin):
    """Plugin for global Wazuh configuration."""

    def __init__(self):
        """Initialize global plugin."""
        super().__init__("global", "global", ["manager", "agent"])

    def get_default_state(self) -> Dict[str, Any]:
        """Return default global configuration."""
        return {
            "attributes": {},
            "children": {
                "email_notification": {"text": "no"},
                "smtp_server": {"text": "smtp.example.wazuh.com"},
                "email_from": {"text": "wazuh@example.wazuh.com"},
                "email_to": {"text": "recipient@example.wazuh.com"},
            },
        }

    def get_schema(self) -> Dict[str, Any]:
        """Return schema for global section."""
        return {
            "type": "object",
            "properties": {
                "email_notification": {"type": "string", "enum": ["yes", "no"]},
                "smtp_server": {"type": "string"},
                "email_from": {"type": "string"},
                "email_to": {"type": "string"},
            },
        }

    def _normalize_state(self, section_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize global section to simple dict."""
        normalized = {}
        if "children" in section_data:
            for key, value in section_data["children"].items():
                if isinstance(value, dict) and "text" in value:
                    normalized[key] = value["text"]
                else:
                    normalized[key] = value
        return normalized

    def _denormalize_state(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Convert normalized state back to XML structure."""
        children = {}
        for key, value in state.items():
            if isinstance(value, str):
                children[key] = {"text": value}
            else:
                children[key] = value
        return {"children": children}

    def validate(self, state: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate global configuration."""
        errors = []
        if "email_notification" in state:
            if state["email_notification"] not in ["yes", "no"]:
                errors.append("email_notification must be 'yes' or 'no'")
        return len(errors) == 0, errors

