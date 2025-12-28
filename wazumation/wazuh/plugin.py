"""Plugin system for Wazuh configuration sections."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from wazumation.core.change_plan import ChangePlan, FileChange, ServiceChange, ChangeType
from datetime import datetime
import uuid


class WazuhPlugin(ABC):
    """Base class for Wazuh configuration plugins."""

    def __init__(self, name: str, section_name: str, applies_to: List[str]):
        """
        Initialize plugin.

        Args:
            name: Plugin name (e.g., "syscheck")
            section_name: XML section name (e.g., "syscheck")
            applies_to: List of "manager" or "agent" indicating where this applies
        """
        self.name = name
        self.section_name = section_name
        self.applies_to = applies_to  # ["manager", "agent", or both]

    @abstractmethod
    def read(self, config_path: Path) -> Dict[str, Any]:
        """Read current configuration state from file."""
        pass

    @abstractmethod
    def plan(
        self, config_path: Path, current_state: Dict[str, Any], desired_state: Dict[str, Any]
    ) -> ChangePlan:
        """Generate a change plan for transitioning from current to desired state."""
        pass

    @abstractmethod
    def validate(self, state: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate a configuration state. Returns (is_valid, errors)."""
        pass

    def get_schema(self) -> Dict[str, Any]:
        """Return schema definition for this plugin (optional)."""
        return {}

    def requires_service_restart(self) -> bool:
        """Whether changes to this plugin require service restart."""
        return True  # Default: most changes require restart

    def get_default_state(self) -> Dict[str, Any]:
        """Return default configuration state."""
        return {}


class PluginRegistry:
    """Registry for all Wazuh configuration plugins."""

    def __init__(self):
        """Initialize plugin registry."""
        self._plugins: Dict[str, WazuhPlugin] = {}

    def register(self, plugin: WazuhPlugin) -> None:
        """Register a plugin."""
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> Optional[WazuhPlugin]:
        """Get a plugin by name."""
        return self._plugins.get(name)

    def list_all(self) -> List[WazuhPlugin]:
        """List all registered plugins."""
        return list(self._plugins.values())

    def list_for_target(self, target: str) -> List[WazuhPlugin]:
        """List plugins that apply to a target (manager/agent)."""
        return [p for p in self._plugins.values() if target in p.applies_to]

    def get_by_section(self, section_name: str) -> Optional[WazuhPlugin]:
        """Get plugin by XML section name."""
        for plugin in self._plugins.values():
            if plugin.section_name == section_name:
                return plugin
        return None

