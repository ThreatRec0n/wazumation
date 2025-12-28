"""Base plugin implementation with common functionality."""

from pathlib import Path
from typing import Dict, Any, List, Tuple
from datetime import datetime, timezone
import uuid
from wazumation.wazuh.plugin import WazuhPlugin
from wazumation.wazuh.xml_parser import WazuhXMLParser, WazuhXMLWriter
from wazumation.core.change_plan import ChangePlan, FileChange, ServiceChange, ChangeType


class BaseWazuhPlugin(WazuhPlugin):
    """Base implementation with common functionality."""

    def __init__(self, name: str, section_name: str, applies_to: List[str]):
        """Initialize base plugin."""
        super().__init__(name, section_name, applies_to)

    def read(self, config_path: Path) -> Dict[str, Any]:
        """Read current configuration state."""
        parser = WazuhXMLParser(config_path)
        section_data = parser.get_section(self.section_name)
        if section_data is None:
            return self.get_default_state()
        return self._normalize_state(section_data)

    def plan(
        self, config_path: Path, current_state: Dict[str, Any], desired_state: Dict[str, Any]
    ) -> ChangePlan:
        """Generate change plan."""
        plan_id = str(uuid.uuid4())[:8]
        plan = ChangePlan(
            plan_id=plan_id,
            created_at=datetime.now(timezone.utc),
            description=f"Update {self.name} configuration",
            metadata={"plugin": self.name, "section": self.section_name},
        )

        # Check if changes are needed
        if current_state == desired_state:
            return plan  # Empty plan

        # Generate new XML content
        parser = WazuhXMLParser(config_path)
        full_data = parser.parse()
        full_data["sections"][self.section_name] = self._denormalize_state(desired_state)

        writer = WazuhXMLWriter(config_path)
        new_content = writer.write(full_data)

        # Read current content for diff
        current_content = ""
        if config_path.exists():
            current_content = config_path.read_text(encoding="utf-8")

        # Add file change
        file_change = FileChange(
            path=str(config_path),
            change_type=ChangeType.UPDATE,
            old_content=current_content,
            new_content=new_content,
            metadata={"plan_id": plan_id, "plugin": self.name},
        )
        plan.add_file_change(file_change)

        # Add service restart if needed
        if self.requires_service_restart():
            service_change = ServiceChange(
                service_name="wazuh-manager",
                change_type=ChangeType.SERVICE_RESTART,
                reason=f"Configuration change in {self.name}",
                metadata={"plan_id": plan_id},
            )
            plan.add_service_change(service_change)

        return plan

    def validate(self, state: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate configuration state."""
        errors = []
        # Basic validation - plugins can override for specific checks
        return len(errors) == 0, errors

    def _normalize_state(self, section_data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize XML structure to plugin-specific state."""
        # Default: return as-is, plugins can override
        return section_data

    def _denormalize_state(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Convert plugin state back to XML structure."""
        # Default: return as-is, plugins can override
        return state

