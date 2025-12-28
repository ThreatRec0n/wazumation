"""Change planning and execution tracking."""

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from pathlib import Path


class ChangeType(Enum):
    """Type of change operation."""

    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    SERVICE_RESTART = "service_restart"
    SERVICE_STOP = "service_stop"
    SERVICE_START = "service_start"


@dataclass
class FileChange:
    """Represents a file modification."""

    path: str
    change_type: ChangeType
    old_content: Optional[str] = None
    new_content: Optional[str] = None
    backup_path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate file change."""
        if self.change_type in (ChangeType.CREATE, ChangeType.UPDATE) and not self.new_content:
            raise ValueError(f"{self.change_type.value} requires new_content")
        if self.change_type == ChangeType.DELETE and not self.old_content:
            raise ValueError("DELETE requires old_content")


@dataclass
class ServiceChange:
    """Represents a service operation."""

    service_name: str
    change_type: ChangeType
    reason: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate service change."""
        if self.change_type not in (
            ChangeType.SERVICE_RESTART,
            ChangeType.SERVICE_STOP,
            ChangeType.SERVICE_START,
        ):
            raise ValueError(f"Invalid service change type: {self.change_type}")


@dataclass
class ChangePlan:
    """Complete plan of changes to apply."""

    plan_id: str
    created_at: datetime
    description: str
    file_changes: List[FileChange] = field(default_factory=list)
    service_changes: List[ServiceChange] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    requires_sudo: bool = False

    def add_file_change(self, change: FileChange) -> None:
        """Add a file change to the plan."""
        self.file_changes.append(change)

    def add_service_change(self, change: ServiceChange) -> None:
        """Add a service change to the plan."""
        self.service_changes.append(change)
        if change.change_type == ChangeType.SERVICE_RESTART:
            self.requires_sudo = True

    def is_empty(self) -> bool:
        """Check if plan has any changes."""
        return len(self.file_changes) == 0 and len(self.service_changes) == 0

    def get_summary(self) -> str:
        """Get human-readable summary of the plan."""
        parts = [f"Plan: {self.description}"]
        if self.file_changes:
            parts.append(f"  Files: {len(self.file_changes)} change(s)")
        if self.service_changes:
            parts.append(f"  Services: {len(self.service_changes)} operation(s)")
        if self.requires_sudo:
            parts.append("  [WARNING] Requires sudo privileges")
        return "\n".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        """Convert plan to dictionary for JSON serialization."""
        return {
            "plan_id": self.plan_id,
            "created_at": self.created_at.isoformat(),
            "description": self.description,
            "file_changes": [
                {
                    "path": fc.path,
                    "change_type": fc.change_type.value,
                    "old_content": fc.old_content,
                    "new_content": fc.new_content,
                    "backup_path": fc.backup_path,
                    "metadata": fc.metadata,
                }
                for fc in self.file_changes
            ],
            "service_changes": [
                {
                    "service_name": sc.service_name,
                    "change_type": sc.change_type.value,
                    "reason": sc.reason,
                    "metadata": sc.metadata,
                }
                for sc in self.service_changes
            ],
            "metadata": self.metadata,
            "requires_sudo": self.requires_sudo,
        }

    def to_json(self, file_path: Path) -> None:
        """Serialize plan to JSON file."""
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChangePlan":
        """Create plan from dictionary."""
        plan = cls(
            plan_id=data["plan_id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            description=data["description"],
            metadata=data.get("metadata", {}),
            requires_sudo=data.get("requires_sudo", False),
        )
        for fc_data in data.get("file_changes", []):
            plan.add_file_change(
                FileChange(
                    path=fc_data["path"],
                    change_type=ChangeType(fc_data["change_type"]),
                    old_content=fc_data.get("old_content"),
                    new_content=fc_data.get("new_content"),
                    backup_path=fc_data.get("backup_path"),
                    metadata=fc_data.get("metadata", {}),
                )
            )
        for sc_data in data.get("service_changes", []):
            plan.add_service_change(
                ServiceChange(
                    service_name=sc_data["service_name"],
                    change_type=ChangeType(sc_data["change_type"]),
                    reason=sc_data["reason"],
                    metadata=sc_data.get("metadata", {}),
                )
            )
        return plan

    @classmethod
    def from_json(cls, file_path: Path) -> "ChangePlan":
        """Load plan from JSON file."""
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)

