"""Models for feature selection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Feature:
    feature_id: str
    title: str
    description: str
    # List of changes this feature applies to ossec.conf (section_tag -> desired dict or special action dict)
    actions: List[Dict[str, Any]] = field(default_factory=list)
    requires_linux: bool = True
    requires_manager: bool = True
    requires_secrets: bool = False


