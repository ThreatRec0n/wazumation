"""Models for feature selection (feature specs + config schemas)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Literal, Optional, Tuple


FieldType = Literal["string", "int", "bool", "path", "email", "list[string]", "enum"]


@dataclass(frozen=True)
class FieldSpec:
    name: str
    field_type: FieldType
    default: Optional[Any] = None
    placeholder: Optional[str] = None
    required: bool = False
    help_text: str = ""
    choices: Optional[List[str]] = None  # for enum
    regex: Optional[str] = None
    custom_validator: Optional[Callable[[Any], Tuple[bool, str]]] = None
    # Where/how this value is stored in ossec.conf (for prefill)
    ossec_section: Optional[str] = None
    ossec_key: Optional[str] = None

    def coerce(self, raw: Any) -> Any:
        if raw is None:
            return None
        if self.field_type in ("string", "path", "email"):
            return str(raw)
        if self.field_type == "int":
            if isinstance(raw, int):
                return raw
            return int(str(raw).strip())
        if self.field_type == "bool":
            if isinstance(raw, bool):
                return raw
            s = str(raw).strip().lower()
            if s in ("1", "true", "yes", "y", "on", "enabled"):
                return True
            if s in ("0", "false", "no", "n", "off", "disabled"):
                return False
            raise ValueError(f"Invalid boolean for {self.name}: {raw!r}")
        if self.field_type == "list[string]":
            if isinstance(raw, list):
                return [str(x).strip() for x in raw if str(x).strip()]
            return [x.strip() for x in str(raw).split(",") if x.strip()]
        if self.field_type == "enum":
            return str(raw).strip()
        return raw

    def validate(self, value: Any) -> Tuple[bool, str]:
        if value is None or (isinstance(value, str) and not value.strip()) or (isinstance(value, list) and not value):
            if self.required:
                return False, f"Missing required value: {self.name}"
            return True, ""

        if self.field_type == "enum" and self.choices:
            if str(value) not in self.choices:
                return False, f"Invalid value for {self.name}: must be one of {self.choices}"

        if self.field_type == "email":
            if "@" not in str(value):
                return False, f"Invalid email for {self.name}"

        if self.regex:
            if not re.fullmatch(self.regex, str(value)):
                return False, f"Invalid value for {self.name} (regex mismatch)"

        if self.custom_validator:
            ok, msg = self.custom_validator(value)
            if not ok:
                return False, msg or f"Invalid value for {self.name}"

        return True, ""


@dataclass(frozen=True)
class FeatureSpec:
    feature_id: str
    title: str
    description: str
    actions: List[Dict[str, Any]] = field(default_factory=list)
    config_schema: List[FieldSpec] = field(default_factory=list)
    requires_linux: bool = True
    requires_manager: bool = True
    requires_secrets: bool = False

    def schema_by_name(self) -> Dict[str, FieldSpec]:
        return {f.name: f for f in self.config_schema}


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


