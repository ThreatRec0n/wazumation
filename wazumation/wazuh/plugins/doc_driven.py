"""Doc-driven generic plugin implementation for Wazuh ossec.conf sections."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

from wazumation.core.change_plan import ChangePlan, ChangeType, FileChange, ServiceChange
from wazumation.wazuh.plugin import WazuhPlugin
from wazumation.wazuh.xml_parser import WazuhXMLParser, WazuhXMLWriter


def _repo_data_path(filename: str) -> Optional[Path]:
    """
    Best-effort locate repo-root `data/` directory during local execution.
    This avoids hardcoding local paths and keeps runtime local-only.
    """
    # First: current working directory (common for CLI execution in repo root).
    cand = Path("data") / filename
    if cand.exists():
        return cand

    # Next: walk upwards from this file looking for a repo root containing data/.
    here = Path(__file__).resolve()
    for p in here.parents:
        cand = p / "data" / filename
        if cand.exists():
            return cand
    return None


def load_section_schema(identifier: str) -> Dict[str, Any]:
    path = _repo_data_path("wazuh_section_schemas.json")
    if not path:
        raise FileNotFoundError(
            "Missing wazuh_section_schemas.json. Run tools/sync_wazuh_sections.py and "
            "tools/scrape_wazuh_section_schema.py, or ensure data/ is present."
        )
    all_schemas = json.loads(path.read_text(encoding="utf-8"))
    return all_schemas.get(identifier, {"type": "object", "properties": {}, "additionalProperties": True})


def load_section_metadata(identifier: str) -> Dict[str, Any]:
    path = _repo_data_path("wazuh_section_metadata.json")
    if not path:
        return {}
    meta = json.loads(path.read_text(encoding="utf-8"))
    return meta.get(identifier, {})


def _validate_against_schema(schema: Dict[str, Any], state: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Minimal JSON-schema-like validator tailored to our scraped schema shape:
      - type: object
      - properties: {key: {type: "string", enum?: [...]}}
      - additionalProperties: bool (default False in our generated schemas)
    """
    errors: List[str] = []
    if not isinstance(state, dict):
        return False, ["Desired state must be a JSON object"]

    props = schema.get("properties", {}) or {}
    additional = schema.get("additionalProperties", False)

    for k, v in state.items():
        if k not in props:
            # allow explicit null to mean "delete" even if additionalProperties is False
            if v is None:
                continue
            if not additional:
                errors.append(f"Unknown option: {k}")
                continue
            # If additional properties allowed, accept as string-ish
            continue
        spec = props[k] or {}
        expected_type = spec.get("type", "string")
        if v is None:
            # explicit delete
            continue
        if expected_type == "string":
            if not isinstance(v, str):
                errors.append(f"{k} must be a string")
                continue
            enum = spec.get("enum")
            if enum and v not in enum:
                errors.append(f"{k} must be one of: {', '.join(enum)}")
        else:
            # We only emit string schemas today. Fail rather than guess.
            errors.append(f"{k} uses unsupported schema type {expected_type}")

    return len(errors) == 0, errors


def _normalize_section_dict(section_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize an XML section dict into a stable, flat key/value map:
      - child elements with text become key -> text
      - repeated child elements become key -> [text|dict...]
      - attributes are exposed as @attrname (rare for sections, but supported)
    """
    out: Dict[str, Any] = {}
    attrs = section_dict.get("attributes") or {}
    for k in sorted(attrs.keys()):
        out[f"@{k}"] = str(attrs[k])

    children = section_dict.get("children") or {}
    for k in sorted(children.keys()):
        v = children[k]
        if isinstance(v, list):
            items = []
            for item in v:
                if isinstance(item, dict) and "text" in item and len(item.keys()) <= 2:
                    items.append(item.get("text"))
                else:
                    items.append(item)
            out[k] = items
        elif isinstance(v, dict) and "text" in v and len(v.keys()) <= 2:
            out[k] = v.get("text")
        else:
            out[k] = v
    return out


def _apply_desired_to_section(section_name: str, desired: Dict[str, Any], current_section_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply desired_state onto the section dict, only touching keys present in desired.
    Deletes occur only when desired explicitly sets a key to null.
    """
    section = dict(current_section_dict) if current_section_dict else {}
    children = dict(section.get("children") or {})
    attrs = dict(section.get("attributes") or {})

    for k, v in desired.items():
        if k.startswith("@"):
            attr = k[1:]
            if v is None:
                attrs.pop(attr, None)
            else:
                attrs[attr] = str(v)
            continue
        if v is None:
            children.pop(k, None)
        else:
            # Represent scalar desired values as text nodes.
            if isinstance(v, str):
                children[k] = {"text": v}
            else:
                children[k] = v

    if attrs:
        section["attributes"] = attrs
    else:
        section.pop("attributes", None)
    if children:
        section["children"] = children
    else:
        section.pop("children", None)
    return section


class DocDrivenSectionPlugin(WazuhPlugin):
    """
    Generic plugin backed by scraped Wazuh docs schema.

    Note: section_name can contain hyphens (valid XML tag). Plugin name matches section_name.
    """

    def __init__(
        self,
        identifier: str,
        section_tag: str,
        supported_installations: List[str],
        selector_attributes: Optional[Dict[str, str]] = None,
    ):
        super().__init__(name=identifier, section_name=section_tag, applies_to=supported_installations)
        self.identifier = identifier
        self.section_tag = section_tag
        self.selector_attributes = selector_attributes or {}
        self._schema = load_section_schema(identifier)
        self._meta = load_section_metadata(identifier)

    def get_schema(self) -> Dict[str, Any]:
        return self._schema

    def validate(self, state: Dict[str, Any]) -> Tuple[bool, List[str]]:
        return _validate_against_schema(self._schema, state)

    def read(self, config_path: Path) -> Dict[str, Any]:
        parser = WazuhXMLParser(config_path)
        data = parser.parse()
        sec = data["sections"].get(self.section_name)
        if sec is None:
            return {}
        items = sec if isinstance(sec, list) else [sec]
        if self.selector_attributes:
            filtered = []
            for it in items:
                attrs = (it.get("attributes") or {}) if isinstance(it, dict) else {}
                ok = True
                for k, v in self.selector_attributes.items():
                    if str(attrs.get(k)) != v:
                        ok = False
                        break
                if ok:
                    filtered.append(it)
            items = filtered
        if len(items) == 0:
            return {}
        if len(items) > 1:
            return {"instances": [_normalize_section_dict(x) for x in items]}
        return _normalize_section_dict(items[0])

    def requires_service_restart(self) -> bool:
        # We only restart when docs mention restart/reload for this section.
        # Otherwise we conservatively do not restart automatically.
        return bool(self._meta.get("restart_guidance"))

    def plan(
        self,
        config_path: Path,
        current_state: Dict[str, Any],
        desired_state: Dict[str, Any],
    ) -> ChangePlan:
        plan_id = str(uuid.uuid4())[:8]
        plan = ChangePlan(
            plan_id=plan_id,
            created_at=datetime.now(timezone.utc),
            description=f"Update {self.name} configuration",
            metadata={"plugin": self.name, "section": self.section_name, "docs": self._meta.get("source_url")},
        )

        parser = WazuhXMLParser(config_path)
        full = parser.parse()
        sections = full.get("sections", {})
        current_sec = sections.get(self.section_name)
        items = current_sec if isinstance(current_sec, list) else ([current_sec] if current_sec is not None else [])

        target_idx = None
        if self.selector_attributes and items:
            for i, it in enumerate(items):
                attrs = (it.get("attributes") or {}) if isinstance(it, dict) else {}
                ok = True
                for k, v in self.selector_attributes.items():
                    if str(attrs.get(k)) != v:
                        ok = False
                        break
                if ok:
                    target_idx = i
                    break

        if target_idx is None:
            # Create new instance if selector is used and no match exists; otherwise update first or create.
            current_sec_dict = {}
            if self.selector_attributes:
                current_sec_dict = {"attributes": dict(self.selector_attributes)}
            updated = _apply_desired_to_section(self.section_name, desired_state, current_sec_dict)
            if isinstance(current_sec, list):
                items.append(updated)
                sections[self.section_name] = items
            elif current_sec is None and self.selector_attributes:
                sections[self.section_name] = [updated]
            else:
                sections[self.section_name] = updated
        else:
            current_sec_dict = items[target_idx] if isinstance(items[target_idx], dict) else {}
            updated = _apply_desired_to_section(self.section_name, desired_state, current_sec_dict)
            items[target_idx] = updated
            sections[self.section_name] = items if isinstance(current_sec, list) else items[0]

        full["sections"] = sections

        writer = WazuhXMLWriter(config_path)
        new_content = writer.write(full)

        old_content = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
        if old_content == new_content:
            return plan  # empty plan

        plan.add_file_change(
            FileChange(
                path=str(config_path),
                change_type=ChangeType.UPDATE,
                old_content=old_content,
                new_content=new_content,
                metadata={"plan_id": plan_id, "plugin": self.name},
            )
        )

        if self.requires_service_restart():
            plan.add_service_change(
                ServiceChange(
                    service_name="wazuh-manager",
                    change_type=ChangeType.SERVICE_RESTART,
                    reason=f"Docs mention restart/reload for {self.section_name}",
                    metadata={"plan_id": plan_id, "guidance": self._meta.get("restart_guidance")},
                )
            )

        return plan


