"""Planner for applying feature toggles to ossec.conf safely and idempotently."""

from __future__ import annotations

import getpass
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import uuid

from wazumation.core.change_plan import ChangePlan, ChangeType, FileChange, ServiceChange
from wazumation.wazuh.xml_parser import WazuhXMLParser, WazuhXMLWriter


def _is_wazuh_manager(config_path: Path) -> Tuple[bool, str]:
    if os.name != "posix":
        return False, "This feature tool targets Linux Wazuh managers only."
    if not config_path.exists():
        return False, f"ossec.conf not found at {config_path}"
    wazuh_control = Path("/var/ossec/bin/wazuh-control")
    if not wazuh_control.exists():
        return False, "Wazuh manager not detected (missing /var/ossec/bin/wazuh-control)."
    return True, ""


def _ensure_localfile_instance(sections: Dict[str, Any], instance: Dict[str, str], *, marker: Optional[str] = None) -> None:
    """
    Ensure a <localfile> block exists with exact (log_format, location).
    This is idempotent: it does not duplicate if an equivalent instance exists.
    """
    tag = "localfile"
    existing = sections.get(tag)
    items = existing if isinstance(existing, list) else ([existing] if existing is not None else [])

    def _matches(it: Dict[str, Any]) -> bool:
        children = (it.get("children") or {}) if isinstance(it, dict) else {}
        lf = children.get("log_format", {}).get("text") if isinstance(children.get("log_format"), dict) else None
        loc = children.get("location", {}).get("text") if isinstance(children.get("location"), dict) else None
        return lf == instance.get("log_format") and loc == instance.get("location")

    for it in items:
        if isinstance(it, dict) and _matches(it):
            sections[tag] = items if isinstance(existing, list) else it
            return

    new_it = {
        "__comments__": [f"WAZUMATION:feature={marker}"] if marker else [],
        "children": {
            "log_format": {"text": instance["log_format"]},
            "location": {"text": instance["location"]},
        }
    }
    if isinstance(existing, list) or existing is None:
        items.append(new_it)
        sections[tag] = items
    else:
        # Existing single instance; convert to list
        sections[tag] = [existing, new_it]


def _remove_localfile_instance(
    sections: Dict[str, Any], instance: Dict[str, str], *, marker: Optional[str] = None
) -> None:
    """Remove matching <localfile> instances (log_format + location), optionally requiring a marker."""
    tag = "localfile"
    existing = sections.get(tag)
    items = existing if isinstance(existing, list) else ([existing] if existing is not None else [])

    def _matches(it: Dict[str, Any]) -> bool:
        children = (it.get("children") or {}) if isinstance(it, dict) else {}
        lf = children.get("log_format", {}).get("text") if isinstance(children.get("log_format"), dict) else None
        loc = children.get("location", {}).get("text") if isinstance(children.get("location"), dict) else None
        if lf != instance.get("log_format") or loc != instance.get("location"):
            return False
        if marker:
            comments = it.get("__comments__") if isinstance(it, dict) else None
            return isinstance(comments, list) and any(f"WAZUMATION:feature={marker}" in str(c) for c in comments)
        return True

    kept = [it for it in items if not (isinstance(it, dict) and _matches(it))]
    if not kept:
        sections.pop(tag, None)
    elif len(kept) == 1:
        sections[tag] = kept[0]
    else:
        sections[tag] = kept

def _apply_section_desired(sections: Dict[str, Any], section_tag: str, desired: Dict[str, Any]) -> None:
    """
    Apply desired child key/values to a single section (create if missing).
    Deleting a key requires desired[key] = None.
    """
    current = sections.get(section_tag)
    if isinstance(current, list):
        # Update first instance for section-level settings.
        current_dict = current[0] if current else {}
    else:
        current_dict = current or {}

    section = dict(current_dict) if isinstance(current_dict, dict) else {}
    children = dict(section.get("children") or {})
    attrs = dict(section.get("attributes") or {})

    for k, v in desired.items():
        if k.startswith("@"):
            ak = k[1:]
            if v is None:
                attrs.pop(ak, None)
            else:
                attrs[ak] = str(v)
            continue
        if v is None:
            children.pop(k, None)
        else:
            if isinstance(v, list):
                children[k] = [{"text": str(x)} for x in v]
            else:
                children[k] = {"text": str(v)}

    if attrs:
        section["attributes"] = attrs
    else:
        section.pop("attributes", None)
    if children:
        section["children"] = children
    else:
        section.pop("children", None)

    if isinstance(current, list):
        if current:
            current[0] = section
            sections[section_tag] = current
        else:
            sections[section_tag] = [section]
    else:
        sections[section_tag] = section


@dataclass
class FeaturePlanResult:
    plan: ChangePlan
    per_feature_plan_paths: Dict[str, str]


def build_feature_plan(
    *,
    config_path: Path,
    data_dir: Path,
    enable_features: List[Dict[str, Any]],
    disable_features: List[Dict[str, Any]],
    state_snapshot: Dict[str, Any],
    prompt_fn: Optional[Any],
    is_manager_fn: Optional[Any] = None,
    values_by_feature: Optional[Dict[str, Dict[str, Any]]] = None,
) -> FeaturePlanResult:
    ok, reason = (is_manager_fn(config_path) if is_manager_fn else _is_wazuh_manager(config_path))
    if not ok:
        raise RuntimeError(reason)

    parser = WazuhXMLParser(config_path)
    full = parser.parse()
    sections = full.get("sections", {})

    # Snapshot old content for a single-file plan.
    old_content = config_path.read_text(encoding="utf-8") if config_path.exists() else ""

    # Apply enable actions.
    for feat in enable_features:
        for action in feat["actions"]:
            section = action["section"]
            if "desired" in action:
                _apply_section_desired(sections, section, action["desired"])
            elif "ensure_instance" in action and section == "localfile":
                _ensure_localfile_instance(
                    sections,
                    action["ensure_instance"],
                    marker=action.get("marker") or feat.get("feature_id"),
                )
            elif "desired_from_prompts" in action:
                if not prompt_fn:
                    raise RuntimeError(f"Feature '{feat['feature_id']}' requires interactive input.")
                desired = {}
                for k, spec in action["desired_from_prompts"].items():
                    desired[k] = prompt_fn(spec["prompt"], spec.get("default"), spec.get("required", False))
                _apply_section_desired(sections, section, desired)
            elif "desired_from_values" in action:
                values = (values_by_feature or {}).get(feat["feature_id"], {})
                desired = {}
                for ossec_key, value_key in action["desired_from_values"].items():
                    desired[ossec_key] = values.get(value_key)
                _apply_section_desired(sections, section, desired)

    # Apply disable: restore previous values captured in state_snapshot.
    for feat in disable_features:
        snap = state_snapshot.get(feat["feature_id"], {})
        restore = snap.get("restore", {})
        for section_tag, desired in restore.items():
            if section_tag == "__remove_localfile__":
                for inst in desired:
                    if isinstance(inst, dict) and "instance" in inst:
                        _remove_localfile_instance(
                            sections,
                            inst["instance"],
                            marker=inst.get("marker"),
                        )
                    else:
                        _remove_localfile_instance(sections, inst, marker=feat.get("feature_id"))
                continue
            _apply_section_desired(sections, section_tag, desired)

    full["sections"] = sections
    writer = WazuhXMLWriter(config_path)
    new_content = writer.write(full)

    plan_id = str(uuid.uuid4())[:8]
    plan = ChangePlan(
        plan_id=plan_id,
        created_at=datetime.now(timezone.utc),
        description="Apply Wazumation feature selection",
        metadata={"mode": "features"},
    )

    if new_content != old_content:
        plan.add_file_change(
            FileChange(
                path=str(config_path),
                change_type=ChangeType.UPDATE,
                old_content=old_content,
                new_content=new_content,
                metadata={"plan_id": plan_id, "plugin": "features"},
            )
        )
        # Feature changes typically require restart.
        plan.add_service_change(
            ServiceChange(
                service_name="wazuh-manager",
                change_type=ChangeType.SERVICE_RESTART,
                reason="Feature configuration changes applied",
                metadata={"plan_id": plan_id},
            )
        )

    return FeaturePlanResult(plan=plan, per_feature_plan_paths={})


