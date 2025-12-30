"""Live feature detection from real Wazuh configuration (no state-file assumptions)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from wazumation.wazuh.xml_parser import WazuhXMLParser
from wazumation.features.registry import get_feature_registry


FeatureStatus = Literal["enabled", "disabled", "partial"]


def _get_section(sections: Dict[str, Any], tag: str) -> Optional[Any]:
    return sections.get(tag)


def _get_child_text(section_dict: Dict[str, Any], child_tag: str) -> Optional[str]:
    children = section_dict.get("children") or {}
    v = children.get(child_tag)
    if isinstance(v, dict) and "text" in v:
        return v.get("text")
    if isinstance(v, str):
        return v
    return None


def _localfile_instances(sections: Dict[str, Any]) -> List[Dict[str, Optional[str]]]:
    sec = sections.get("localfile")
    items = sec if isinstance(sec, list) else ([sec] if isinstance(sec, dict) else [])
    out = []
    for it in items:
        if not isinstance(it, dict):
            continue
        out.append(
            {
                "log_format": _get_child_text(it, "log_format"),
                "location": _get_child_text(it, "location"),
            }
        )
    return out


def detect_feature_states(config_path: Path) -> Dict[str, Dict[str, Any]]:
    """
    Return a dict: feature_id -> {status, evidence}.
    This function reads and parses the live ossec.conf file.
    """
    parser = WazuhXMLParser(config_path)
    data = parser.parse()
    sections = data.get("sections", {})

    reg = get_feature_registry()
    instances = _localfile_instances(sections)

    states: Dict[str, Dict[str, Any]] = {}

    def _section_dict(tag: str) -> Optional[Dict[str, Any]]:
        sec = sections.get(tag)
        if isinstance(sec, dict):
            return sec
        if isinstance(sec, list) and sec and isinstance(sec[0], dict):
            return sec[0]
        return None

    for fid, feat in reg.items():
        matches = 0
        total = 0
        evidence: Dict[str, Any] = {}
        values: Dict[str, Any] = {}

        # Extract schema values for prefill (best-effort).
        for fs in feat.config_schema:
            if fs.ossec_section and fs.ossec_key:
                sd = _section_dict(fs.ossec_section)
                v = _get_child_text(sd, fs.ossec_key) if isinstance(sd, dict) else None
                if v is not None:
                    values[fs.name] = v

        # Evaluate actions for enabled/partial/disabled.
        for action in feat.actions:
            section = action.get("section")
            if "desired" in action:
                desired = action.get("desired") or {}
                total += len(desired)
                sd = _section_dict(section)
                for k, expected in desired.items():
                    got = _get_child_text(sd, k) if isinstance(sd, dict) else None
                    evidence.setdefault(section, {})[k] = got
                    if got == str(expected):
                        matches += 1
            elif "ensure_instance" in action and section == "localfile":
                total += 1
                inst = action["ensure_instance"]
                present = any(i.get("log_format") == inst.get("log_format") and i.get("location") == inst.get("location") for i in instances)
                evidence["localfile_instances"] = instances
                if present:
                    matches += 1
            elif "desired_from_values" in action:
                # Detection: treat as enabled if all targeted keys exist (non-empty).
                keys = list((action.get("desired_from_values") or {}).keys())
                total += len(keys)
                sd = _section_dict(section)
                for ossec_key in keys:
                    got = _get_child_text(sd, ossec_key) if isinstance(sd, dict) else None
                    evidence.setdefault(section, {})[ossec_key] = got
                    if got is not None and str(got).strip() != "":
                        matches += 1

        if total == 0:
            status: FeatureStatus = "disabled"
        elif matches == 0:
            status = "disabled"
        elif matches == total:
            status = "enabled"
        else:
            status = "partial"

        states[fid] = {"status": status, "evidence": evidence, "values": values}

    # Special: selftest-probe status is derived from a specific localfile instance.
    probe_present = any(
        i.get("log_format") == "syslog" and i.get("location") == "/var/ossec/logs/wazumation-selftest.log"
        for i in instances
    )
    states["selftest-probe"] = {
        "status": "enabled" if probe_present else "disabled",
        "evidence": {"localfile_instances": instances},
        "values": {},
    }

    return states


