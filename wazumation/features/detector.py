"""Live feature detection from real Wazuh configuration (no state-file assumptions)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

from wazumation.wazuh.xml_parser import WazuhXMLParser


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

    states: Dict[str, Dict[str, Any]] = {}

    # fim-enhanced: syscheck scan_on_start=yes and whodata=yes
    syscheck = sections.get("syscheck")
    syscheck_dict = syscheck if isinstance(syscheck, dict) else (syscheck[0] if isinstance(syscheck, list) and syscheck else None)
    scan = _get_child_text(syscheck_dict, "scan_on_start") if isinstance(syscheck_dict, dict) else None
    who = _get_child_text(syscheck_dict, "whodata") if isinstance(syscheck_dict, dict) else None
    enabled_count = sum([scan == "yes", who == "yes"])
    if enabled_count == 2:
        st: FeatureStatus = "enabled"
    elif enabled_count == 0:
        st = "disabled"
    else:
        st = "partial"
    states["fim-enhanced"] = {"status": st, "evidence": {"scan_on_start": scan, "whodata": who}}

    # auditd-monitoring: localfile instance audit + /var/log/audit/audit.log
    instances = _localfile_instances(sections)
    audit_present = any(i["log_format"] == "audit" and i["location"] == "/var/log/audit/audit.log" for i in instances)
    states["auditd-monitoring"] = {"status": "enabled" if audit_present else "disabled", "evidence": {"instances": instances}}

    # selftest-probe: localfile instance syslog + /var/ossec/logs/wazumation-selftest.log
    probe_present = any(
        i["log_format"] == "syslog" and i["location"] == "/var/ossec/logs/wazumation-selftest.log" for i in instances
    )
    states["selftest-probe"] = {"status": "enabled" if probe_present else "disabled", "evidence": {"instances": instances}}

    # vuln-detector: vulnerability-detection enabled=yes
    vd = sections.get("vulnerability-detection")
    vd_dict = vd if isinstance(vd, dict) else (vd[0] if isinstance(vd, list) and vd else None)
    vd_enabled = _get_child_text(vd_dict, "enabled") if isinstance(vd_dict, dict) else None
    states["vuln-detector"] = {"status": "enabled" if vd_enabled == "yes" else "disabled", "evidence": {"enabled": vd_enabled}}

    # sca-cis: sca enabled=yes
    sca = sections.get("sca")
    sca_dict = sca if isinstance(sca, dict) else (sca[0] if isinstance(sca, list) and sca else None)
    sca_enabled = _get_child_text(sca_dict, "enabled") if isinstance(sca_dict, dict) else None
    states["sca-cis"] = {"status": "enabled" if sca_enabled == "yes" else "disabled", "evidence": {"enabled": sca_enabled}}

    # localfile-nginx: localfile instance apache + /var/log/nginx/access.log
    nginx_present = any(i["log_format"] == "apache" and i["location"] == "/var/log/nginx/access.log" for i in instances)
    states["localfile-nginx"] = {"status": "enabled" if nginx_present else "disabled", "evidence": {"instances": instances}}

    # email-alerts: global email_notification=yes and smtp_server/email_to/email_from set
    g = sections.get("global")
    g_dict = g if isinstance(g, dict) else (g[0] if isinstance(g, list) and g else None)
    email_notification = _get_child_text(g_dict, "email_notification") if isinstance(g_dict, dict) else None
    smtp = _get_child_text(g_dict, "smtp_server") if isinstance(g_dict, dict) else None
    email_from = _get_child_text(g_dict, "email_from") if isinstance(g_dict, dict) else None
    email_to = _get_child_text(g_dict, "email_to") if isinstance(g_dict, dict) else None
    if email_notification == "yes" and smtp and email_from and email_to:
        states["email-alerts"] = {"status": "enabled", "evidence": {"smtp_server": smtp, "email_from": email_from, "email_to": email_to}}
    elif email_notification == "yes" and (smtp or email_from or email_to):
        states["email-alerts"] = {"status": "partial", "evidence": {"smtp_server": smtp, "email_from": email_from, "email_to": email_to}}
    else:
        states["email-alerts"] = {"status": "disabled", "evidence": {"smtp_server": smtp, "email_from": email_from, "email_to": email_to}}

    return states


