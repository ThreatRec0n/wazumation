"""Configuration validation engine."""

import subprocess
import os
import shutil
from pathlib import Path
from typing import List, Tuple, Optional
from wazumation.core.change_plan import ChangePlan


class ValidationError(Exception):
    """Raised when validation fails."""

    def __init__(self, message: str, errors: List[str]):
        super().__init__(message)
        self.errors = errors


class ConfigValidator:
    """Validates Wazuh configuration files."""

    def __init__(self, wazuh_manager_path: Path = Path("/var/ossec")):
        """Initialize validator."""
        self.wazuh_manager_path = wazuh_manager_path
        self.wazuh_control = wazuh_manager_path / "bin" / "wazuh-control"

    def validate_ossec_conf(self, config_path: Path) -> Tuple[bool, List[str]]:
        """Validate ossec.conf using multiple methods (xmllint + lxml + wazuh-control when supported)."""
        errors = []
        # Always do local XML validation first (fast + actionable).
        ok_xml, xml_errors = self._validate_xml(config_path)
        if not ok_xml:
            return False, [
                "Wazuh config validation failed. Fix ossec.conf before restart. Output: " + "; ".join(xml_errors)
            ]

        try:
            # 1) xmllint gate (best-effort, but preferred when available)
            xmllint = shutil.which("xmllint")
            if xmllint:
                rxml = subprocess.run(
                    [xmllint, "--noout", str(config_path)],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                if rxml.returncode != 0:
                    out = (rxml.stdout or "") + (("\n" + rxml.stderr) if rxml.stderr else "")
                    errors.append(
                        "Wazuh config validation failed. Fix ossec.conf before restart. Output: " + out.strip()
                    )
                    return False, errors

            # 2) wazuh-control validation (best-effort; varies by Wazuh/OSSEC builds).
            if self.wazuh_control.exists():
                candidates = [
                    [str(self.wazuh_control), "-t"],
                    [str(self.wazuh_control), "info", "-t"],
                ]
                if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
                    candidates = [["sudo", "-n", *c] for c in candidates]

                last_out = ""
                for cmd in candidates:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    out = (result.stdout or "") + (("\n" + result.stderr) if result.stderr else "")
                    last_out = out.strip()
                    if result.returncode == 0:
                        return True, []
                    # If this command form is unsupported, try the next candidate.
                    if "Usage:" in out and "wazuh-control" in out:
                        continue
                errors.append(
                    "Wazuh config validation failed. Fix ossec.conf before restart. Output: " + last_out
                )
                return False, errors

            return True, []
        except subprocess.TimeoutExpired:
            errors.append("Validation timeout")
            return False, errors
        except Exception as e:
            errors.append(f"Validation error: {str(e)}")
            return False, errors

    def _validate_xml(self, config_path: Path) -> Tuple[bool, List[str]]:
        """XML validation (syntax + minimal semantic checks)."""
        errors = []
        try:
            from lxml import etree
            tree = etree.parse(str(config_path), etree.XMLParser(remove_blank_text=True))
            root = tree.getroot()
            if root.tag != "ossec_config":
                errors.append(f"Root element must be <ossec_config>, found <{root.tag}>")
                return False, errors

            for elem in root.xpath("//enabled"):
                value = elem.text.strip().lower() if elem.text else ""
                if value not in ["yes", "no"]:
                    errors.append(f"Invalid <enabled> value: '{elem.text}' (must be 'yes' or 'no')")
                    return False, errors
            return True, []
        except etree.XMLSyntaxError as e:
            errors.append(f"XML parse error at line {e.lineno}: {e.msg}")
            return False, errors
        except Exception as e:
            errors.append(f"XML validation error: {str(e)}")
            return False, errors

    def validate_plan(self, plan: ChangePlan) -> Tuple[bool, List[str]]:
        """Validate a change plan before applying."""
        errors = []
        for file_change in plan.file_changes:
            if file_change.path.endswith("ossec.conf"):
                # For ossec.conf, we'd need to write to temp and validate
                # This is a simplified version
                if file_change.new_content:
                    # Basic check: ensure XML is well-formed
                    try:
                        from lxml import etree
                        etree.fromstring(file_change.new_content.encode())
                    except Exception as e:
                        errors.append(f"Invalid XML in {file_change.path}: {str(e)}")
            elif file_change.path.endswith("agent.conf"):
                # Similar validation for agent.conf
                if file_change.new_content:
                    try:
                        from lxml import etree
                        etree.fromstring(file_change.new_content.encode())
                    except Exception as e:
                        errors.append(f"Invalid XML in {file_change.path}: {str(e)}")

        return len(errors) == 0, errors


