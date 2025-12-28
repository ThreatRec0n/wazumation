"""Configuration validation engine."""

import subprocess
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
        """Validate ossec.conf using Wazuh's built-in validator."""
        errors = []
        if not self.wazuh_control.exists():
            # Fallback: basic XML validation
            return self._validate_xml(config_path)

        try:
            # Use wazuh-control to validate
            result = subprocess.run(
                [str(self.wazuh_control), "testconfig"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                errors.append(f"wazuh-control testconfig failed: {result.stderr}")
                return False, errors
            return True, []
        except subprocess.TimeoutExpired:
            errors.append("Validation timeout")
            return False, errors
        except Exception as e:
            errors.append(f"Validation error: {str(e)}")
            return False, errors

    def _validate_xml(self, config_path: Path) -> Tuple[bool, List[str]]:
        """Basic XML validation."""
        errors = []
        try:
            from lxml import etree
            parser = etree.XMLParser(remove_blank_text=True)
            etree.parse(str(config_path), parser)
            return True, []
        except etree.XMLSyntaxError as e:
            errors.append(f"XML syntax error: {str(e)}")
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


