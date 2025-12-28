"""
Generate one Python plugin module per Wazuh ossec.conf section.

Why generation:
  - The official Wazuh section names include hyphens (valid XML) which are not valid
    Python module names. We therefore map:
      section-name  ->  section_name.py
    while keeping the plugin's `section_name` exactly as the XML tag from docs.

Outputs:
  wazumation/wazuh/plugins/generated_sections/<module>.py

These modules are optional wrappers around the doc-driven engine and exist to satisfy
"one plugin per section" structure while remaining import-safe in Python.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, Any, List


SECTIONS_JSON = Path("data") / "wazuh_sections.json"
OUT_DIR = Path("wazumation") / "wazuh" / "plugins"


def _module_name(identifier: str) -> str:
    if identifier.startswith('wodle name="') and identifier.endswith('"'):
        name = identifier[len('wodle name="'):-1]
        return "wodle_" + name.replace("-", "_").replace(".", "_")
    return identifier.replace("-", "_").replace(".", "_")


def _class_name(identifier: str) -> str:
    if identifier.startswith('wodle name="') and identifier.endswith('"'):
        name = identifier[len('wodle name="'):-1]
        parts = re.split(r"[-_.]+", "wodle_" + name)
    else:
        parts = re.split(r"[-_.]+", identifier)
    return "".join(p[:1].upper() + p[1:] for p in parts if p) + "Plugin"


def main() -> int:
    sections: List[Dict[str, Any]] = json.loads(SECTIONS_JSON.read_text(encoding="utf-8"))
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for s in sections:
        identifier = s["identifier"]
        applies = s.get("supported_installations", ["manager", "agent"])
        section_tag = s["section_tag"]
        selector = {}
        if section_tag == "wodle" and s.get("wodle_name"):
            selector = {"name": s["wodle_name"]}
        mod = _module_name(identifier)
        cls = _class_name(identifier)

        code = f'''"""Auto-generated plugin wrapper for `{identifier}`."""\n\n'''
        code += "from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin\n\n\n"
        code += f"class {cls}(DocDrivenSectionPlugin):\n"
        code += "    \"\"\"Doc-driven plugin for this Wazuh section.\"\"\"\n\n"
        code += "    def __init__(self):\n"
        code += (
            f"        super().__init__(identifier={identifier!r}, section_tag={section_tag!r}, "
            f"supported_installations={applies!r}, selector_attributes={selector!r} or None)\n"
        )

        (OUT_DIR / f"{mod}.py").write_text(code, encoding="utf-8")

    print(f"[OK] Generated {len(sections)} plugin wrapper modules in {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


