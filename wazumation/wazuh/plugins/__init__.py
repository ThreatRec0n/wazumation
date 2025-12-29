"""Wazuh configuration plugins (doc-driven full coverage, canonical identifiers)."""

import json
from pathlib import Path
from typing import Any, Dict, List

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


def _load_sections() -> List[Dict[str, Any]]:
    # Local-only, repo-first: try current working directory `data/` first.
    path = Path("data") / "wazuh_sections.json"
    if not path.exists():
        # Next, try packaged location `wazumation/data/` (when running from a source tree).
        pkg_path = Path("wazumation") / "data" / "wazuh_sections.json"
        if pkg_path.exists():
            return json.loads(pkg_path.read_text(encoding="utf-8"))

        # Best-effort auto-generation if running from repo and the tools script is importable.
        try:
            from tools.sync_wazuh_sections import sync as _sync_sections  # type: ignore

            path.parent.mkdir(parents=True, exist_ok=True)
            _sync_sections(path)
        except Exception:
            raise FileNotFoundError(
                "Missing data/wazuh_sections.json. Run: python3 tools/sync_wazuh_sections.py"
            )
    return json.loads(path.read_text(encoding="utf-8"))


def register_all_plugins(registry) -> None:
    """Register all plugins with the registry."""
    sections = _load_sections()
    for s in sections:
        identifier = s["identifier"]
        section_tag = s["section_tag"]
        selector = {}
        if section_tag == "wodle" and s.get("wodle_name"):
            selector = {"name": s["wodle_name"]}
        registry.register(
            DocDrivenSectionPlugin(
                identifier=identifier,
                section_tag=section_tag,
                supported_installations=s.get("supported_installations", ["manager", "agent"]),
                selector_attributes=selector or None,
            )
        )


