"""Wazuh configuration plugins (doc-driven full coverage, canonical identifiers)."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from wazumation.wazuh.plugins.doc_driven import DocDrivenSectionPlugin


def _load_sections() -> List[Dict[str, Any]]:
    """
    Load sections from JSON with multiple fallbacks.

    Key constraint: installs must *not* assume CWD contains a top-level `data/`.
    We therefore prefer packaged resources first, then known install locations,
    and only then source-tree relative paths.
    """
    # 1) Prefer packaged data (works for wheels/venvs and editable installs).
    try:
        from importlib import resources as importlib_resources

        traversable = importlib_resources.files("wazumation").joinpath("data/wazuh_sections.json")
        if traversable.is_file():
            return json.loads(traversable.read_text(encoding="utf-8"))
    except Exception:
        # Fall through to path-based search.
        pass

    # 2) Search multiple filesystem locations (repo + packaged + known install dirs).
    # NOTE: This file lives at `wazumation/wazuh/plugins/__init__.py`, so:
    # - parents[2] == `wazumation/`
    # - parents[1] == `wazumation/wazuh/`
    pkg_root = Path(__file__).resolve().parents[2]
    search_paths = [
        pkg_root / "data" / "wazuh_sections.json",  # installed package layout
        Path("/opt/Wazumation/wazumation/data/wazuh_sections.json"),
        Path("/opt/Wazumation/data/wazuh_sections.json"),
        Path("wazumation") / "data" / "wazuh_sections.json",  # source tree layout
        Path("data") / "wazuh_sections.json",  # repo checkout convenience
    ]

    for p in search_paths:
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))

    # Optional: try to generate if the dev tools module exists (source checkout only).
    try:
        try:
            from tools.sync_wazuh_sections import sync as _sync_sections  # type: ignore
        except ImportError:
            # tools module not available - skip sync
            _sync_sections = None

        if _sync_sections is not None:
            out_path = Path("data") / "wazuh_sections.json"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            _sync_sections(out_path)
            if out_path.exists():
                return json.loads(out_path.read_text(encoding="utf-8"))
    except Exception:
        pass

    # Fallback: minimal defaults so the tool remains usable even if the full catalog is missing.
    logging.warning("wazuh_sections.json not found - using minimal default sections")
    return [
        {"identifier": "global", "section_tag": "global"},
        {"identifier": "syscheck", "section_tag": "syscheck"},
        {"identifier": "rootcheck", "section_tag": "rootcheck"},
        {"identifier": "vulnerability-detection", "section_tag": "vulnerability-detection"},
        {"identifier": "sca", "section_tag": "sca"},
        {"identifier": "localfile", "section_tag": "localfile"},
    ]


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


