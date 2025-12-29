"""Tests for missing data/wazuh_sections.json handling (actionable error)."""

import os
from pathlib import Path

import pytest


def test_missing_sections_file_actionable_error(monkeypatch, tmp_path):
    # Simulate running from a directory without data/ or wazumation/data/
    monkeypatch.chdir(tmp_path)

    # Ensure tool auto-generation path is attempted but fails cleanly (no silent fail).
    import tools.sync_wazuh_sections as sync_mod

    def _fail_sync(_path: Path):
        raise RuntimeError("no internet")

    monkeypatch.setattr(sync_mod, "sync", _fail_sync)

    from wazumation.wazuh.plugin import PluginRegistry
    from wazumation.wazuh.plugins import register_all_plugins

    reg = PluginRegistry()
    with pytest.raises(FileNotFoundError) as exc:
        register_all_plugins(reg)

    assert "python3 tools/sync_wazuh_sections.py" in str(exc.value)


