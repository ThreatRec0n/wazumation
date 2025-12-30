"""Tests for missing data/wazuh_sections.json handling (actionable error)."""

import os
from pathlib import Path

import pytest


def test_missing_sections_file_falls_back_to_defaults(monkeypatch, tmp_path, caplog):
    # Simulate running from a directory without data/ or wazumation/data/
    monkeypatch.chdir(tmp_path)

    # Ensure tool auto-generation path is attempted but fails cleanly.
    import tools.sync_wazuh_sections as sync_mod

    def _fail_sync(_path: Path):
        raise RuntimeError("no internet")

    monkeypatch.setattr(sync_mod, "sync", _fail_sync)

    from wazumation.wazuh.plugin import PluginRegistry
    from wazumation.wazuh.plugins import register_all_plugins

    reg = PluginRegistry()
    with caplog.at_level("WARNING"):
        register_all_plugins(reg)

    # Minimal defaults should still register, keeping CLI usable even without the full catalog.
    assert len(reg.list_all()) >= 6
    assert reg.get("global") is not None
    # Note: in normal installs this should load from packaged data (no warning needed).


