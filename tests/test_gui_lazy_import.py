import builtins
import importlib


def test_gui_requires_tkinter_message(monkeypatch, capsys):
    """
    Simulate a headless server without tkinter: launching GUI should fail cleanly
    with the required installation message, without breaking CLI-only imports.
    """

    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "tkinter" or name.startswith("tkinter."):
            raise ModuleNotFoundError("No module named 'tkinter'")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    # Importing CLI should still work (no tkinter import at import-time).
    import wazumation.cli.main as cli_main

    importlib.reload(cli_main)

    # Importing GUI module should still work (tkinter is imported lazily in launch_gui()).
    import wazumation.features.gui as gui

    # Now calling the GUI should produce the clean error.
    from pathlib import Path
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        cfg = tmp / "ossec.conf"
        cfg.write_text("<ossec_config></ossec_config>\n", encoding="utf-8")
        rc = gui.launch_gui(
            config_path=cfg,
            data_dir=tmp / "data",
            state_path=tmp / "state.json",
            applier=None,
            validator=None,
        )
    assert rc == 1
    captured = capsys.readouterr()
    assert "GUI requires python3-tk. Install with: sudo apt install python3-tk" in captured.err


