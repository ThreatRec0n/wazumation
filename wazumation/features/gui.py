"""Optional GUI feature selector (tkinter/ttk, lightweight)."""

from __future__ import annotations

import os
import sys
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, List, Callable

from wazumation.features.registry import get_feature_registry
from wazumation.features.state import FeatureState
from wazumation.features.detector import detect_feature_states
from wazumation.features.cli import cmd_enable_disable
from wazumation.features.self_test import run_self_test
from wazumation.features.service_manager import WazuhServiceManager


def launch_gui(*, config_path: Path, data_dir: Path, state_path: Path, applier, validator) -> int:
    # Lazy tkinter import: CLI must work headless with zero GUI deps.
    try:
        import tkinter as tk  # type: ignore
        from tkinter import messagebox, simpledialog  # type: ignore
    except Exception:
        import sys

        print("GUI requires python3-tk. Install: sudo apt-get update && sudo apt-get install -y python3-tk", file=sys.stderr)
        return 1

    # ttk-based, dark theme UI. Keep it lightweight and avoid freezing via threads.
    import threading
    from tkinter import ttk

    reg = get_feature_registry()
    st = FeatureState.load(state_path)

    root = tk.Tk()
    root.title("Wazumation - Wazuh Feature Selector")
    root.geometry("1000x720")

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    BG = "#1e1e1e"
    FG = "#e6e6e6"
    ACCENT = "#4caf50"
    WARN = "#ff9800"
    ERR = "#f44336"

    root.configure(bg=BG)
    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=FG)
    style.configure("TLabelframe", background=BG, foreground=FG)
    style.configure("TLabelframe.Label", background=BG, foreground=FG)
    style.configure("TButton", padding=6)
    style.configure("TCheckbutton", background=BG, foreground=FG)

    # Top bar
    top = ttk.Frame(root)
    top.pack(fill="x", padx=12, pady=(12, 6))

    ttk.Label(top, text="Wazumation", font=("Segoe UI", 16, "bold")).pack(side="left")
    cfg_lbl = ttk.Label(top, text=f"Config: {config_path}", foreground="#9fb3c8")
    cfg_lbl.pack(side="left", padx=(12, 0))

    wazuh_status = ttk.Label(top, text="Wazuh: UNKNOWN", foreground=WARN)
    wazuh_status.pack(side="right", padx=(10, 0))

    # Main split
    main = ttk.PanedWindow(root, orient="horizontal")
    main.pack(fill="both", expand=True, padx=12, pady=6)

    left = ttk.Frame(main)
    right = ttk.Frame(main)
    main.add(left, weight=2)
    main.add(right, weight=3)

    # Left: search + list
    ttk.Label(left, text="Features").pack(anchor="w")
    search_var = tk.StringVar(value="")
    search_entry = ttk.Entry(left, textvariable=search_var)
    search_entry.pack(fill="x", pady=(6, 6))

    cols = ("status", "id")
    tree = ttk.Treeview(left, columns=cols, show="headings", height=18)
    tree.heading("status", text="Status")
    tree.heading("id", text="Feature")
    tree.column("status", width=90, anchor="center")
    tree.column("id", width=240, anchor="w")
    tree.pack(fill="both", expand=True)

    # Desired state toggles
    # Desired toggles (what user wants). Bootstrap from *live detection* on first load.
    desired_enabled: Dict[str, bool] = {fid: False for fid in reg.keys()}
    desired_initialized = False

    # Right: details + schema-driven config form
    title_lbl = ttk.Label(right, text="Select a feature", font=("Segoe UI", 14, "bold"))
    title_lbl.pack(anchor="w")
    desc_lbl = ttk.Label(right, text="", wraplength=520, justify="left")
    desc_lbl.pack(anchor="w", pady=(6, 10))

    form_frame = ttk.Labelframe(right, text="Configuration", padding=10)
    form_frame.pack(fill="x", pady=(0, 10))

    # Field widgets: name -> (spec, var, widget)
    field_vars: Dict[str, Any] = {}
    current_feature_id: Optional[str] = None

    def clear_form():
        for child in list(form_frame.winfo_children()):
            child.destroy()
        field_vars.clear()

    def log(msg: str) -> None:
        log_box.insert("end", msg + "\n")
        log_box.see("end")

    def handle_service_error(error_msg: str) -> None:
        """Show helpful dialog when service operations fail."""
        from tkinter import messagebox  # type: ignore

        dialog_msg = f"Service operation failed:\n\n{error_msg}\n\n"
        dialog_msg += "Common solutions:\n"
        dialog_msg += "• Check if Wazuh is installed\n"
        dialog_msg += "• Run: sudo systemctl status wazuh-manager\n"
        dialog_msg += "• Start service: sudo systemctl start wazuh-manager\n"
        dialog_msg += "• Check logs: sudo journalctl -xeu wazuh-manager\n"
        messagebox.showerror("Service Error", dialog_msg)

    def refresh_wazuh_status() -> None:
        """Refresh Wazuh service status indicator."""
        try:
            status = WazuhServiceManager.get_status()

            status_colors = {
                "running": ACCENT,
                "stopped": ERR,
                "failed": "#ff5722",
                "unknown": WARN,
            }
            status_text = {
                "running": "Wazuh: RUNNING",
                "stopped": "Wazuh: STOPPED",
                "failed": "Wazuh: FAILED",
                "unknown": "Wazuh: UNKNOWN",
            }

            wazuh_status.configure(
                text=status_text.get(status, "Wazuh: ???"),
                foreground=status_colors.get(status, WARN),
            )
        except Exception:
            wazuh_status.configure(text="Wazuh: UNKNOWN", foreground=WARN)

    def auto_refresh_status() -> None:
        """Auto-refresh service status periodically."""
        refresh_wazuh_status()
        root.after(5000, auto_refresh_status)

    def load_detection() -> Dict[str, Dict[str, Any]]:
        return detect_feature_states(config_path)

    detected_cache: Dict[str, Dict[str, Any]] = {}

    def populate_tree():
        nonlocal detected_cache
        nonlocal desired_initialized
        detected_cache = load_detection()
        tree.delete(*tree.get_children())
        q = search_var.get().strip().lower()
        for fid in sorted(reg.keys()):
            f = reg[fid]
            if q and (q not in fid.lower() and q not in f.title.lower()):
                continue
            stt = detected_cache.get(fid, {}).get("status", "unknown")
            tree.insert("", "end", iid=fid, values=(stt, f"{fid} — {f.title}"))

        # Bootstrap desired toggles from live detection once per GUI session.
        if not desired_initialized:
            for fid in reg.keys():
                desired_enabled[fid] = detected_cache.get(fid, {}).get("status") == "enabled"
            desired_initialized = True

    def validate_current_fields() -> Optional[str]:
        if not current_feature_id:
            return None
        f = reg[current_feature_id]
        if not f.config_schema:
            return None
        values: Dict[str, Any] = {}
        for fs in f.config_schema:
            v = field_vars.get(fs.name)
            if v is None:
                continue
            raw = v.get() if hasattr(v, "get") else v
            # list[string] fields are entered as comma separated
            try:
                coerced = fs.coerce(raw)
            except Exception as e:
                return f"{fs.name}: {e}"
            ok, msg = fs.validate(coerced)
            if not ok:
                return msg
            values[fs.name] = coerced
        return None

    def values_for_feature(fid: str) -> Dict[str, Any]:
        f = reg[fid]
        vals: Dict[str, Any] = {}
        for fs in f.config_schema:
            v = field_vars.get(fs.name)
            if v is None:
                continue
            raw = v.get() if hasattr(v, "get") else v
            vals[fs.name] = fs.coerce(raw)
        return vals

    def render_feature(fid: str):
        nonlocal current_feature_id
        current_feature_id = fid
        f = reg[fid]
        title_lbl.configure(text=f"{fid} — {f.title}")
        stt = detected_cache.get(fid, {}).get("status", "unknown")
        desc_lbl.configure(text=f"{f.description}\n\nDetected: {stt}")

        clear_form()
        if not f.config_schema:
            ttk.Label(form_frame, text="No additional configuration required for this feature.").pack(anchor="w")
            return

        # Prefill from detected values when present.
        detected_values = detected_cache.get(fid, {}).get("values", {}) or {}

        row = 0
        for fs in f.config_schema:
            ttk.Label(form_frame, text=fs.name).grid(row=row, column=0, sticky="w", pady=4)
            default_val = detected_values.get(fs.name, fs.default if fs.default is not None else "")
            if fs.field_type == "bool":
                var = tk.BooleanVar(value=bool(default_val) if not isinstance(default_val, str) else default_val.lower() in ("1", "true", "yes", "y", "on"))
                cb = ttk.Checkbutton(form_frame, variable=var)
                cb.grid(row=row, column=1, sticky="w", pady=4)
                field_vars[fs.name] = var
            else:
                if isinstance(default_val, list):
                    default_val = ",".join(str(x) for x in default_val)
                var = tk.StringVar(value=str(default_val) if default_val is not None else "")
                ent = ttk.Entry(form_frame, textvariable=var)
                ent.grid(row=row, column=1, sticky="ew", pady=4)
                field_vars[fs.name] = var
            if fs.help_text:
                ttk.Label(form_frame, text=fs.help_text, foreground="#9fb3c8", wraplength=420).grid(
                    row=row + 1, column=0, columnspan=2, sticky="w", pady=(0, 6)
                )
                row += 1
            row += 1

        form_frame.columnconfigure(1, weight=1)

    def on_select(_evt=None):
        sel = tree.selection()
        if not sel:
            return
        render_feature(sel[0])

    tree.bind("<<TreeviewSelect>>", on_select)

    def set_desired(enable: bool):
        sel = tree.selection()
        if not sel:
            return
        for fid in sel:
            desired_enabled[fid] = enable
        log(f"Set desired={'ENABLED' if enable else 'DISABLED'} for: {', '.join(sel)}")

    def build_values_by_feature(enable_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        for fid in enable_ids:
            if fid == current_feature_id:
                err = validate_current_fields()
                if err:
                    raise ValueError(err)
            if reg[fid].config_schema:
                out[fid] = values_for_feature(fid)
        return out

    # Buttons + progress
    actions = ttk.Frame(right)
    actions.pack(fill="x", pady=(0, 8))
    approve_var = tk.BooleanVar(value=False)
    dry_run_var = tk.BooleanVar(value=True)
    ttk.Checkbutton(actions, text="Approve apply", variable=approve_var).pack(side="left")
    ttk.Checkbutton(actions, text="Dry run", variable=dry_run_var).pack(side="left", padx=(10, 0))

    pb = ttk.Progressbar(actions, mode="indeterminate")
    pb.pack(side="right", fill="x", expand=True, padx=(10, 0))

    btn_row = ttk.Frame(right)
    btn_row.pack(fill="x", pady=(0, 10))

    def run_in_thread(fn):
        def wrap():
            try:
                pb.start(10)
                fn()
            finally:
                pb.stop()
                root.after(0, refresh_wazuh_status)
        threading.Thread(target=wrap, daemon=True).start()

    def do_refresh():
        def _work():
            root.after(0, lambda: log("Refreshing status..."))
            root.after(0, populate_tree)
        run_in_thread(_work)

    def do_apply():
        if not approve_var.get() and not dry_run_var.get():
            messagebox.showerror("Approval required", "Check 'Approve apply' to perform real changes.")
            return

        # Decide what to change based on *live detection* (state file can drift).
        enable_ids = [
            fid
            for fid, desired in desired_enabled.items()
            if desired and detected_cache.get(fid, {}).get("status") != "enabled"
        ]
        disable_ids = [
            fid
            for fid, desired in desired_enabled.items()
            if (not desired) and detected_cache.get(fid, {}).get("status") in ("enabled", "partial")
        ]

        def _work():
            try:
                vals = build_values_by_feature(enable_ids)
                rc = cmd_enable_disable(
                    config_path=config_path,
                    data_dir=data_dir,
                    state_path=state_path,
                    enable=enable_ids,
                    disable=disable_ids,
                    approve_features=approve_var.get(),
                    dry_run=dry_run_var.get(),
                    interactive=True,
                    prompt_fn_override=None,
                    values_by_feature=vals,
                    applier=applier,
                    validator=validator,
                )
                root.after(0, lambda: log(f"Apply finished (rc={rc})."))
                # After successful apply, auto-refresh status shortly after (gives systemd time).
                root.after(0, lambda: log("Auto-refreshing status..."))
                root.after(1000, refresh_wazuh_status)
            except Exception as e:
                msg = str(e)
                root.after(0, lambda: messagebox.showerror("Apply failed", msg))
                if "Service operation failed" in msg or "systemctl" in msg:
                    root.after(0, lambda: handle_service_error(msg))
            root.after(0, populate_tree)

        run_in_thread(_work)

    def do_self_test():
        def _work():
            res = run_self_test(config_path=config_path, data_dir=data_dir, applier=applier, validator=validator)
            root.after(0, lambda: log(res.render()))
            root.after(0, lambda: messagebox.showinfo("Self Test", "PASS" if res.passed else "FAIL"))
        run_in_thread(_work)

    def do_diff():
        sel = tree.selection()
        if not sel:
            return
        fid = sel[0]
        # show last plan diff if present
        try:
            from wazumation.features.state import FeatureState
            from wazumation.core.change_plan import ChangePlan
            from wazumation.core.diff import DiffEngine
            st2 = FeatureState.load(state_path)
            info = st2.enabled.get(fid)
            if not info or not info.get("last_plan_path"):
                messagebox.showinfo("Diff", "No recorded plan for this feature yet. Apply it first.")
                return
            plan = ChangePlan.from_json(Path(info["last_plan_path"]))
            diff_txt = DiffEngine.generate_plan_diff(plan)
        except Exception as e:
            messagebox.showerror("Diff error", str(e))
            return

        win = tk.Toplevel(root)
        win.title(f"Diff: {fid}")
        win.geometry("900x600")
        t = tk.Text(win, bg="#111", fg="#eee")
        t.pack(fill="both", expand=True)
        t.insert("1.0", diff_txt)
        t.configure(state="disabled")

    ttk.Button(btn_row, text="Refresh", command=do_refresh).pack(side="left")
    # Service controls
    def _start_service():
        def _work():
            root.after(0, lambda: log("Starting Wazuh service..."))
            ok, msg = WazuhServiceManager.start()
            root.after(0, lambda: log(("✓ " if ok else "✗ ") + msg))
            if not ok:
                root.after(0, lambda: handle_service_error(msg))
            root.after(1000, refresh_wazuh_status)

        run_in_thread(_work)

    def _stop_service():
        if not messagebox.askyesno("Confirm", "Stop Wazuh service?"):
            return

        def _work():
            root.after(0, lambda: log("Stopping Wazuh service..."))
            ok, msg = WazuhServiceManager.stop()
            root.after(0, lambda: log(("✓ " if ok else "✗ ") + msg))
            if not ok:
                root.after(0, lambda: handle_service_error(msg))
            root.after(1000, refresh_wazuh_status)

        run_in_thread(_work)

    def _restart_service():
        def _work():
            root.after(0, lambda: log("Restarting Wazuh service..."))
            ok, msg = WazuhServiceManager.restart()
            root.after(0, lambda: log(("✓ " if ok else "✗ ") + msg))
            if not ok:
                root.after(0, lambda: handle_service_error(msg))
            root.after(1000, refresh_wazuh_status)

        run_in_thread(_work)

    def _daemon_reload():
        def _work():
            root.after(0, lambda: log("Reloading systemd daemon..."))
            ok, msg = WazuhServiceManager.daemon_reload()
            root.after(0, lambda: log(("✓ " if ok else "✗ ") + msg))
            if not ok:
                root.after(0, lambda: handle_service_error(msg))
            root.after(1000, refresh_wazuh_status)

        run_in_thread(_work)

    def _show_logs():
        import tkinter as tk  # type: ignore
        from tkinter import ttk  # type: ignore
        from tkinter import scrolledtext  # type: ignore

        win = tk.Toplevel(root)
        win.title("Wazuh Logs")
        win.geometry("950x650")

        nb = ttk.Notebook(win)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        # Tab 1: systemd journal
        f1 = ttk.Frame(nb)
        nb.add(f1, text="systemd Journal")
        t1 = scrolledtext.ScrolledText(f1, wrap="word", bg="#111", fg="#eee", font=("Consolas", 9))
        t1.pack(fill="both", expand=True)
        try:
            r = subprocess.run(
                ["journalctl", "-xeu", "wazuh-manager", "-n", "200", "--no-pager"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            t1.insert("1.0", r.stdout or r.stderr or "(no output)")
        except Exception as e:
            t1.insert("1.0", f"Error fetching journalctl: {e}")
        t1.configure(state="disabled")

        # Tab 2: ossec.log
        f2 = ttk.Frame(nb)
        nb.add(f2, text="ossec.log")
        t2 = scrolledtext.ScrolledText(f2, wrap="word", bg="#111", fg="#eee", font=("Consolas", 9))
        t2.pack(fill="both", expand=True)
        try:
            p = Path("/var/ossec/logs/ossec.log")
            if p.exists():
                lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
                t2.insert("1.0", "\n".join(lines[-200:]))
            else:
                t2.insert("1.0", f"File not found: {p}")
        except Exception as e:
            t2.insert("1.0", f"Error reading ossec.log: {e}")
        t2.configure(state="disabled")

        ttk.Button(win, text="Close", command=win.destroy).pack(pady=(0, 10))

    ttk.Button(btn_row, text="Reload Daemon", command=_daemon_reload).pack(side="left", padx=(8, 0))
    ttk.Button(btn_row, text="Start Wazuh", command=_start_service).pack(side="left", padx=(8, 0))
    ttk.Button(btn_row, text="Stop Wazuh", command=_stop_service).pack(side="left", padx=(8, 0))
    ttk.Button(btn_row, text="Restart Wazuh", command=_restart_service).pack(side="left", padx=(8, 0))
    ttk.Button(btn_row, text="Logs", command=_show_logs).pack(side="left", padx=(8, 0))
    ttk.Button(btn_row, text="Enable Selected", command=lambda: set_desired(True)).pack(side="left", padx=(8, 0))
    ttk.Button(btn_row, text="Disable Selected", command=lambda: set_desired(False)).pack(side="left", padx=(8, 0))
    ttk.Button(btn_row, text="Diff", command=do_diff).pack(side="left", padx=(8, 0))
    ttk.Button(btn_row, text="Self Test", command=do_self_test).pack(side="right")
    ttk.Button(btn_row, text="Apply", command=do_apply).pack(side="right", padx=(0, 8))

    # Log
    log_frame = ttk.Labelframe(root, text="Log", padding=8)
    log_frame.pack(fill="both", expand=False, padx=12, pady=(0, 12))
    log_box = tk.Text(log_frame, height=8, bg="#111", fg="#eee")
    log_box.pack(fill="both", expand=True)

    def on_search(*_a):
        populate_tree()
    search_var.trace_add("write", on_search)

    refresh_wazuh_status()
    auto_refresh_status()
    populate_tree()
    log("Ready.")

    root.mainloop()
    return 0


