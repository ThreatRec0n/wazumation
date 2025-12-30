"""Optional GUI feature selector (tkinter)."""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import messagebox, simpledialog
from pathlib import Path
from typing import Optional, List

from wazumation.features.registry import get_feature_registry
from wazumation.features.state import FeatureState
from wazumation.features.cli import cmd_enable_disable


def launch_gui(*, config_path: Path, data_dir: Path, state_path: Path, applier, validator) -> int:
    reg = get_feature_registry()
    st = FeatureState.load(state_path)

    root = tk.Tk()
    root.title("Wazumation - Feature Selector")

    tk.Label(root, text="Select features to enable (checked) or disable (unchecked):").pack(
        anchor="w", padx=10, pady=(10, 4)
    )

    frame = tk.Frame(root)
    frame.pack(fill="both", expand=True, padx=10, pady=5)

    vars_by_id = {}
    for fid in sorted(reg.keys()):
        v = tk.BooleanVar(value=(fid in st.enabled))
        vars_by_id[fid] = v
        cb = tk.Checkbutton(frame, text=f"{fid} — {reg[fid].title}", variable=v, anchor="w", justify="left")
        cb.pack(fill="x", anchor="w")

    dry_run_var = tk.BooleanVar(value=True)
    approve_var = tk.BooleanVar(value=False)

    tk.Checkbutton(root, text="Dry run (no changes)", variable=dry_run_var).pack(anchor="w", padx=10, pady=(8, 0))
    tk.Checkbutton(root, text="Approve apply (required for real changes)", variable=approve_var).pack(
        anchor="w", padx=10, pady=(0, 8)
    )

    def prompt_fn(prompt: str, default: Optional[str], required: bool) -> str:
        val = simpledialog.askstring("Wazumation input", prompt, initialvalue=default or "")
        if val is None:
            raise RuntimeError("User cancelled input")
        val = val.strip()
        if not val and default is not None:
            val = default
        if required and not val:
            raise ValueError(f"Missing required value for: {prompt}")
        return val

    def on_apply():
        desired_enabled = [fid for fid, v in vars_by_id.items() if v.get()]
        currently_enabled = set(st.enabled.keys())
        enable = [fid for fid in desired_enabled if fid not in currently_enabled]
        disable = [fid for fid in currently_enabled if fid not in set(desired_enabled)]

        # Run apply through the shared CLI logic (no code duplication).
        try:
            rc = cmd_enable_disable(
                config_path=config_path,
                data_dir=data_dir,
                state_path=state_path,
                enable=enable,
                disable=disable,
                approve_features=approve_var.get(),
                dry_run=dry_run_var.get(),
                interactive=True,
                prompt_fn_override=prompt_fn,
                applier=applier,
                validator=validator,
            )
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        if rc == 0:
            messagebox.showinfo("Success", "Operation completed successfully.")
            root.destroy()
        else:
            messagebox.showerror("Failed", "Operation failed. Check CLI output for details.")

    btns = tk.Frame(root)
    btns.pack(fill="x", padx=10, pady=10)
    tk.Button(btns, text="Apply", command=on_apply).pack(side="right")
    tk.Button(btns, text="Cancel", command=root.destroy).pack(side="right", padx=(0, 8))

    root.mainloop()
    return 0


