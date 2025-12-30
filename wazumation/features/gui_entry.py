"""Console entrypoint for the lightweight Tkinter feature selector GUI."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from wazumation.core.audit import AuditChain, AuditLogger
from wazumation.core.backup import BackupManager
from wazumation.core.applier import PlanApplier
from wazumation.core.config_paths import detect_ossec_conf_path
from wazumation.core.validator import ConfigValidator
from wazumation.features.state import default_state_path


def main() -> None:
    p = argparse.ArgumentParser(description="Wazumation Feature Selector GUI")
    p.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to ossec.conf",
    )
    p.add_argument(
        "--data-dir",
        type=Path,
        default=Path.home() / ".wazumation",
        help="Data directory for audit logs and backups",
    )
    args = p.parse_args()

    data_dir = args.data_dir
    data_dir.mkdir(parents=True, exist_ok=True)

    audit_chain = AuditChain(data_dir / "audit.db")
    audit_logger = AuditLogger(audit_chain)
    backup_manager = BackupManager(data_dir / "backups")
    validator = ConfigValidator()
    applier = PlanApplier(backup_manager, validator, audit_logger, dry_run=False)

    state_path = default_state_path()
    try:
        cfg = detect_ossec_conf_path(config_override=args.config, state_path=state_path)
    except Exception as e:
        print(str(e), file=sys.stderr)
        raise SystemExit(1)

    # Lazy-load GUI (tkinter may not be installed on headless servers).
    try:
        from wazumation.features.gui import launch_gui  # local import by design
    except ModuleNotFoundError as e:
        if str(e).strip("'\"") in ("tkinter",):
            print("GUI requires python3-tk. Install: sudo apt-get update && sudo apt-get install -y python3-tk", file=sys.stderr)
            raise SystemExit(1)
        raise
    raise SystemExit(
        launch_gui(
            config_path=cfg,
            data_dir=data_dir,
            state_path=state_path,
            applier=applier,
            validator=validator,
        )
    )


if __name__ == "__main__":
    main()


