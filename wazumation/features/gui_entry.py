"""Console entrypoint for the lightweight Tkinter feature selector GUI."""

from __future__ import annotations

import argparse
from pathlib import Path

from wazumation.core.audit import AuditChain, AuditLogger
from wazumation.core.backup import BackupManager
from wazumation.core.applier import PlanApplier
from wazumation.core.validator import ConfigValidator
from wazumation.features.gui import launch_gui
from wazumation.features.state import default_state_path


def main() -> None:
    p = argparse.ArgumentParser(description="Wazumation Feature Selector GUI")
    p.add_argument(
        "--config",
        type=Path,
        default=Path("/var/ossec/etc/ossec.conf"),
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
    raise SystemExit(
        launch_gui(
            config_path=args.config,
            data_dir=data_dir,
            state_path=state_path,
            applier=applier,
            validator=validator,
        )
    )


if __name__ == "__main__":
    main()


