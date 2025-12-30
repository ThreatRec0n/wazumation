"""CLI main entry point."""

import argparse
import json
import sys
from pathlib import Path

from wazumation.core.audit import AuditChain, AuditLogger, AuditResult
from wazumation.core.backup import BackupManager
from wazumation.core.config_paths import detect_ossec_conf_path
from wazumation.core.validator import ConfigValidator
from wazumation.core.applier import PlanApplier
from wazumation.core.diff import DiffEngine
from wazumation.core.change_plan import ChangePlan
from wazumation.wazuh.plugin import PluginRegistry
from wazumation.wazuh.plugins import register_all_plugins
from wazumation.features.cli import (
    cmd_list_features,
    cmd_status,
    cmd_enable_disable,
    cmd_diff,
)
from wazumation.features.state import default_state_path
from wazumation.features.self_test import run_self_test


def main():
    """CLI main function."""
    parser = argparse.ArgumentParser(description="Wazumation - Wazuh Configuration Automation")
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to ossec.conf",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path.home() / ".wazumation",
        help="Data directory for audit logs and backups",
    )
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode (no changes)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    # Feature selection mode (flags, no subcommand)
    parser.add_argument("--list", action="store_true", help="List available Wazuh features")
    parser.add_argument("--enable", type=str, help="Enable features (comma-separated)")
    parser.add_argument("--disable", type=str, help="Disable features (comma-separated)")
    parser.add_argument("--status", action="store_true", help="Show current feature status")
    parser.add_argument("--diff-feature", type=str, help="Show diff for a feature (by feature_id)")
    parser.add_argument("--gui", action="store_true", help="Launch GUI feature selector")
    parser.add_argument("--self-test", action="store_true", help="Run self test (apply+detect+revert) to prove tool is synced")
    parser.add_argument(
        "--fix-xml",
        action="store_true",
        help="Automatically fix common XML issues in ossec.conf (backs up original first)",
    )
    parser.add_argument(
        "--approve-features",
        action="store_true",
        help="Explicitly approve applying feature changes (required unless --dry-run)",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Allow subcommand-local overrides so users can place flags after the subcommand,
    # e.g. `... read syscheck --config path` (acceptance criteria).
    def _add_common_overrides(p: argparse.ArgumentParser) -> None:
        p.add_argument("--config", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        p.add_argument("--data-dir", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        p.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        p.add_argument("--verbose", "-v", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)

    # Read command
    read_parser = subparsers.add_parser("read", help="Read current configuration")
    read_parser.add_argument("module", help="Module/plugin name")
    _add_common_overrides(read_parser)

    # Plan command
    plan_parser = subparsers.add_parser("plan", help="Create a change plan")
    plan_parser.add_argument("module", help="Module/plugin name")
    plan_parser.add_argument("--desired", type=Path, required=True, help="Path to desired state JSON file")
    plan_parser.add_argument("--output", type=Path, required=True, help="Output plan JSON file")
    _add_common_overrides(plan_parser)

    # Apply command
    apply_parser = subparsers.add_parser("apply", help="Apply a change plan")
    apply_parser.add_argument("plan_file", type=Path, help="Path to plan file (JSON)")
    apply_parser.add_argument("--approve", action="store_true", help="Explicitly approve applying the plan")
    _add_common_overrides(apply_parser)

    # Diff command
    diff_parser = subparsers.add_parser("diff", help="Show diff for a plan")
    diff_parser.add_argument("plan_file", type=Path, help="Path to plan file (JSON)")
    _add_common_overrides(diff_parser)

    # Audit command
    audit_parser = subparsers.add_parser("audit", help="View audit log")
    audit_parser.add_argument("--module", help="Filter by module")
    audit_parser.add_argument("--user", help="Filter by user")
    audit_parser.add_argument("--limit", type=int, default=100, help="Limit results")
    _add_common_overrides(audit_parser)

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify audit chain integrity")
    _add_common_overrides(verify_parser)

    # List plugins
    list_parser = subparsers.add_parser("list-plugins", help="List supported ossec.conf sections/plugins")
    _add_common_overrides(list_parser)

    # Self test (subcommand)
    test_parser = subparsers.add_parser("test", help="Run self test (apply+detect+revert) to prove tool is synced")
    _add_common_overrides(test_parser)

    args = parser.parse_args()

    feature_mode = any(
        [
            args.list,
            bool(args.enable),
            bool(args.disable),
            args.status,
            bool(args.diff_feature),
            args.gui,
            args.self_test,
            args.fix_xml,
        ]
    )

    if not args.command and not feature_mode:
        parser.print_help()
        sys.exit(1)

    # Initialize components
    data_dir = args.data_dir
    data_dir.mkdir(exist_ok=True)

    audit_chain = AuditChain(data_dir / "audit.db")
    audit_logger = AuditLogger(audit_chain)
    backup_manager = BackupManager(data_dir / "backups")
    validator = ConfigValidator()
    applier = PlanApplier(backup_manager, validator, audit_logger, dry_run=args.dry_run)

    plugin_registry = PluginRegistry()
    register_all_plugins(plugin_registry)

    # Execute command
    if feature_mode:
        state_path = default_state_path()
        enable_list = [x.strip() for x in (args.enable or "").split(",") if x.strip()]
        disable_list = [x.strip() for x in (args.disable or "").split(",") if x.strip()]
        needs_config = bool(args.status) or bool(args.gui) or bool(args.self_test) or bool(args.fix_xml) or bool(enable_list or disable_list)
        if needs_config:
            try:
                args.config = detect_ossec_conf_path(config_override=args.config, state_path=state_path)
            except Exception as e:
                print(str(e), file=sys.stderr)
                sys.exit(1)

        if args.list:
            sys.exit(cmd_list_features())
        if args.fix_xml:
            print(f"Config: {args.config}", file=sys.stderr)
            was_fixed, msg = validator.auto_fix_xml_issues(args.config)
            print(msg)
            sys.exit(0 if was_fixed else 1)
        if args.status:
            print(f"Config: {args.config}", file=sys.stderr)
            sys.exit(cmd_status(state_path, args.config))
        if args.diff_feature:
            sys.exit(cmd_diff(args.diff_feature, state_path, data_dir))
        if args.gui:
            # Lazy-load GUI to keep CLI headless-friendly (tkinter may not be installed).
            try:
                from wazumation.features.gui import launch_gui  # local import by design
            except ModuleNotFoundError as e:
                # If tkinter isn't installed, importing gui will fail inside it; but keep this
                # as a hard safety net for unusual environments.
                if str(e).strip("'\"") in ("tkinter",):
                    print(
                        "GUI requires python3-tk. Install: sudo apt-get update && sudo apt-get install -y python3-tk",
                        file=sys.stderr,
                    )
                    sys.exit(1)
                raise
            sys.exit(
                launch_gui(
                    config_path=args.config,
                    data_dir=data_dir,
                    state_path=state_path,
                    applier=applier,
                    validator=validator,
                )
            )
        if args.self_test:
            print(f"Config: {args.config}", file=sys.stderr)
            res = run_self_test(config_path=args.config, data_dir=data_dir, applier=applier, validator=validator)
            print(res.render())
            sys.exit(0 if res.passed else 1)
        if enable_list or disable_list:
            print(f"Config: {args.config}", file=sys.stderr)
            sys.exit(
                cmd_enable_disable(
                    config_path=args.config,
                    data_dir=data_dir,
                    state_path=state_path,
                    enable=enable_list,
                    disable=disable_list,
                    approve_features=args.approve_features,
                    dry_run=args.dry_run,
                    interactive=sys.stdin.isatty(),
                    prompt_fn_override=None,
                    applier=applier,
                    validator=validator,
                )
            )
        sys.exit(0)

    if args.command == "read":
        state_path = default_state_path()
        try:
            args.config = detect_ossec_conf_path(config_override=args.config, state_path=state_path)
        except Exception as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
        module = args.module
        if module == "wazuh-db":
            print("Warning: 'wazuh-db' is deprecated; use 'wazuh_db' instead.", file=sys.stderr)
            module = "wazuh_db"
        plugin = plugin_registry.get(module)
        if not plugin:
            print(f"Error: Module '{args.module}' not found", file=sys.stderr)
            sys.exit(1)
        print(f"Config: {args.config}", file=sys.stderr)
        state = plugin.read(args.config)
        print(json.dumps(state, indent=2))

    elif args.command == "plan":
        state_path = default_state_path()
        try:
            args.config = detect_ossec_conf_path(config_override=args.config, state_path=state_path)
        except Exception as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
        module = args.module
        if module == "wazuh-db":
            print("Warning: 'wazuh-db' is deprecated; use 'wazuh_db' instead.", file=sys.stderr)
            module = "wazuh_db"
        plugin = plugin_registry.get(module)
        if not plugin:
            print(f"Error: Module '{args.module}' not found", file=sys.stderr)
            sys.exit(1)
        print(f"Config: {args.config}", file=sys.stderr)
        if not args.desired.exists():
            print(f"Error: Desired state file not found: {args.desired}", file=sys.stderr)
            sys.exit(1)

        # Read current state
        current_state = plugin.read(args.config)

        # Read desired state
        with open(args.desired, "r", encoding="utf-8") as f:
            desired_state = json.load(f)

        # Validate desired state
        is_valid, errors = plugin.validate(desired_state)
        if not is_valid:
            print(f"Error: Desired state validation failed:", file=sys.stderr)
            for error in errors:
                print(f"  {error}", file=sys.stderr)
            sys.exit(1)

        # Generate plan
        plan = plugin.plan(args.config, current_state, desired_state)

        # Validate generated plan (security-first gate)
        plan_ok, plan_errors = validator.validate_plan(plan)
        if not plan_ok:
            print("Error: Generated plan is invalid:", file=sys.stderr)
            for error in plan_errors:
                print(f"  {error}", file=sys.stderr)
            sys.exit(1)

        # Save plan (even if empty, for deterministic workflows and for diff/apply commands)
        plan.to_json(args.output)
        print(f"Plan created: {args.output}")
        print(f"Plan ID: {plan.plan_id}")
        summary = plan.get_summary()
        try:
            print(summary)
        except UnicodeEncodeError:
            # Fallback for Windows console encoding issues
            print(summary.encode("ascii", "replace").decode("ascii"))

        if plan.is_empty():
            print("No changes needed. Current state matches desired state.", file=sys.stderr)
            sys.exit(0)

    elif args.command == "diff":
        if not args.plan_file.exists():
            print(f"Error: Plan file not found: {args.plan_file}", file=sys.stderr)
            sys.exit(1)

        plan = ChangePlan.from_json(args.plan_file)
        diff_output = DiffEngine.generate_plan_diff(plan)
        print(diff_output)

    elif args.command == "apply":
        if not args.plan_file.exists():
            print(f"Error: Plan file not found: {args.plan_file}", file=sys.stderr)
            sys.exit(1)

        if not args.approve:
            print("Error: --approve flag required to apply changes", file=sys.stderr)
            print("Review the plan with 'diff' command first, then use --approve to apply.", file=sys.stderr)
            sys.exit(1)

        plan = ChangePlan.from_json(args.plan_file)

        if plan.is_empty():
            print("Plan is empty. Nothing to apply.")
            sys.exit(0)

        # Show plan summary
        print("Applying plan:")
        print(plan.get_summary())
        print()

        # Apply plan
        success, errors = applier.apply(plan, require_approval=True)  # Approval gate satisfied via --approve flag

        if success:
            print("[OK] Plan applied successfully")
            sys.exit(0)
        else:
            print("[FAIL] Plan application failed:", file=sys.stderr)
            for error in errors:
                print(f"  {error}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "audit":
        entries = audit_chain.query(
            module=args.module, user=args.user, limit=args.limit
        )
        print(f"Found {len(entries)} audit entries")
        for entry in entries:
            print(
                f"{entry.timestamp.isoformat()} | {entry.user} | {entry.module} | {entry.action} | {entry.result.value}"
            )

    elif args.command == "verify":
        is_valid, errors = audit_chain.verify_chain()
        if is_valid:
            print("[OK] Audit chain integrity verified")
            sys.exit(0)
        else:
            print("[FAIL] Audit chain integrity failed:")
            for error in errors:
                print(f"  {error}")
            sys.exit(1)

    elif args.command == "list-plugins":
        # Must match the authoritative section list exactly (one entry per line).
        plugins = plugin_registry.list_all()
        for p in sorted(plugins, key=lambda x: x.name):
            print(p.name)
        sys.exit(0)

    elif args.command == "test":
        state_path = default_state_path()
        try:
            args.config = detect_ossec_conf_path(config_override=args.config, state_path=state_path)
        except Exception as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
        print(f"Config: {args.config}", file=sys.stderr)
        res = run_self_test(config_path=args.config, data_dir=data_dir, applier=applier, validator=validator)
        print(res.render())
        sys.exit(0 if res.passed else 1)


if __name__ == "__main__":
    main()

