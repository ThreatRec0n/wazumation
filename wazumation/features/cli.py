"""Feature-mode CLI entrypoint helpers."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from wazumation.core.audit import AuditResult
from wazumation.core.change_plan import ChangePlan
from wazumation.core.diff import DiffEngine
from wazumation.features.planner import build_feature_plan
from wazumation.features.registry import get_feature_registry
from wazumation.features.state import FeatureState, default_state_path


def _parse_csv(arg: Optional[str]) -> List[str]:
    if not arg:
        return []
    return [x.strip() for x in arg.split(",") if x.strip()]


def cmd_list_features() -> int:
    reg = get_feature_registry()
    for fid in sorted(reg.keys()):
        f = reg[fid]
        print(f"{fid}\t{f.title}")
    return 0


def cmd_status(state_path: Path) -> int:
    st = FeatureState.load(state_path)
    print(f"State file: {state_path}")
    print(f"Last applied: {st.last_applied_at or 'never'}")
    print("Enabled features:")
    for fid in sorted(st.enabled.keys()):
        print(f"  {fid}")
    if st.modified_files:
        print("Modified files:")
        for p in st.modified_files:
            print(f"  {p}")
    return 0


def cmd_diff(feature_id: str, state_path: Path, data_dir: Path) -> int:
    st = FeatureState.load(state_path)
    info = st.enabled.get(feature_id)
    if not info:
        print(f"Error: feature not enabled or no plan recorded: {feature_id}", file=sys.stderr)
        return 1
    plan_path = Path(info.get("last_plan_path", ""))
    if not plan_path.exists():
        print(f"Error: plan file not found: {plan_path}", file=sys.stderr)
        return 1
    plan = ChangePlan.from_json(plan_path)
    print(DiffEngine.generate_plan_diff(plan))
    return 0


def cmd_enable_disable(
    *,
    config_path: Path,
    data_dir: Path,
    state_path: Path,
    enable: List[str],
    disable: List[str],
    approve_features: bool,
    dry_run: bool,
    interactive: bool,
    prompt_fn_override,
    applier,
    validator,
) -> int:
    if not dry_run and not approve_features:
        print("Error: refusing to modify system without explicit approval.", file=sys.stderr)
        print("Re-run with --approve-features (or use --dry-run).", file=sys.stderr)
        return 1

    reg = get_feature_registry()
    unknown = [x for x in enable + disable if x not in reg]
    if unknown:
        print(f"Error: unknown feature(s): {', '.join(unknown)}", file=sys.stderr)
        return 1

    st = FeatureState.load(state_path)

    enable_feats = [reg[x] for x in enable if x not in st.enabled]
    disable_feats = [reg[x] for x in disable if x in st.enabled]

    # Capture restore snapshot for features being enabled.
    restore_snapshot = {}
    for f in enable_feats:
        restore = {}
        for action in f.actions:
            section = action["section"]
            if "desired" in action:
                # Restore by deleting keys we set (best-effort safe revert).
                restore[section] = {k: None for k in action["desired"].keys()}
            elif "ensure_instance" in action and section == "localfile":
                # Restore by removing the instance only if we added it.
                restore.setdefault("__remove_localfile__", []).append(action["ensure_instance"])
        restore_snapshot[f.feature_id] = {"restore": restore}

    # Build a plan applying all requested toggles as a single atomic change.
    def _prompt_value(prompt: str, default: Optional[str] = None, required: bool = False) -> str:
        if default:
            p = f"{prompt} [{default}]: "
        else:
            p = f"{prompt}: "
        val = input(p).strip()
        if not val and default is not None:
            val = default
        if required and not val:
            raise ValueError(f"Missing required value for: {prompt}")
        return val

    prompt_fn = prompt_fn_override or (_prompt_value if interactive else None)

    result = build_feature_plan(
        config_path=config_path,
        data_dir=data_dir,
        enable_features=[{"feature_id": f.feature_id, "actions": f.actions} for f in enable_feats],
        disable_features=[{"feature_id": f.feature_id, "actions": f.actions} for f in disable_feats],
        state_snapshot={fid: st.enabled[fid] for fid in disable if fid in st.enabled} | restore_snapshot,
        prompt_fn=prompt_fn,
    )

    plan = result.plan
    ok, errs = validator.validate_plan(plan)
    if not ok:
        print("Error: generated plan is invalid:", file=sys.stderr)
        for e in errs:
            print(f"  {e}", file=sys.stderr)
        return 1

    # Persist plan for diff/debugging
    plans_dir = data_dir / "feature_plans"
    plans_dir.mkdir(parents=True, exist_ok=True)
    plan_path = plans_dir / f"features-{plan.plan_id}.json"
    plan.to_json(plan_path)

    print(f"Plan created: {plan_path}")
    print(plan.get_summary())

    if plan.is_empty():
        print("No changes needed.")
        return 0

    success, errors = applier.apply(plan, require_approval=approve_features)
    if not success:
        print("[FAIL] Feature apply failed:", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1

    # Update state
    for f in enable_feats:
        st.enabled[f.feature_id] = {"last_plan_path": str(plan_path), **restore_snapshot.get(f.feature_id, {})}
    for f in disable_feats:
        st.enabled.pop(f.feature_id, None)

    st.modified_files = sorted({*(st.modified_files or []), str(config_path)})
    st.save(state_path)

    print("[OK] Features applied successfully")
    return 0


