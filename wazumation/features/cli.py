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
from wazumation.features.detector import detect_feature_states


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


def cmd_status(state_path: Path, config_path: Path) -> int:
    st = FeatureState.load(state_path)
    print(f"State file: {state_path}")
    print(f"Last applied (state): {st.last_applied_at or 'never'}")
    print("")
    print("Detected feature state (live config):")
    reg = get_feature_registry()
    detected = detect_feature_states(config_path)
    for fid in sorted(reg.keys()):
        ds = detected.get(fid, {})
        status = ds.get("status", "unknown")
        print(f"  {fid}: {status}")

    if st.modified_files:
        print("")
        print("Files recorded as modified (state):")
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
    values_by_feature: Optional[dict] = None,
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

    # IMPORTANT: Use *live detection* to decide whether changes are needed.
    # The state file is best-effort and can drift (e.g. manual edits, restores, failed restarts).
    detected = detect_feature_states(config_path)

    def _is_live_enabled(fid: str) -> bool:
        return detected.get(fid, {}).get("status") in ("enabled", "partial")

    enable_feats = [reg[x] for x in enable if not _is_live_enabled(x)]
    disable_feats = [reg[x] for x in disable if _is_live_enabled(x)]

    # Capture restore snapshot for features being enabled (best-effort safe revert).
    # For schema-driven features, capture existing values for the relevant keys so disable can restore.
    from wazumation.wazuh.xml_parser import WazuhXMLParser

    parsed = WazuhXMLParser(config_path).parse()
    sections = parsed.get("sections", {})

    def _section_dict(tag: str):
        sec = sections.get(tag)
        if isinstance(sec, dict):
            return sec
        if isinstance(sec, list) and sec and isinstance(sec[0], dict):
            return sec[0]
        return None

    def _get_child_text(sd, key: str) -> Optional[str]:
        if not isinstance(sd, dict):
            return None
        children = sd.get("children") or {}
        v = children.get(key)
        if isinstance(v, dict):
            return v.get("text")
        if isinstance(v, str):
            return v
        if isinstance(v, list):
            # join list children into comma string
            parts = []
            for it in v:
                if isinstance(it, dict) and "text" in it and it["text"]:
                    parts.append(str(it["text"]))
            return ",".join(parts) if parts else None
        return None

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
                restore.setdefault("__remove_localfile__", []).append(
                    {"instance": action["ensure_instance"], "marker": f.feature_id}
                )
            elif "desired_from_values" in action:
                sd = _section_dict(section)
                desired_restore = {}
                for ossec_key in (action.get("desired_from_values") or {}).keys():
                    prev = _get_child_text(sd, ossec_key)
                    desired_restore[ossec_key] = prev if prev is not None else None
                restore[section] = desired_restore
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
        is_manager_fn=None,
        values_by_feature=values_by_feature,
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
        # Still sync the state file to the user's requested toggles to avoid future drift.
        for fid in enable:
            if fid in reg:
                st.enabled.setdefault(fid, {})
        for fid in disable:
            st.enabled.pop(fid, None)
        st.modified_files = sorted({*(st.modified_files or []), str(config_path)})
        st.save(state_path)
        return 0

    # Honor dry-run regardless of how the applier was constructed (GUI may reuse a non-dry-run applier).
    orig_dry_run = getattr(applier, "dry_run", False)
    try:
        applier.dry_run = bool(dry_run)
        success, errors = applier.apply(plan, require_approval=approve_features)
    finally:
        applier.dry_run = orig_dry_run
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


