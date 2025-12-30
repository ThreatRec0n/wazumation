"""Self test: prove Wazumation is synced with live Wazuh config and can safely apply/revert."""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from lxml import etree

from wazumation.core.change_plan import ChangePlan, ChangeType, FileChange
from wazumation.features.detector import detect_feature_states
from wazumation.features.planner import _is_wazuh_manager, build_feature_plan


def _semantic_hash_ossec_config(config_path: Path) -> str:
    """Canonical-ish hash of the first ossec_config block, ignoring formatting and comments."""
    raw = config_path.read_text(encoding="utf-8", errors="replace")
    # Reuse sanitizer via parser import path (no direct lxml parsing of full file here).
    from wazumation.wazuh.xml_sanitize import extract_first_ossec_config

    xml_text = extract_first_ossec_config(raw)
    parser = etree.XMLParser(remove_blank_text=True, remove_comments=True, remove_pis=True)
    root = etree.fromstring(xml_text.encode("utf-8"), parser=parser)
    c14n = etree.tostring(root, method="c14n")  # bytes
    return hashlib.sha256(c14n).hexdigest()


@dataclass
class SelfTestResult:
    passed: bool
    summary: str
    details: List[str] = field(default_factory=list)

    def render(self) -> str:
        lines = [self.summary]
        if self.details:
            lines.append("")
            lines.extend(self.details)
        return "\n".join(lines)


def run_self_test(
    *,
    config_path: Path,
    data_dir: Path,
    applier,
    validator,
    is_manager_fn: Optional[Callable[[Path], Tuple[bool, str]]] = None,
    detector_fn: Callable[[Path], Dict[str, Dict[str, Any]]] = detect_feature_states,
) -> SelfTestResult:
    """
    Fully automated self test:
      - Preflight checks
      - Probe apply/detect/revert (safe localfile probe, no restart)
      - Sandbox invalid-XML validation gate
    """
    details: List[str] = []

    def fail(msg: str) -> SelfTestResult:
        return SelfTestResult(passed=False, summary="FAIL: Tool not synced", details=details + [msg])

    def ok(msg: str) -> None:
        details.append(f"[OK] {msg}")

    # A) Preflight
    is_manager_fn = is_manager_fn or _is_wazuh_manager
    is_mgr, reason = is_manager_fn(config_path)
    if not is_mgr:
        return fail(f"Preflight: not a Wazuh manager node: {reason}")

    if not config_path.exists():
        return fail(f"Preflight: ossec.conf not found: {config_path}")

    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "backups").mkdir(parents=True, exist_ok=True)
    (data_dir / "feature_plans").mkdir(parents=True, exist_ok=True)

    valid, errors = validator.validate_ossec_conf(config_path)
    if not valid:
        return fail("Preflight: ossec.conf validation failed: " + "; ".join(errors))
    ok("ossec.conf validates before test")

    # Privilege check (fully automated: no prompts).
    # Note: current applier writes files directly (no sudo wrapper), so the config must be writable.
    if not os.access(config_path, os.W_OK):
        return fail(f"Preflight: insufficient privileges to modify {config_path}. Re-run as root.")
    ok("privilege check passed (config is writable)")

    # Probe definition (safe): add a unique localfile instance with marker comment.
    probe_feature_id = "selftest-probe"
    probe_instance = {"log_format": "syslog", "location": "/var/ossec/logs/wazumation-selftest.log"}

    # Baseline snapshot
    baseline_sem_hash = _semantic_hash_ossec_config(config_path)
    baseline_detect = detector_fn(config_path)
    ok("baseline parsed and detection map produced")
    if baseline_detect.get("selftest-probe", {}).get("status") == "enabled":
        return fail(
            "Preflight: selftest probe appears to already be present in live config "
            "(selftest-probe detected). Remove it first or use a clean config."
        )

    # Apply probe via same plan+applier path as enable.
    enable_actions = [
        {
            "feature_id": probe_feature_id,
            "actions": [
                {
                    "section": "localfile",
                    "ensure_instance": probe_instance,
                }
            ],
        }
    ]

    disable_snapshot = {
        probe_feature_id: {"restore": {"__remove_localfile__": [probe_instance]}},
    }

    # Build and apply enable plan (no service restart for self test)
    result_enable = build_feature_plan(
        config_path=config_path,
        data_dir=data_dir,
        enable_features=enable_actions,
        disable_features=[],
        state_snapshot=disable_snapshot,
        prompt_fn=None,
        is_manager_fn=is_manager_fn,
    )
    plan_enable = result_enable.plan
    # Remove any service restart for self test safety.
    plan_enable.service_changes = []
    plan_enable.requires_sudo = False

    plan_ok, plan_errs = validator.validate_plan(plan_enable)
    if not plan_ok:
        return fail("Probe: generated enable plan invalid: " + "; ".join(plan_errs))

    success, apply_errs = applier.apply(plan_enable, require_approval=False)
    if not success:
        return fail("Probe: failed to apply enable plan: " + "; ".join(apply_errs))
    ok("probe applied")

    # Confirm detection sees the probe
    after_enable_hash = _semantic_hash_ossec_config(config_path)
    if after_enable_hash == baseline_sem_hash:
        return fail("Probe: semantic hash did not change after applying probe")
    after_enable_detect = detector_fn(config_path)
    if after_enable_detect.get("selftest-probe", {}).get("status") != "enabled":
        return fail("Probe: detection did not observe probe localfile instance after apply")
    ok("probe detected after apply")

    # Revert probe via same path as disable.
    result_disable = build_feature_plan(
        config_path=config_path,
        data_dir=data_dir,
        enable_features=[],
        disable_features=[{"feature_id": probe_feature_id, "actions": []}],
        state_snapshot=disable_snapshot,
        prompt_fn=None,
        is_manager_fn=is_manager_fn,
    )
    plan_disable = result_disable.plan
    plan_disable.service_changes = []
    plan_disable.requires_sudo = False

    plan_ok, plan_errs = validator.validate_plan(plan_disable)
    if not plan_ok:
        return fail("Probe: generated disable plan invalid: " + "; ".join(plan_errs))

    success, apply_errs = applier.apply(plan_disable, require_approval=False)
    if not success:
        return fail("Probe: failed to apply disable plan: " + "; ".join(apply_errs))
    ok("probe reverted")

    final_hash = _semantic_hash_ossec_config(config_path)
    if final_hash != baseline_sem_hash:
        return fail("Return-to-baseline: semantic hash does not match baseline after revert")
    final_detect = detector_fn(config_path)
    if final_detect.get("selftest-probe", {}).get("status") != "disabled":
        return fail("Return-to-baseline: probe still detected after revert")
    ok("returned to baseline and detection matches")

    # Validate Wazuh configuration using wazuh-control -t (must pass; no restart attempted on failure).
    valid2, errors2 = validator.validate_ossec_conf(config_path)
    if not valid2:
        return fail("Service health: " + "; ".join(errors2))
    ok("wazuh-control -t validation passed")

    # Confirm backups exist (at least one for ossec.conf) if not dry-run.
    backups = list((data_dir / "backups").glob("ossec.conf.*.bak"))
    if backups:
        ok("backup file(s) exist")
    else:
        # On some runs, config_path name may not be ossec.conf; don't fail, but note.
        details.append("[WARN] No ossec.conf backup found in data-dir backups (this may be expected if config filename differs).")

    # C) Rollback simulation (sandbox): invalid XML must be rejected by validator.validate_plan
    with tempfile.TemporaryDirectory() as tmpdir:
        bad_path = Path(tmpdir) / "ossec.conf"
        bad_path.write_text("<ossec_config><syscheck></ossec_config>", encoding="utf-8")
        bad_plan = ChangePlan(
            plan_id="selftestbad",
            created_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            description="selftest invalid xml plan",
        )
        bad_plan.add_file_change(
            FileChange(
                path=str(bad_path),
                change_type=ChangeType.UPDATE,
                old_content="",
                new_content="<ossec_config><syscheck></ossec_config>",
            )
        )
        ok2, errs2 = validator.validate_plan(bad_plan)
        if ok2:
            return fail("Sandbox: validator.validate_plan unexpectedly accepted invalid XML")
        ok("sandbox invalid XML correctly rejected")

    return SelfTestResult(passed=True, summary="PASS: Tool synced", details=details)


