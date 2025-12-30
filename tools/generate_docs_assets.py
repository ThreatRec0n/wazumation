"""Generate docs/assets screenshots from real tool runs against safe local fixtures.

This does NOT touch real Wazuh system paths; it creates a temporary fixture ossec.conf,
runs the relevant commands/functions, and writes SVG "screenshots" and the raw output
text under docs/assets/.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from wazumation.core.audit import AuditChain, AuditLogger  # noqa: E402
from wazumation.core.backup import BackupManager  # noqa: E402
from wazumation.core.applier import PlanApplier  # noqa: E402
from wazumation.core.validator import ConfigValidator  # noqa: E402
from wazumation.features.self_test import run_self_test  # noqa: E402
from wazumation.features.planner import build_feature_plan  # noqa: E402
from wazumation.features.state import FeatureState  # noqa: E402
from tools.render_text_svg import render_text_to_svg  # noqa: E402


FIXTURE_OSSEC = """<?xml version="1.0"?>
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
  </global>
  <syscheck>
    <disabled>no</disabled>
  </syscheck>
</ossec_config>
"""


def _run_cli(args: list[str], *, env: dict[str, str], cwd: Path) -> str:
    p = subprocess.run(
        [os.environ.get("PYTHON", "python"), "-m", "wazumation.cli.main", *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
    )
    out = (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
    return out.strip() + "\n"


def main() -> None:
    assets = REPO_ROOT / "docs" / "assets"
    assets.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        fixture = tmp / "ossec.conf"
        fixture.write_text(FIXTURE_OSSEC, encoding="utf-8")

        # Isolate state path to temp HOME/USERPROFILE so docgen doesn't touch the user's machine.
        env = dict(os.environ)
        env["HOME"] = str(tmp / "home")
        env["USERPROFILE"] = str(tmp / "home")

        data_dir = tmp / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        # 1) --list
        out_list = _run_cli(["--list"], env=env, cwd=REPO_ROOT)
        (assets / "cli-list.txt").write_text(out_list, encoding="utf-8")
        render_text_to_svg(title="wazumation --list", lines=out_list.splitlines(), out_path=assets / "cli-list.svg")

        # 2) --status (against fixture config)
        out_status = _run_cli(["--status", "--config", str(fixture)], env=env, cwd=REPO_ROOT)
        (assets / "cli-status.txt").write_text(out_status, encoding="utf-8")
        render_text_to_svg(
            title="wazumation --status (fixture ossec.conf)",
            lines=out_status.splitlines(),
            out_path=assets / "cli-status.svg",
        )

        # 3) Self test (fixture run, same engine paths; manager detection bypassed for fixture safety)
        audit_chain = AuditChain(data_dir / "audit.db")
        audit_logger = AuditLogger(audit_chain)
        backup_manager = BackupManager(data_dir / "backups")
        validator = ConfigValidator(wazuh_manager_path=tmp)
        applier = PlanApplier(backup_manager, validator, audit_logger, dry_run=False)
        res = run_self_test(
            config_path=fixture,
            data_dir=data_dir,
            applier=applier,
            validator=validator,
            is_manager_fn=lambda p: (True, ""),
        )
        out_self = res.render() + "\n"
        (assets / "self-test-pass.txt").write_text(out_self, encoding="utf-8")
        render_text_to_svg(
            title="Self Test (fixture run) - PASS",
            lines=out_self.splitlines(),
            out_path=assets / "self-test-pass.svg",
        )

        # 4) Feature diff screenshot (plan diff for enabling localfile-nginx on fixture)
        feature_id = "localfile-nginx"
        enable_actions = [
            {
                "feature_id": feature_id,
                "actions": [
                    {
                        "section": "localfile",
                        "ensure_instance": {"log_format": "apache", "location": "/var/log/nginx/access.log"},
                    }
                ],
            }
        ]
        restore_snapshot = {feature_id: {"restore": {"__remove_localfile__": [{"instance": enable_actions[0]["actions"][0]["ensure_instance"], "marker": feature_id}]}}}
        plan_res = build_feature_plan(
            config_path=fixture,
            data_dir=data_dir,
            enable_features=enable_actions,
            disable_features=[],
            state_snapshot=restore_snapshot,
            prompt_fn=None,
            is_manager_fn=lambda p: (True, ""),
        )
        plan = plan_res.plan
        plans_dir = data_dir / "feature_plans"
        plans_dir.mkdir(parents=True, exist_ok=True)
        plan_path = plans_dir / f"features-{plan.plan_id}.json"
        plan.to_json(plan_path)

        st = FeatureState()
        st.enabled[feature_id] = {"last_plan_path": str(plan_path), **restore_snapshot[feature_id]}
        state_path = Path(env["HOME"]) / ".wazumation" / "state.json"
        st.save(state_path)

        out_diff_feature = _run_cli(
            ["--diff-feature", feature_id, "--config", str(fixture), "--data-dir", str(data_dir)],
            env=env,
            cwd=REPO_ROOT,
        )
        (assets / "cli-diff-feature.txt").write_text(out_diff_feature, encoding="utf-8")
        render_text_to_svg(
            title="wazumation --diff-feature localfile-nginx (plan diff)",
            lines=out_diff_feature.splitlines(),
            out_path=assets / "cli-diff-feature.svg",
            max_width_chars=140,
        )

        # 5) "GUI screenshot": render a lightweight SVG snapshot of feature statuses on the fixture.
        # This is generated from the same live detection results the GUI shows.
        from wazumation.features.detector import detect_feature_states
        from wazumation.features.registry import get_feature_registry

        det = detect_feature_states(fixture)
        reg = get_feature_registry()
        gui_lines = ["Feature Selector (fixture snapshot)", ""]
        for fid in sorted(reg.keys()):
            gui_lines.append(f"{fid:18}  {det.get(fid, {}).get('status', 'unknown')}")
        out_gui = "\n".join(gui_lines) + "\n"
        (assets / "gui-snapshot.txt").write_text(out_gui, encoding="utf-8")
        render_text_to_svg(
            title="GUI feature list snapshot (same detection engine)",
            lines=out_gui.splitlines(),
            out_path=assets / "gui-snapshot.svg",
        )

    print(f"[OK] Wrote docs assets under: {assets}")


if __name__ == "__main__":
    main()


