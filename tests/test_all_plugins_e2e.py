"""End-to-end CLI tests for every doc-listed ossec.conf section plugin (unittest, no pytest)."""

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def _load_sections():
    return json.loads(Path("data/wazuh_sections.json").read_text(encoding="utf-8"))


def _load_schemas():
    return json.loads(Path("data/wazuh_section_schemas.json").read_text(encoding="utf-8"))


def _pick_desired(schema: dict) -> dict:
    props = (schema or {}).get("properties") or {}
    # If no documented options, return empty desired state (real behavior: no changes).
    if not props:
        return {}
    k = sorted(props.keys())[0]
    spec = props[k] or {}
    if "enum" in spec and spec["enum"]:
        v = spec["enum"][0]
    elif "default" in spec and spec["default"]:
        v = spec["default"]
    else:
        v = "1"
    # Desired state values are strings by design in our doc-driven schema.
    return {k: str(v)}


class TestAllPluginsE2E(unittest.TestCase):
    def test_list_plugins_matches_doc_index(self):
        sections = _load_sections()
        expected = [s["identifier"] for s in sections]

        result = subprocess.run(
            [sys.executable, "-m", "wazumation.cli.main", "list-plugins", "--data-dir", ".wazumation_test"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        got = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        self.assertEqual(got, expected)

    def test_plan_diff_apply_dry_run_for_every_section(self):
        sections = _load_sections()
        schemas = _load_schemas()

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            data_dir = tmp / "data"
            data_dir.mkdir()

            for s in sections:
                identifier = s["identifier"]
                schema = schemas.get(identifier, {})
                desired = _pick_desired(schema)

                config_path = tmp / f"ossec-{re.sub(r'[^A-Za-z0-9_-]+','_',identifier)}.conf"
                # Minimal well-formed XML with a single empty section.
                if identifier.startswith('wodle name="') and identifier.endswith('"'):
                    name = identifier[len('wodle name="'):-1]
                    section_xml = f'<wodle name="{name}"/>'
                else:
                    section_xml = f"<{identifier}/>"
                config_path.write_text(
                    f"""<?xml version="1.0"?>
<ossec_config>
  {section_xml}
</ossec_config>
""",
                    encoding="utf-8",
                )
                before = config_path.read_text(encoding="utf-8")

                desired_path = tmp / f"desired-{re.sub(r'[^A-Za-z0-9_-]+','_',identifier)}.json"
                desired_path.write_text(json.dumps(desired), encoding="utf-8")

                plan_path = tmp / f"plan-{re.sub(r'[^A-Za-z0-9_-]+','_',identifier)}.json"

                # plan
                plan_res = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "wazumation.cli.main",
                        "plan",
                        identifier,
                        "--config",
                        str(config_path),
                        "--desired",
                        str(desired_path),
                        "--output",
                        str(plan_path),
                        "--data-dir",
                        str(data_dir),
                    ],
                    capture_output=True,
                    text=True,
                )
                self.assertIn(plan_res.returncode, (0,), msg=plan_res.stderr)
                self.assertTrue(plan_path.exists(), msg=f"{identifier}: plan file not created")

                # diff
                diff_res = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "wazumation.cli.main",
                        "diff",
                        str(plan_path),
                        "--data-dir",
                        str(data_dir),
                    ],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(diff_res.returncode, 0, msg=diff_res.stderr)
                self.assertIn("=== Change Plan:", diff_res.stdout)

                # apply (dry-run)
                apply_res = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "wazumation.cli.main",
                        "--dry-run",
                        "apply",
                        str(plan_path),
                        "--approve",
                        "--config",
                        str(config_path),
                        "--data-dir",
                        str(data_dir),
                    ],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(apply_res.returncode, 0, msg=apply_res.stderr)
                self.assertIn("[OK]", apply_res.stdout)
                after = config_path.read_text(encoding="utf-8")
                self.assertEqual(before, after, msg=f"{identifier}: dry-run modified config")

            # verify
            verify_res = subprocess.run(
                [sys.executable, "-m", "wazumation.cli.main", "verify", "--data-dir", str(data_dir)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(verify_res.returncode, 0, msg=verify_res.stderr)
            self.assertIn("[OK]", verify_res.stdout)


if __name__ == "__main__":
    unittest.main()


