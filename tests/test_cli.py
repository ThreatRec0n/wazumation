"""CLI tests using unittest."""

import unittest
import tempfile
import json
import subprocess
import sys
from pathlib import Path


class TestCLI(unittest.TestCase):
    """Test CLI commands."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)
        self.config_file = self.temp_path / "ossec.conf"
        self.config_file.write_text(
            """<?xml version="1.0"?>
<ossec_config>
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
  </syscheck>
</ossec_config>"""
        )
        self.data_dir = self.temp_path / "data"
        self.data_dir.mkdir()

    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_read_command(self):
        """Test read command."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "wazumation.cli.main",
                "--config",
                str(self.config_file),
                "--data-dir",
                str(self.data_dir),
                "read",
                "syscheck",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertIn("disabled", output)
        self.assertEqual(output["disabled"], "no")

    def test_plan_command(self):
        """Test plan command."""
        desired_state = {"disabled": "yes", "frequency": "86400"}
        desired_file = self.temp_path / "desired.json"
        desired_file.write_text(json.dumps(desired_state))

        plan_file = self.temp_path / "plan.json"

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "wazumation.cli.main",
                "--config",
                str(self.config_file),
                "--data-dir",
                str(self.data_dir),
                "plan",
                "syscheck",
                "--desired",
                str(desired_file),
                "--output",
                str(plan_file),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertTrue(plan_file.exists())

        # Verify plan JSON is valid
        plan_data = json.loads(plan_file.read_text())
        self.assertIn("plan_id", plan_data)
        self.assertIn("file_changes", plan_data)
        self.assertGreater(len(plan_data["file_changes"]), 0)

    def test_plan_wazuh_db_deprecated_alias(self):
        """`wazuh-db` should warn and route to `wazuh_db`."""
        desired_state = {}
        desired_file = self.temp_path / "desired.json"
        desired_file.write_text(json.dumps(desired_state))
        plan_file = self.temp_path / "plan.json"

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "wazumation.cli.main",
                "--config",
                str(self.config_file),
                "--data-dir",
                str(self.data_dir),
                "plan",
                "wazuh-db",
                "--desired",
                str(desired_file),
                "--output",
                str(plan_file),
            ],
            capture_output=True,
            text=True,
        )
        # Plan may be empty or non-empty depending on whether section already exists; either is valid.
        self.assertIn(result.returncode, (0,), msg=result.stderr)
        self.assertIn("deprecated", result.stderr.lower())
        self.assertTrue(plan_file.exists())

    def test_diff_command(self):
        """Test diff command."""
        # Create a plan first
        desired_state = {"disabled": "yes"}
        desired_file = self.temp_path / "desired.json"
        desired_file.write_text(json.dumps(desired_state))

        plan_file = self.temp_path / "plan.json"

        subprocess.run(
            [
                sys.executable,
                "-m",
                "wazumation.cli.main",
                "--config",
                str(self.config_file),
                "--data-dir",
                str(self.data_dir),
                "plan",
                "syscheck",
                "--desired",
                str(desired_file),
                "--output",
                str(plan_file),
            ],
            capture_output=True,
        )

        # Test diff
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "wazumation.cli.main",
                "--data-dir",
                str(self.data_dir),
                "diff",
                str(plan_file),
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("syscheck", result.stdout.lower())

    def test_apply_dry_run(self):
        """Test apply command in dry-run mode."""
        # Create a plan
        desired_state = {"disabled": "yes"}
        desired_file = self.temp_path / "desired.json"
        desired_file.write_text(json.dumps(desired_state))

        plan_file = self.temp_path / "plan.json"

        subprocess.run(
            [
                sys.executable,
                "-m",
                "wazumation.cli.main",
                "--config",
                str(self.config_file),
                "--data-dir",
                str(self.data_dir),
                "plan",
                "syscheck",
                "--desired",
                str(desired_file),
                "--output",
                str(plan_file),
            ],
            capture_output=True,
        )

        # Test apply with dry-run
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "wazumation.cli.main",
                "--config",
                str(self.config_file),
                "--data-dir",
                str(self.data_dir),
                "--dry-run",
                "apply",
                str(plan_file),
                "--approve",
            ],
            capture_output=True,
            text=True,
        )
        # Should succeed in dry-run mode
        self.assertEqual(result.returncode, 0)

    def test_verify_command(self):
        """Test verify command."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "wazumation.cli.main",
                "--data-dir",
                str(self.data_dir),
                "verify",
            ],
            capture_output=True,
            text=True,
        )
        # Should succeed with empty chain
        self.assertEqual(result.returncode, 0)
        self.assertIn("verified", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()


