"""Tests for feature-mode CLI flags (cross-platform safe subset)."""

import subprocess
import sys
import unittest


class TestFeatureModeCLI(unittest.TestCase):
    def test_list_features_flag(self):
        result = subprocess.run(
            [sys.executable, "-m", "wazumation.cli.main", "--list"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("fim-enhanced", result.stdout)


if __name__ == "__main__":
    unittest.main()


