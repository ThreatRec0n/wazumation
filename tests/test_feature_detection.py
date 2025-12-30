"""Tests for live feature detection logic."""

import json
import tempfile
import unittest
from pathlib import Path

from wazumation.features.detector import detect_feature_states


class TestFeatureDetection(unittest.TestCase):
    def test_detect_fim_partial_and_enabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "ossec.conf"
            p.write_text(
                """<?xml version="1.0"?>
<ossec_config>
  <syscheck>
    <scan_on_start>yes</scan_on_start>
  </syscheck>
</ossec_config>
""",
                encoding="utf-8",
            )
            st = detect_feature_states(p)
            self.assertEqual(st["fim-enhanced"]["status"], "partial")

            p.write_text(
                """<?xml version="1.0"?>
<ossec_config>
  <syscheck>
    <scan_on_start>yes</scan_on_start>
    <whodata>yes</whodata>
  </syscheck>
</ossec_config>
""",
                encoding="utf-8",
            )
            st = detect_feature_states(p)
            self.assertEqual(st["fim-enhanced"]["status"], "enabled")


if __name__ == "__main__":
    unittest.main()


