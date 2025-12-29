"""Tests for robust parsing of ossec.conf with extra content or multiple roots."""

import tempfile
import unittest
from pathlib import Path

from wazumation.wazuh.xml_parser import WazuhXMLParser
from wazumation.wazuh.xml_sanitize import extract_first_ossec_config


class TestXMLSanitize(unittest.TestCase):
    def test_trailing_garbage_after_root_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "ossec.conf"
            p.write_text(
                """<?xml version="1.0"?>
<ossec_config>
  <syscheck>
    <disabled>no</disabled>
  </syscheck>
</ossec_config>
THIS IS NOT XML AND SHOULD BE IGNORED
""",
                encoding="utf-8",
            )

            parser = WazuhXMLParser(p)
            sec = parser.get_section("syscheck")
            self.assertIsNotNone(sec)

    def test_only_first_root_block_is_used(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "ossec.conf"
            p.write_text(
                """<?xml version="1.0"?>
<ossec_config>
  <syscheck>
    <disabled>no</disabled>
  </syscheck>
</ossec_config>
<ossec_config>
  <syscheck>
    <disabled>yes</disabled>
  </syscheck>
</ossec_config>
""",
                encoding="utf-8",
            )

            parser = WazuhXMLParser(p)
            sec = parser.get_section("syscheck")
            # Ensure we used the FIRST block (disabled=no)
            disabled = sec["children"]["disabled"]["text"]
            self.assertEqual(disabled, "no")

    def test_no_root_raises_clear_error(self):
        with self.assertRaises(ValueError) as ctx:
            extract_first_ossec_config("not xml")
        self.assertEqual(str(ctx.exception), "No <ossec_config> root element found")


if __name__ == "__main__":
    unittest.main()


