from __future__ import annotations

from pathlib import Path

from lxml import etree

from wazumation.core.validator import ConfigValidator
from wazumation.core.xml_healer import XMLHealer


def test_xml_healer_removes_bom_nul_and_trailing_garbage(tmp_path: Path):
    cfg = tmp_path / "ossec.conf"
    # UTF-8 BOM + valid XML + garbage after closing + NULs
    raw = (
        b"\xef\xbb\xbf"
        b'<?xml version="1.0"?>\n'
        b"<ossec_config>\n"
        b"  <syscheck>\n"
        b"    <disabled>no</disabled>\n"
        b"  </syscheck>\n"
        b"</ossec_config>\n"
        b"\x00\x00GARBAGE_AFTER_CLOSE\x00"
    )
    cfg.write_bytes(raw)

    validator = ConfigValidator(wazuh_manager_path=tmp_path)  # no wazuh-control; lxml gate only
    res = XMLHealer(cfg, validator=validator).heal()

    assert res.ok, "\n".join(res.fixes)
    text = cfg.read_text(encoding="utf-8", errors="strict")
    assert "GARBAGE_AFTER_CLOSE" not in text
    assert "\x00" not in text
    # Validate parse is clean
    etree.parse(str(cfg), etree.XMLParser(remove_blank_text=True))


