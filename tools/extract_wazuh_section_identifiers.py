"""
Extract canonical ossec.conf section identifiers from official Wazuh docs pages.

Why:
  Wazuh docs URLs ("slug") do not always equal the actual XML tag name.
  Example: docs page slug might be "github-module" but the XML tag may be "<github>".
  For Wodle modules, the actual config is typically "<wodle name=\"...\">", not "<wodle-...>".

This script fetches each section page listed in data/wazuh_sections.json and attempts to
extract the canonical identifier from XML code blocks:
  - For normal sections: the first child tag under <ossec_config>
  - For wodle: "<wodle name=\"...\">" extracted from the example snippet

Outputs a JSON mapping to stdout.
"""

from __future__ import annotations

import html as html_stdlib
import json
import re
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from lxml import etree, html


SECTIONS_PATH = Path("data") / "wazuh_sections.json"


def _fetch(url: str, timeout: int = 30) -> str:
    last: Optional[Exception] = None
    for attempt in range(1, 6):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "wazumation-extract/1.0 (+https://github.com/)",
                    "Accept": "text/html",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                charset = resp.headers.get_content_charset() or "utf-8"
                return resp.read().decode(charset, errors="replace")
        except Exception as e:
            last = e
            time.sleep(min(2 ** (attempt - 1), 8))
    raise last  # type: ignore[misc]


def _iter_code_blocks(doc: html.HtmlElement) -> List[str]:
    blocks: List[str] = []
    # Prefer <pre><code> blocks
    for code in doc.xpath("//pre//code"):
        txt = "".join(code.itertext())
        txt = html_stdlib.unescape(txt)
        txt = txt.replace("\r\n", "\n")
        if "<" in txt and ">" in txt:
            blocks.append(txt)
    # Fallback: <code> blocks
    if not blocks:
        for code in doc.xpath("//code"):
            txt = "".join(code.itertext())
            txt = html_stdlib.unescape(txt)
            txt = txt.replace("\r\n", "\n")
            if "<" in txt and ">" in txt:
                blocks.append(txt)
    return blocks


def _extract_from_xml_block(block: str) -> Optional[Tuple[str, Optional[str]]]:
    """
    Returns:
      (section_tag, wodle_name?) where wodle_name is set only if section_tag == "wodle"
    """
    # Find a <wodle name="..."> example first (more specific)
    m = re.search(r"<wodle\\s+[^>]*name\\s*=\\s*\"([^\"]+)\"[^>]*>", block, re.IGNORECASE)
    if m:
        return "wodle", m.group(1)

    # Otherwise, parse an <ossec_config> snippet and get its first direct child tag.
    if "<ossec_config" not in block:
        return None
    start = block.find("<ossec_config")
    end = block.rfind("</ossec_config>")
    if start == -1 or end == -1:
        return None
    snippet = block[start : end + len("</ossec_config>")]

    try:
        root = etree.fromstring(snippet.encode("utf-8", errors="ignore"))
    except Exception:
        return None
    if root.tag != "ossec_config":
        return None
    for child in list(root):
        # first element child
        if isinstance(child.tag, str):
            return child.tag, None
    return None


def extract_identifiers(url: str) -> Dict[str, Any]:
    html_text = _fetch(url)
    doc = html.fromstring(html_text)
    for block in _iter_code_blocks(doc):
        found = _extract_from_xml_block(block)
        if found:
            tag, wodle_name = found
            return {"section_tag": tag, "wodle_name": wodle_name}
    return {"section_tag": None, "wodle_name": None}


def main(argv: List[str]) -> int:
    sections = json.loads(SECTIONS_PATH.read_text(encoding="utf-8"))
    out: Dict[str, Any] = {}
    failures = 0
    for s in sections:
        slug = s["section_name"]
        url = s["source_url"]
        info = extract_identifiers(url)
        out[slug] = {"source_url": url, **info}
        if info["section_tag"] is None:
            failures += 1
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if failures == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))


