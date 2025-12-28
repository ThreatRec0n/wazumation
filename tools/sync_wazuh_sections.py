"""
Sync authoritative ossec.conf section list from official Wazuh documentation.

Source of truth:
  Wazuh docs: Local configuration (ossec.conf) - Reference (index)

This script fetches the ossec.conf reference index, discovers all section pages,
then fetches each page and uses its <h1> title as the canonical identifier.

Important:
  - Wazuh docs slugs do not always match the canonical section name.
    Example: docs page `commands.html` has H1 `command`.
  - Wodle modules are represented as `wodle name="..."` in H1, and are not flat sections.

It writes:
  data/wazuh_sections.json

Notes:
  - This script requires internet access.
  - The generated JSON is committed so builds/tests do not require internet.
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import List, Set, Optional, Dict, Any


INDEX_URL = "https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html"
BASE_PREFIX = "https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/"


@dataclass(frozen=True)
class SectionInfo:
    identifier: str
    section_tag: str
    wodle_name: Optional[str]
    supported_installations: List[str]
    source_url: str


def _fetch(url: str, timeout: int = 30) -> str:
    last_exc: Optional[Exception] = None
    for attempt in range(1, 6):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "wazumation-sync/1.0 (+https://github.com/)",
                    "Accept": "text/html",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                charset = resp.headers.get_content_charset() or "utf-8"
                return resp.read().decode(charset, errors="replace")
        except Exception as e:
            last_exc = e
            time.sleep(min(2 ** (attempt - 1), 8))
    raise last_exc  # type: ignore[misc]


def _extract_section_slugs(index_html: str) -> Set[str]:
    # Grab any link that points to the ossec-conf reference subtree.
    # We intentionally avoid depending on a specific site HTML structure.
    slugs: Set[str] = set()
    for m in re.finditer(r'href="([^"]+)"', index_html):
        href = m.group(1)
        abs_url = urllib.parse.urljoin(INDEX_URL, href)
        if not abs_url.startswith(BASE_PREFIX):
            continue
        if not abs_url.endswith(".html"):
            continue
        last = abs_url.rsplit("/", 1)[-1]
        if last in {"index.html"}:
            continue
        slug = last[:-5]  # strip .html
        # Filter out helper pages that aren't configuration sections
        if slug in {"verifying-configuration"}:
            continue
        slugs.add(slug)
    return slugs


def _extract_identifier_and_tag(page_html: str, url: str) -> Dict[str, Any]:
    """
    Use the page's H1 title as the canonical identifier (doc-truth).
    """
    try:
        from lxml import html as lxml_html
    except Exception as e:
        raise RuntimeError("lxml is required to parse Wazuh docs HTML") from e

    doc = lxml_html.fromstring(page_html)
    h1 = doc.xpath("//h1/text()")
    if not h1 or not h1[0].strip():
        raise RuntimeError(f"Missing H1 section title on {url}")
    ident = h1[0].strip()

    m = re.fullmatch(r'wodle\s+name="([^"]+)"', ident)
    if m:
        return {"identifier": ident, "section_tag": "wodle", "wodle_name": m.group(1)}

    # Normalize known doc title inconsistencies to canonical ossec.conf tag naming.
    # Wazuh DB section is <wazuh_db> in ossec.conf, but some docs titles may show "wazuh-db".
    if ident == "wazuh-db":
        return {"identifier": "wazuh_db", "section_tag": "wazuh_db", "wodle_name": None}

    return {"identifier": ident, "section_tag": ident, "wodle_name": None}


def sync(output_path: Path) -> List[SectionInfo]:
    index_html = _fetch(INDEX_URL)
    slugs = sorted(_extract_section_slugs(index_html))
    if not slugs:
        raise RuntimeError("No section slugs found. Wazuh docs structure may have changed.")

    sections: List[SectionInfo] = []
    for slug in slugs:
        url = urllib.parse.urljoin(BASE_PREFIX, f"{slug}.html")
        page_html = _fetch(url)
        # Applicability is not consistently machine-readable across the index pages;
        # store a safe default and focus list-plugins on authoritative identifiers.
        supported = ["manager", "agent"]
        extracted = _extract_identifier_and_tag(page_html, url)
        sections.append(
            SectionInfo(
                identifier=extracted["identifier"],
                section_tag=extracted["section_tag"],
                wodle_name=extracted["wodle_name"],
                supported_installations=supported,
                source_url=url,
            )
        )

    # Stable output
    sections.sort(key=lambda s: s.identifier)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(
            [
                {
                    "identifier": s.identifier,
                    "section_tag": s.section_tag,
                    "wodle_name": s.wodle_name,
                    "supported_installations": s.supported_installations,
                    "source_url": s.source_url,
                }
                for s in sections
            ],
            f,
            indent=2,
            sort_keys=True,
        )
        f.write("\n")
    return sections


def main(argv: List[str]) -> int:
    out = Path("data") / "wazuh_sections.json"
    try:
        sections = sync(out)
    except Exception as e:
        print(f"[FAIL] sync_wazuh_sections: {e}", file=sys.stderr)
        return 1

    print(f"[OK] Wrote {len(sections)} sections to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))


