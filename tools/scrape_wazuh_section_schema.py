"""
Scrape per-section configuration option metadata from official Wazuh ossec.conf docs.

This scraper is intentionally conservative:
  - It extracts option names, types/allowed values/defaults when presented in tables.
  - If a section page doesn't present machine-readable option metadata, we fail rather
    than guessing.

Outputs:
  data/wazuh_section_schemas.json
  data/wazuh_section_metadata.json

Requires:
  - Internet access
  - lxml (already a project dependency)
"""

from __future__ import annotations

import json
import re
import sys
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from lxml import html


SECTIONS_PATH = Path("data") / "wazuh_sections.json"


def _fetch(url: str, timeout: int = 30) -> str:
    last_exc: Optional[Exception] = None
    for attempt in range(1, 6):
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "wazumation-scrape/1.0 (+https://github.com/)",
                    "Accept": "text/html",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                charset = resp.headers.get_content_charset() or "utf-8"
                return resp.read().decode(charset, errors="replace")
        except Exception as e:
            last_exc = e
            # simple exponential backoff
            time.sleep(min(2 ** (attempt - 1), 8))
            continue
    raise last_exc  # type: ignore[misc]


def _normalize_text(s: str) -> str:
    return re.sub(r"\\s+", " ", (s or "").strip())


def _detect_restart_guidance(page_text_lower: str) -> Optional[str]:
    # We do not infer "restart required"; we capture the doc hint textually.
    # If any restart/reload phrases exist, we store that as guidance.
    if "restart" in page_text_lower or "reload" in page_text_lower:
        # Return a short snippet for traceability.
        m = re.search(r"(.{0,80}(restart|reload).{0,80})", page_text_lower)
        if m:
            return _normalize_text(m.group(1))
        return "restart/reload mentioned"
    return None


def _guess_type_from_allowed(allowed: str) -> Tuple[str, Optional[List[str]]]:
    """
    Conservative typing:
      - If allowed looks like yes/no -> enum string
      - If allowed is comma-separated words -> enum string
      - Else -> string
    """
    a = _normalize_text(allowed)
    if not a:
        return "string", None
    a_lower = a.lower()
    if a_lower in {"yes/no", "yes / no", "yes, no", "yes or no"}:
        return "string", ["yes", "no"]
    # Extract enums from patterns like: "one of: a, b, c"
    if "," in a and len(a) < 120:
        parts = [p.strip() for p in a.split(",") if p.strip()]
        if 2 <= len(parts) <= 20 and all(re.fullmatch(r"[A-Za-z0-9._-]+", p) for p in parts):
            return "string", parts
    return "string", None


def _table_to_option_rows(table) -> List[Dict[str, str]]:
    # Extract headers
    headers = [_normalize_text("".join(th.itertext())) for th in table.xpath(".//thead//th")]
    if not headers:
        headers = [_normalize_text("".join(th.itertext())) for th in table.xpath(".//tr[1]//th")]
    headers_lower = [h.lower() for h in headers]

    rows = []
    for tr in table.xpath(".//tbody//tr") or table.xpath(".//tr[position()>1]"):
        cells = tr.xpath("./td")
        if not cells:
            continue
        values = [_normalize_text("".join(td.itertext())) for td in cells]
        row = {}
        for i, v in enumerate(values):
            if i < len(headers_lower) and headers_lower[i]:
                row[headers_lower[i]] = v
        if row:
            rows.append(row)
    return rows


def scrape_section_schema(section_name: str, url: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    html_text = _fetch(url)
    doc = html.fromstring(html_text)

    full_text = _normalize_text(" ".join(doc.xpath("//text()")))
    full_text_lower = full_text.lower()

    # Most Wazuh reference pages use <section id="option_name"> wrapping an <h2>/<h3>
    # and a small option metadata table (Description / Default value / Allowed values).
    # Each option is represented by a <section id="..."> wrapper with a heading whose
    # visible text is the option name (often using underscores even if the anchor id uses hyphens).
    option_blocks: List[Tuple[str, str, Any]] = []  # (option_name, anchor_id, table)
    for sec in doc.xpath("//section[@id]"):
        opt_id = (sec.get("id") or "").strip()
        if not opt_id:
            continue
        if opt_id in {"index", "reference", "configuration", "examples"}:
            continue
        # Allow common option-id characters used by Wazuh docs anchors (e.g., alert-new-files)
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", opt_id):
            continue

        # Determine canonical option name from heading text.
        h = sec.xpath(".//h2[1] | .//h3[1]")
        option_name = ""
        if h:
            # Prefer only direct text nodes to avoid including the link glyph/title.
            option_name = _normalize_text("".join(h[0].xpath("./text()")))
            if not option_name:
                option_name = _normalize_text("".join(h[0].itertext()))
        option_name = option_name.strip()
        if not option_name:
            option_name = opt_id

        # Skip the section's own wrapper heading (e.g., <section id="syscheck"><h2>syscheck</h2>...)
        if option_name.lower() == section_name.lower() and opt_id.lower() == section_name.lower():
            continue

        # Option name must be a valid Wazuh XML tag name. In the reference pages,
        # these are consistently lowercase (and often underscores).
        # If it's not, skip it rather than guessing.
        if not re.fullmatch(r"[a-z_][a-z0-9._-]*", option_name):
            continue

        table = sec.xpath(".//table[1]")
        if not table:
            continue
        option_blocks.append((option_name, opt_id, table[0]))

    if not option_blocks:
        raise RuntimeError(
            f"{section_name}: could not find option headings with following tables on {url}"
        )

    # Build a conservative JSON schema: flat key/value object (option -> string/enum).
    properties: Dict[str, Any] = {}
    required: List[str] = []
    for opt_name, opt_id, table in option_blocks:
        # Many per-option tables are 2 columns: Field | Value.
        kv: Dict[str, str] = {}
        for tr in table.xpath(".//tr"):
            tds = tr.xpath("./td")
            if len(tds) < 2:
                continue
            k = _normalize_text("".join(tds[0].itertext())).lower()
            v = _normalize_text("".join(tds[1].itertext()))
            if k and v:
                kv[k] = v

        allowed = (
            kv.get("allowed values")
            or kv.get("allowed")
            or kv.get("values")
            or kv.get("value")
            or ""
        )
        default = kv.get("default value") or kv.get("default") or ""
        desc = kv.get("description") or kv.get("meaning") or ""

        typ, enum = _guess_type_from_allowed(allowed)
        prop: Dict[str, Any] = {"type": typ}
        if enum:
            prop["enum"] = enum
        if default:
            prop["default"] = default
        if desc:
            prop["description"] = desc

        # Use canonical option name as the desired_state key (matches docs heading / XML tag naming).
        properties[opt_name] = prop

    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
        "required": required,
    }

    metadata = {
        "section_name": section_name,
        "source_url": url,
        "restart_guidance": _detect_restart_guidance(full_text_lower),
    }

    return schema, metadata


def main(argv: List[str]) -> int:
    if not SECTIONS_PATH.exists():
        print(f"[FAIL] Missing {SECTIONS_PATH}. Run tools/sync_wazuh_sections.py first.", file=sys.stderr)
        return 1

    sections = json.loads(SECTIONS_PATH.read_text(encoding="utf-8"))
    schemas: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}

    failures: List[str] = []
    for s in sections:
        name = s["identifier"]
        url = s["source_url"]
        try:
            schema, meta = scrape_section_schema(name, url)
        except Exception as e:
            failures.append(f"{name}: {e}")
            continue
        schemas[name] = schema
        metadata[name] = meta

    (Path("data") / "wazuh_section_schemas.json").write_text(
        json.dumps(schemas, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (Path("data") / "wazuh_section_metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    if failures:
        print("[FAIL] Some sections could not be scraped safely (no guess):", file=sys.stderr)
        for f in failures[:30]:
            print(f"  - {f}", file=sys.stderr)
        print(f"[FAIL] Total failures: {len(failures)}", file=sys.stderr)
        return 2

    print(f"[OK] Scraped schemas for {len(schemas)} sections")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))


