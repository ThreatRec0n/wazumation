"""Helpers to sanitize Wazuh XML config files before parsing.

Wazuh config files are expected to have a single <ossec_config> root element, but
in practice files may contain trailing garbage or multiple <ossec_config> blocks.
We defensively extract the first complete <ossec_config>...</ossec_config> block
and parse that only.
"""

from __future__ import annotations

import re


_OPEN_RE = re.compile(r"<ossec_config\b[^>]*>", re.IGNORECASE)
_CLOSE = "</ossec_config>"


def extract_first_ossec_config(xml_text: str) -> str:
    """
    Return only the first complete <ossec_config>...</ossec_config> block.

    - If no <ossec_config> start tag is found, raises ValueError with a clear message.
    - If a start tag exists but no closing tag exists after it, raises ValueError.
    - If multiple blocks exist, everything after the first closing tag is ignored.
    """
    if xml_text is None:
        xml_text = ""

    m = _OPEN_RE.search(xml_text)
    if not m:
        raise ValueError("No <ossec_config> root element found")

    start = m.start()
    close_idx = xml_text.find(_CLOSE, m.end())
    if close_idx == -1:
        raise ValueError("No </ossec_config> closing tag found for first <ossec_config> block.")

    end = close_idx + len(_CLOSE)
    return xml_text[start:end]


# Backward-compatible alias (internal).
def extract_first_ossec_config_block(raw_text: str) -> str:
    return extract_first_ossec_config(raw_text)


