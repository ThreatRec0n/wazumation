"""
Text-first Wazuh ossec.conf editor (Ansible-style block edits with markers).

Goal: perform *surgical* modifications while preserving original formatting,
comments, ordering, and encoding as much as possible.

This is used by feature-mode planning to avoid re-serializing the entire XML.
Validation remains separate (xmllint/lxml/wazuh-control via existing validators).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class Marker:
    begin: str
    end: str


class WazuhConfigManager:
    """
    Minimal, production-oriented text patcher for Wazuh ossec.conf.

    Supported operations (sufficient for current feature catalog):
    - Ensure/remove a <localfile> instance (log_format + location), with marker comments.
    - Upsert/remove simple key/value children inside a named section (first instance).
    - Create a missing section near end of <ossec_config>.
    """

    @staticmethod
    def _ossec_config_close_start(text: str) -> int:
        """Return the index of the start of the final </ossec_config> closing tag."""
        close = "</ossec_config>"
        start = text.rfind(close)
        if start == -1:
            raise ValueError("Cannot find </ossec_config> tag")
        return start

    @staticmethod
    def _detect_line_indent(line: str) -> str:
        m = re.match(r"^(\s+)", line)
        return m.group(1) if m else ""

    @classmethod
    def feature_marker(cls, feature_id: str, *, scope: str) -> Marker:
        begin = f"<!-- WAZUMATION {feature_id} BEGIN {scope} -->"
        end = f"<!-- WAZUMATION {feature_id} END {scope} -->"
        return Marker(begin=begin, end=end)

    @staticmethod
    def _normalize_yes_no(v: Any) -> Optional[str]:
        if v is None:
            return None
        s = str(v).strip()
        # Preserve user-provided casing if not a boolean-ish token.
        sl = s.lower()
        if sl in {"true", "1", "on", "enabled"}:
            return "yes"
        if sl in {"false", "0", "off", "disabled"}:
            return "no"
        return s

    @classmethod
    def ensure_localfile_instance(
        cls, content: str, instance: Dict[str, str], *, marker: Optional[str] = None
    ) -> str:
        """
        Ensure a <localfile> block exists with exact (log_format, location).
        This is idempotent and does *not* reformat the file.
        """
        log_format = instance.get("log_format")
        location = instance.get("location")
        if not log_format or not location:
            raise ValueError("localfile instance requires log_format and location")

        # If already present anywhere, do nothing.
        lf_re = re.compile(r"<localfile\b[^>]*>[\s\S]*?</localfile>", re.IGNORECASE)
        for m in lf_re.finditer(content):
            block = m.group(0)
            if re.search(rf"<log_format>\s*{re.escape(log_format)}\s*</log_format>", block, re.IGNORECASE) and re.search(
                rf"<location>\s*{re.escape(location)}\s*</location>", block, re.IGNORECASE
            ):
                return content

        # Insert BEFORE the last </ossec_config> (never after, or XML becomes invalid).
        close_start = cls._ossec_config_close_start(content)
        before = content[:close_start]
        after = content[close_start:]

        # Detect root indentation (defaults to two spaces).
        lines = before.splitlines()
        indent = "  "
        for ln in reversed(lines):
            if ln.strip() and ln.strip() != "</ossec_config>":
                indent = cls._detect_line_indent(ln) or "  "
                break

        marker_line = f"WAZUMATION:feature={marker}" if marker else ""
        comment = f"{indent}  <!-- {marker_line} -->\n" if marker_line else ""

        block = (
            f"\n{indent}<localfile>\n"
            f"{comment}"
            f"{indent}  <log_format>{log_format}</log_format>\n"
            f"{indent}  <location>{location}</location>\n"
            f"{indent}</localfile>\n"
        )

        return before + block + after

    @classmethod
    def remove_localfile_instance(
        cls, content: str, instance: Dict[str, str], *, marker: Optional[str] = None
    ) -> str:
        """Remove matching <localfile> blocks; if marker is set, require marker comment inside block."""
        log_format = instance.get("log_format")
        location = instance.get("location")
        if not log_format or not location:
            return content

        lf_re = re.compile(r"<localfile\b[^>]*>[\s\S]*?</localfile>\s*", re.IGNORECASE)
        out = []
        last = 0
        for m in lf_re.finditer(content):
            block = m.group(0)
            matches = re.search(rf"<log_format>\s*{re.escape(log_format)}\s*</log_format>", block, re.IGNORECASE) and re.search(
                rf"<location>\s*{re.escape(location)}\s*</location>", block, re.IGNORECASE
            )
            if not matches:
                continue
            if marker:
                if f"WAZUMATION:feature={marker}" not in block:
                    continue
            out.append(content[last : m.start()])
            last = m.end()
        out.append(content[last:])
        return "".join(out)

    @classmethod
    def upsert_section_desired(
        cls, content: str, section_tag: str, desired: Dict[str, Any], *, feature_id: Optional[str] = None
    ) -> str:
        """
        Upsert/remove simple child keys inside the first <section_tag>...</section_tag> block.

        - If section doesn't exist, create it near end of <ossec_config>.
        - If desired[key] is None, remove existing <key>..</key> occurrences.
        - Otherwise ensure <key>value</key> exists (update if present, insert if missing).
        """
        if not section_tag:
            return content

        # Normalize values (especially booleans).
        desired_norm: Dict[str, Optional[str]] = {k: cls._normalize_yes_no(v) for k, v in (desired or {}).items()}

        sec_re = re.compile(
            rf"(<{re.escape(section_tag)}\b[^>]*>)([\s\S]*?)(</{re.escape(section_tag)}>)",
            re.IGNORECASE,
        )
        m = sec_re.search(content)

        if not m:
            # Create section near end of ossec_config.
            close_start = cls._ossec_config_close_start(content)
            before = content[:close_start]
            after = content[close_start:]

            # Root indentation defaults to two spaces.
            lines = before.splitlines()
            root_indent = "  "
            for ln in reversed(lines):
                if ln.strip() and ln.strip() != "</ossec_config>":
                    root_indent = cls._detect_line_indent(ln) or "  "
                    break

            child_indent = root_indent + "  "
            marker = cls.feature_marker(feature_id, scope=f"section:{section_tag}") if feature_id else None
            marker_lines = ""
            if marker:
                marker_lines = f"{root_indent}{marker.begin}\n"

            body = ""
            for k, v in desired_norm.items():
                if v is None:
                    continue
                body += f"{child_indent}<{k}>{v}</{k}>\n"

            if not body:
                return content

            block = (
                f"\n{marker_lines}"
                f"{root_indent}<{section_tag}>\n"
                f"{body}"
                f"{root_indent}</{section_tag}>\n"
            )
            if marker:
                block += f"{root_indent}{marker.end}\n"

            return before + block + after

        open_tag, inner, close_tag = m.group(1), m.group(2), m.group(3)

        # Detect indentation from existing content.
        lines = (open_tag + inner + close_tag).splitlines()
        section_indent = "  "
        for ln in lines:
            if re.search(rf"^\s*<{re.escape(section_tag)}\b", ln):
                section_indent = cls._detect_line_indent(ln) or "  "
                break
        child_indent = section_indent + "  "

        new_inner = inner

        # First: remove keys set to None.
        for k, v in desired_norm.items():
            if v is not None:
                continue
            key_re = re.compile(rf"^\s*<{re.escape(k)}\b[^>]*>[\s\S]*?</{re.escape(k)}>\s*\n?", re.IGNORECASE | re.MULTILINE)
            new_inner = key_re.sub("", new_inner)

        # Then: upsert keys with a value.
        for k, v in desired_norm.items():
            if v is None:
                continue
            # Update if exists
            key_re = re.compile(rf"(<{re.escape(k)}\b[^>]*>)([\s\S]*?)(</{re.escape(k)}>)", re.IGNORECASE)
            km = key_re.search(new_inner)
            if km:
                new_inner = key_re.sub(rf"\1{v}\3", new_inner, count=1)
                continue

            # Insert before closing tag, optionally inside a marker block.
            marker = cls.feature_marker(feature_id, scope=f"{section_tag}") if feature_id else None
            insert_text = f"{child_indent}<{k}>{v}</{k}>\n"
            if marker and marker.begin not in new_inner:
                insert_text = f"{child_indent}{marker.begin}\n{insert_text}{child_indent}{marker.end}\n"
            new_inner = new_inner.rstrip() + "\n" + insert_text

        replaced = content[: m.start()] + open_tag + new_inner + close_tag + content[m.end() :]
        return replaced


