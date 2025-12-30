"""Auto-heal Wazuh ossec.conf XML issues (zero-touch remediation).

This targets real-world failure modes seen in the field:
- UTF BOM / UTF-16 artifacts
- NUL bytes / control characters
- Trailing garbage after </ossec_config>
- Multiple ossec_config blocks (keep last full block)

Design:
- Always creates a timestamped backup next to the config file.
- Applies conservative, text-level fixes.
- Verifies via lxml parse and (when available) wazuh-control validation.
- Rolls back on failure.
"""

from __future__ import annotations

import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple


@dataclass
class HealResult:
    ok: bool
    fixes: List[str]


class XMLHealer:
    """Automatically detect and fix common ossec.conf XML parsing failures."""

    def __init__(self, config_path: Path, *, validator=None):
        self.config_path = Path(config_path)
        self.validator = validator
        self.backup_path: Optional[Path] = None

    def heal(self) -> HealResult:
        fixes: List[str] = []

        if not self.config_path.exists():
            return HealResult(False, [f"Config not found: {self.config_path}"])

        try:
            self.backup_path = self._create_backup()
            fixes.append(f"Created backup: {self.backup_path}")

            raw = self.config_path.read_bytes()

            text, enc_fix = self._decode_best_effort(raw)
            if enc_fix:
                fixes.append(enc_fix)

            cleaned, clean_fixes = self._sanitize_text(text)
            fixes.extend(clean_fixes)

            # Write candidate
            if cleaned != text:
                self.config_path.write_text(cleaned, encoding="utf-8", newline="\n")
                fixes.append("Wrote repaired config as UTF-8")

            # Validate: lxml + wazuh-control (best-effort)
            ok, vfix = self._validate_with_existing_validator(auto_fix=True)
            fixes.extend(vfix)
            if ok:
                return HealResult(True, fixes)

            # Last attempt: invoke the validator's own auto-fix (it has additional heuristics).
            if self.validator is not None and hasattr(self.validator, "auto_fix_xml_issues"):
                was_fixed, msg = self.validator.auto_fix_xml_issues(self.config_path)
                if was_fixed:
                    fixes.append(f"Validator auto-fix applied: {msg}")
                    ok2, vfix2 = self._validate_with_existing_validator(auto_fix=False)
                    fixes.extend(vfix2)
                    if ok2:
                        return HealResult(True, fixes)

            # Fail -> rollback
            fixes.append("Repair attempts failed; rolling back")
            self.rollback()
            return HealResult(False, fixes)
        except Exception as e:
            fixes.append(f"Fatal error: {e}")
            self.rollback()
            return HealResult(False, fixes)

    def rollback(self) -> None:
        if self.backup_path and self.backup_path.exists():
            shutil.copy2(self.backup_path, self.config_path)

    def _create_backup(self) -> Path:
        ts = int(time.time())
        backup_path = self.config_path.with_name(f"{self.config_path.name}.healer.backup.{ts}")
        shutil.copy2(self.config_path, backup_path)
        return backup_path

    @staticmethod
    def _decode_best_effort(raw: bytes) -> Tuple[str, Optional[str]]:
        # Strip UTF-8 BOM quickly
        if raw.startswith(b"\xef\xbb\xbf"):
            return raw[3:].decode("utf-8", errors="replace"), "Removed UTF-8 BOM"

        # UTF-16 BOM handling
        if raw.startswith(b"\xff\xfe"):
            return raw.decode("utf-16le", errors="replace"), "Decoded UTF-16LE input"
        if raw.startswith(b"\xfe\xff"):
            return raw.decode("utf-16be", errors="replace"), "Decoded UTF-16BE input"

        # Default: UTF-8 with replacement
        return raw.decode("utf-8", errors="replace"), None

    @staticmethod
    def _strip_invalid_xml_chars(s: str) -> Tuple[str, bool]:
        # XML 1.0 valid chars: #x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD]
        def ok(cp: int) -> bool:
            return cp in (0x9, 0xA, 0xD) or (0x20 <= cp <= 0xD7FF) or (0xE000 <= cp <= 0xFFFD)

        out = []
        changed = False
        for ch in s:
            if ok(ord(ch)):
                out.append(ch)
            else:
                changed = True
        return "".join(out), changed

    def _sanitize_text(self, text: str) -> Tuple[str, List[str]]:
        fixes: List[str] = []
        original = text

        # Normalize newlines to avoid mixed CRLF issues
        if "\r\n" in text:
            text = text.replace("\r\n", "\n")
            fixes.append("Normalized CRLF to LF")

        # Remove NUL characters
        if "\x00" in text:
            text = text.replace("\x00", "")
            fixes.append("Removed NUL bytes")

        # Remove invalid XML chars
        text2, changed = self._strip_invalid_xml_chars(text)
        if changed:
            text = text2
            fixes.append("Removed invalid XML characters")

        # Keep only the final complete ossec_config block (most conservative for Wazuh).
        open_re = re.compile(r"<ossec_config\b[^>]*>", re.IGNORECASE)
        close_tag = "</ossec_config>"
        opens = list(open_re.finditer(text))
        last_close = text.lower().rfind(close_tag)
        if last_close != -1 and opens:
            # keep content from last opening before the last closing
            start = None
            for m in reversed(opens):
                if m.start() < last_close:
                    start = m.start()
                    break
            if start is not None:
                end = last_close + len(close_tag)
                trimmed = text[start:end].rstrip() + "\n"
                if trimmed != text:
                    text = trimmed
                    fixes.append("Trimmed to last complete <ossec_config>...</ossec_config> block")

        # Ensure we actually have a closing tag; if missing but opening exists, append it.
        if opens and last_close == -1:
            text = text.rstrip() + "\n</ossec_config>\n"
            fixes.append("Appended missing </ossec_config> closing tag")

        if text != original and not fixes:
            fixes.append("Applied sanitation")

        return text, fixes

    def _validate_with_existing_validator(self, *, auto_fix: bool) -> Tuple[bool, List[str]]:
        msgs: List[str] = []
        # Primary: existing validator (xmllint + lxml + wazuh-control best-effort)
        if self.validator is not None and hasattr(self.validator, "validate_ossec_conf"):
            ok, errs = self.validator.validate_ossec_conf(self.config_path, auto_fix=auto_fix)
            if ok:
                msgs.append("Validation passed")
                return True, msgs
            msgs.append("Validation failed: " + "; ".join(errs))
            return False, msgs

        # Fallback: lxml parse only
        try:
            from lxml import etree

            etree.parse(str(self.config_path), etree.XMLParser(remove_blank_text=True))
            msgs.append("lxml parse passed")
            return True, msgs
        except Exception as e:
            msgs.append(f"lxml parse failed: {e}")
            return False, msgs


