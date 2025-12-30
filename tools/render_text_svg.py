"""Render terminal output text to a lightweight SVG (no external deps).

Used to generate "real output screenshots" under docs/assets from actual tool runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional


def _escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


@dataclass
class SvgStyle:
    font_family: str = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    font_size: int = 14
    line_height: int = 18
    padding: int = 16
    bg: str = "#0b0f14"
    fg: str = "#d7dde6"
    title_fg: str = "#9fb3c8"
    border: str = "#223043"


def render_text_to_svg(
    *,
    title: str,
    lines: Iterable[str],
    out_path: Path,
    style: Optional[SvgStyle] = None,
    max_width_chars: int = 120,
) -> None:
    style = style or SvgStyle()
    raw_lines = [l.rstrip("\n") for l in lines]
    # soft truncate to keep screenshots reasonable
    rendered_lines: List[str] = []
    for l in raw_lines:
        if len(l) > max_width_chars:
            rendered_lines.append(l[: max_width_chars - 1] + "…")
        else:
            rendered_lines.append(l)

    width = style.padding * 2 + max_width_chars * (style.font_size * 0.6)
    height = style.padding * 3 + style.line_height * (len(rendered_lines) + 2)

    x0 = style.padding
    y = style.padding + style.line_height

    parts: List[str] = []
    parts.append('<?xml version="1.0" encoding="UTF-8"?>')
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{int(width)}" height="{int(height)}" viewBox="0 0 {int(width)} {int(height)}">'
    )
    parts.append(
        f'<rect x="1" y="1" width="{int(width)-2}" height="{int(height)-2}" rx="10" fill="{style.bg}" stroke="{style.border}" />'
    )
    parts.append(
        f'<text x="{x0}" y="{y}" fill="{style.title_fg}" font-family="{style.font_family}" font-size="{style.font_size}">{_escape(title)}</text>'
    )
    y += style.line_height * 1.5
    for line in rendered_lines:
        parts.append(
            f'<text x="{x0}" y="{int(y)}" fill="{style.fg}" font-family="{style.font_family}" font-size="{style.font_size}">{_escape(line)}</text>'
        )
        y += style.line_height
    parts.append("</svg>")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(parts) + "\n", encoding="utf-8")


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--title", required=True)
    ap.add_argument("--in", dest="in_path", required=True)
    ap.add_argument("--out", dest="out_path", required=True)
    args = ap.parse_args()
    render_text_to_svg(
        title=args.title,
        lines=Path(args.in_path).read_text(encoding="utf-8", errors="replace").splitlines(),
        out_path=Path(args.out_path),
    )


