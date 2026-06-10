"""badge.py — self-contained SVG governance badge in CWN DDU colors.

render_badge(tier, score, *, refs=None, title=None) -> str  returns a complete, standalone
<svg> string: no external fonts, no <image>, no JS, no network. It is a flat two-cell
shield ("AGENT GOVERNANCE" | "<TIER> <score>") plus an optional row of citable control
chips (e.g. "NIST 800-53 AC-5"), styled in the locked DDU palette.

DDU palette (memory/cwn_ddu_brand_guide.md):
  accent  #FF4500   tier cell + chip outline
  obsidian #0A0A0A  label cell + text-on-accent
  cream   #EFEBE2   chip text + accent-cell text
A tier other than SOVEREIGN/HARDENED keeps the accent cell but dims it so a low score
never *looks* like a win (UNGOVERNED renders on obsidian, not orange — honesty, pol.143).

XML/ASCII discipline: every dynamic string is XML-escaped (_x) and non-ASCII is stripped,
so the badge is safe to inline in HTML/Markdown and safe to drop into the signed receipt
evidence if a caller wants the rendered artifact hashed.

Pure function, zero deps (stdlib only). No import of the rest of the package, so a consumer
can render a badge from a (tier, score) pair without pulling the pipeline.
"""
from __future__ import annotations

# locked DDU tokens
_ACCENT = "#FF4500"
_OBS = "#0A0A0A"
_CREAM = "#EFEBE2"
_DIM = "#3a2a22"   # dimmed accent for non-hardened tiers (still readable, not celebratory)

_MONO = ("ui-monospace,SFMono-Regular,Menlo,Consolas,"
         "'JetBrains Mono','DejaVu Sans Mono',monospace")

# tiers that earn the live-orange accent cell; others render dimmed.
_HOT_TIERS = ("SOVEREIGN", "HARDENED")

# approximate monospace glyph advance at 11px (px). Used to size cells without measuring.
_CW = 7.4


def _x(s) -> str:
    """XML-escape + ASCII-strip. Order: ampersand first, then the angle brackets/quotes."""
    s = "" if s is None else str(s)
    s = s.encode("ascii", "ignore").decode("ascii")  # drop any non-ASCII before escaping
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&apos;"))


def _cell_w(text: str, pad: int = 14) -> int:
    return int(len(text) * _CW + pad * 2)


def render_badge(tier: str, score: int, *, refs=None, title: str | None = None) -> str:
    """Return a complete standalone SVG string for (tier, score).

    tier  one of schema.TIERS (defended here too — an unknown tier renders dimmed).
    score 0..100 int (clamped + coerced; a non-int floors to 0).
    refs  optional list of compact control tokens (badge stays honest if empty).
    title optional <title> tooltip text (defaults to a one-line summary).
    """
    tier = _x(str(tier or "UNGOVERNED").upper())
    try:
        score_i = max(0, min(100, int(score)))
    except (TypeError, ValueError):
        score_i = 0

    label_txt = "AGENT GOVERNANCE"
    value_txt = f"{tier} {score_i}"
    hot = tier in _HOT_TIERS
    value_bg = _ACCENT if hot else _DIM
    value_fg = _OBS if hot else _CREAM

    lw = _cell_w(label_txt)
    vw = _cell_w(value_txt)
    chips = list(refs or [])
    chip_svg, chips_w, chips_h = _chips(chips, lw + vw)
    w = max(lw + vw, chips_w)
    h = 28 + chips_h
    tip = _x(title) if title else _x(f"OpenAgentOntology -- Agent Governance: {tier} {score_i}/100")

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
        f'viewBox="0 0 {w} {h}" role="img" aria-label="Agent Governance {tier} {score_i}">',
        f'<title>{tip}</title>',
        # label cell (obsidian)
        f'<rect x="0" y="0" width="{lw}" height="28" fill="{_OBS}"/>',
        # value cell (accent or dimmed)
        f'<rect x="{lw}" y="0" width="{vw}" height="28" fill="{value_bg}"/>',
        # 2px accent underline ties the shield together
        f'<rect x="0" y="26" width="{w}" height="2" fill="{_ACCENT}"/>',
        f'<text x="{lw // 2}" y="18" fill="{_CREAM}" font-family="{_MONO}" '
        f'font-size="11" font-weight="700" letter-spacing="0.5" '
        f'text-anchor="middle">{_x(label_txt)}</text>',
        f'<text x="{lw + vw // 2}" y="18" fill="{value_fg}" font-family="{_MONO}" '
        f'font-size="11" font-weight="700" letter-spacing="0.5" '
        f'text-anchor="middle">{_x(value_txt)}</text>',
    ]
    parts.extend(chip_svg)
    parts.append("</svg>")
    return "".join(parts)


def _chips(refs, min_w) -> tuple:
    """Render a wrapping-free single row of control chips under the shield.

    Returns (list_of_svg_fragments, total_width, chip_band_height). Empty refs -> no band.
    Each chip is a hairline accent-outlined cell with cream text on obsidian.
    """
    if not refs:
        return [], min_w, 0
    frags = []
    x = 0
    pad = 7
    gap = 5
    band_top = 30
    for token in refs:
        t = _x(str(token))
        cw = int(len(t) * 6.2 + pad * 2)
        frags.append(
            f'<rect x="{x}" y="{band_top}" width="{cw}" height="18" fill="{_OBS}" '
            f'stroke="{_ACCENT}" stroke-width="1"/>'
            f'<text x="{x + cw // 2}" y="{band_top + 13}" fill="{_CREAM}" '
            f'font-family="{_MONO}" font-size="9" text-anchor="middle">{t}</text>')
        x += cw + gap
    total_w = max(min_w, x - gap)
    return frags, total_w, 20
