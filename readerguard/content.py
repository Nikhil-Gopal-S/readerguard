"""Content checks shared by every format: invisible Unicode, and "side-channel" text (metadata, comments,
notes...) that a reader never sees but a loader may index. These count what was removed; they judge nothing."""
from __future__ import annotations

from . import textscan
from .findings import Finding


def content_findings(text: str, channel: str, page=None, side_channel=False) -> list[Finding]:
    """side_channel: also count the mere presence of text in this channel (it is left out of safe_text)."""
    out: list[Finding] = []
    if not text or not text.strip():
        return out
    u = textscan.unicode_anomalies(text)
    if u["tag_chars"]:
        out.append(Finding("unicode_smuggling", f"{u['tag_chars']} invisible Unicode tag characters in {channel}",
                           page))
    if u["bidi"]:
        out.append(Finding("unicode_smuggling", f"{u['bidi']} bidirectional control characters in {channel}", page))
    if u["zero_width"] >= 5:
        out.append(Finding("unicode_smuggling", f"{u['zero_width']} zero-width characters in {channel}", page))
    if side_channel and sum(c.isalnum() for c in text) >= 3:
        out.append(Finding("side_channel_text", f"text in {channel} (not part of the visible body)", page))
    return out


def hidden_text_finding(text: str, channel: str, reason: str, page=None, count: int = 1) -> list[Finding]:
    """A run of text that is extracted but not shown (at least 3 letters or digits)."""
    if sum(c.isalnum() for c in text) < 3:
        return []
    return [Finding("hidden_text", f"hidden text ({reason}): {count} piece(s) of text in {channel} that a parser "
                                   "extracts but a reader cannot see", page)]


def _lum(rgb) -> float:
    def ch(v):
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = (ch(float(v)) for v in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a, b) -> float:
    """WCAG contrast ratio of two RGB colours (channels 0..1)."""
    la, lb = _lum(a), _lum(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)
