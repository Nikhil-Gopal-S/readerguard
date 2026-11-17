"""Checks that run on any extracted string: invisible Unicode, counted and stripped."""
from __future__ import annotations

import re
import unicodedata

TAG_CHARS = (0xE0000, 0xE007F)          # "ASCII smuggling": invisible copies of ASCII
ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E}
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A))


def unicode_anomalies(text: str) -> dict:
    """Counts of suspicious code points, plus the decoded payload of any tag characters."""
    tags, zw, bidi = [], 0, 0
    for ch in text:
        o = ord(ch)
        if TAG_CHARS[0] <= o <= TAG_CHARS[1]:
            tags.append(chr(o - 0xE0000) if 0x20 <= o - 0xE0000 < 0x7F else "")
        elif o in ZERO_WIDTH:
            zw += 1
        elif o in BIDI:
            bidi += 1
    return {"tag_chars": len(tags), "tag_payload": "".join(tags), "zero_width": zw, "bidi": bidi}


_DROP_CATEGORIES = {"Cc", "Cf", "Co", "Cn", "Cs"}   # controls, format, private use, unassigned, lone surrogates
_KEEP = {"\n", "\t", "\f", "\u200c", "\u200d", "\ufe0f"}   # \f separates pages; ZWNJ, ZWJ, VS16: emoji, scripts
_DROP = (set(range(0xFE00, 0xFE10)) | set(range(0xE0100, 0xE01F0)) | {0x180B, 0x180C, 0x180D, 0x180F}  # var. sel.
         | {0x115F, 0x1160, 0x3164, 0xFFA0}                                                     # Hangul fillers
         | {0x034F, 0x17B4, 0x17B5})                     # invisible marks (Mn): grapheme joiner, Khmer inherent vowels
_JOINERS = re.compile("[\u200c\u200d\ufe0f]{2,}")


class _Table(dict):
    """str.translate table, filled on first use of each code point: None drops it."""
    def __missing__(self, o):
        ch = chr(o)
        self[o] = v = o if ch in _KEEP or not (o in _DROP or unicodedata.category(ch) in _DROP_CATEGORIES) else None
        return v


_TABLE = _Table()


def strip_invisible(text: str) -> str:
    """Remove invisible Unicode by category: Cc (but newline, tab, form feed), Cf, Co, Cn, Cs; every variation
    selector but U+FE0F; the Hangul fillers; U+034F, U+17B4, U+17B5. ZWNJ, ZWJ and U+FE0F stay, but a run of
    them keeps each one once."""
    text = text.translate(_TABLE)
    return _JOINERS.sub(lambda m: "".join(c for c in "\ufe0f\u200c\u200d" if c in m.group()), text)
