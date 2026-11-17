"""Just enough CSS to decide whether text is visible: rule parsing, selector matching, cascade, colours, lengths.
No layout engine, so this is an approximation.

Selectors: type, universal, class, id, attribute (all operators), descendant, child and sibling combinators.
Cascade: cascade layers, specificity, source order, !important, inline styles. Declarations a browser drops
(an invalid value, a later duplicate that does not parse) are dropped here too, after comments and escapes.
@media is evaluated for one fixed screen (1280 x 800, light scheme, fine pointer); a query that cannot be
evaluated, and @supports / @container / @scope, make their rules fuzzy (they may only hide, never show).
Rules for interaction states (:hover, :focus, ... outside :not()) and generated content (::before, ...) are
skipped. Any other pseudo-class (:not, :nth-child, :has, ...) is not evaluated: the selector without it matches
a superset of elements, and such a rule may only hide text, never show it (fail closed). A selector that
cannot be parsed is treated the same way, as matching every element.
Not evaluated here: @import (the HTML extractor follows it with imports()), styles set by script, media conditions, var(), calc()."""
from __future__ import annotations

import colorsys
import functools
import re

from .. import limits

RELEVANT = {"display", "visibility", "opacity", "font-size", "color", "background", "background-color", "position",
            "left", "top", "right", "bottom", "text-indent", "clip", "clip-path", "height", "max-height", "width",
            "max-width", "overflow", "overflow-x", "overflow-y", "transform", "translate", "fill", "fill-opacity",
            "font", "background-clip", "-webkit-background-clip", "-webkit-text-fill-color", "content-visibility",
            "scale", "zoom", "filter", "margin", "margin-left", "margin-top", "inset", "background-image",
            "mask", "mask-image", "-webkit-mask", "-webkit-mask-image", "backface-visibility", "-webkit-line-clamp",
            "line-clamp", "letter-spacing", "word-spacing"}
MAX_VALUE = 4096                 # a longer declaration value is dropped (no honest page needs one)
MAX_SELECTOR = 1024              # a longer selector is treated as unparseable (fuzzy: may hide, never show)

NAMED = dict(zip(
    "aliceblue antiquewhite aqua aquamarine azure beige bisque black blanchedalmond blue blueviolet brown burlywood "
    "cadetblue chartreuse chocolate coral cornflowerblue cornsilk crimson cyan darkblue darkcyan darkgoldenrod "
    "darkgray darkgreen darkgrey darkkhaki darkmagenta darkolivegreen darkorange darkorchid darkred darksalmon "
    "darkseagreen darkslateblue darkslategray darkslategrey darkturquoise darkviolet deeppink deepskyblue dimgray "
    "dimgrey dodgerblue firebrick floralwhite forestgreen fuchsia gainsboro ghostwhite gold goldenrod gray green "
    "greenyellow grey honeydew hotpink indianred indigo ivory khaki lavender lavenderblush lawngreen lemonchiffon "
    "lightblue lightcoral lightcyan lightgoldenrodyellow lightgray lightgreen lightgrey lightpink lightsalmon "
    "lightseagreen lightskyblue lightslategray lightslategrey lightsteelblue lightyellow lime limegreen linen "
    "magenta maroon mediumaquamarine mediumblue mediumorchid mediumpurple mediumseagreen mediumslateblue "
    "mediumspringgreen mediumturquoise mediumvioletred midnightblue mintcream mistyrose moccasin navajowhite navy "
    "oldlace olive olivedrab orange orangered orchid palegoldenrod palegreen paleturquoise palevioletred "
    "papayawhip peachpuff peru pink plum powderblue purple rebeccapurple red rosybrown royalblue saddlebrown "
    "salmon sandybrown seagreen seashell sienna silver skyblue slateblue slategray slategrey snow springgreen "
    "steelblue tan teal thistle tomato turquoise violet wheat white whitesmoke yellow yellowgreen".split(),
    [tuple(int(h[i:i + 2], 16) for i in (0, 2, 4)) for h in (
        "f0f8ff faebd7 00ffff 7fffd4 f0ffff f5f5dc ffe4c4 000000 ffebcd 0000ff 8a2be2 a52a2a deb887 5f9ea0 7fff00 "
        "d2691e ff7f50 6495ed fff8dc dc143c 00ffff 00008b 008b8b b8860b a9a9a9 006400 a9a9a9 bdb76b 8b008b 556b2f "
        "ff8c00 9932cc 8b0000 e9967a 8fbc8f 483d8b 2f4f4f 2f4f4f 00ced1 9400d3 ff1493 00bfff 696969 696969 1e90ff "
        "b22222 fffaf0 228b22 ff00ff dcdcdc f8f8ff ffd700 daa520 808080 008000 adff2f 808080 f0fff0 ff69b4 cd5c5c "
        "4b0082 fffff0 f0e68c e6e6fa fff0f5 7cfc00 fffacd add8e6 f08080 e0ffff fafad2 d3d3d3 90ee90 d3d3d3 ffb6c1 "
        "ffa07a 20b2aa 87cefa 778899 778899 b0c4de ffffe0 00ff00 32cd32 faf0e6 ff00ff 800000 66cdaa 0000cd ba55d3 "
        "9370db 3cb371 7b68ee 00fa9a 48d1cc c71585 191970 f5fffa ffe4e1 ffe4b5 ffdead 000080 fdf5e6 808000 6b8e23 "
        "ffa500 ff4500 da70d6 eee8aa 98fb98 afeeee db7093 ffefd5 ffdab9 cd853f ffc0cb dda0dd b0e0e6 800080 663399 "
        "ff0000 bc8f8f 4169e1 8b4513 fa8072 f4a460 2e8b57 fff5ee a0522d c0c0c0 87ceeb 6a5acd 708090 708090 fffafa "
        "00ff7f 4682b4 d2b48c 008080 d8bfd8 ff6347 40e0d0 ee82ee f5deb3 ffffff f5f5f5 ffff00 9acd32").split()]))
NAMED.update({   # CSS system colours, as a default light-scheme browser paints them
    "canvas": (255, 255, 255), "canvastext": (0, 0, 0), "linktext": (0, 0, 238), "visitedtext": (85, 26, 139),
    "activetext": (255, 0, 0), "buttonface": (240, 240, 240), "buttontext": (0, 0, 0),
    "buttonborder": (118, 118, 118), "field": (255, 255, 255), "fieldtext": (0, 0, 0),
    "highlight": (0, 120, 215), "highlighttext": (255, 255, 255), "graytext": (109, 109, 109),
    "mark": (255, 255, 0), "marktext": (0, 0, 0), "selecteditem": (0, 120, 215),
    "selecteditemtext": (255, 255, 255), "accentcolor": (0, 120, 215), "accentcolortext": (255, 255, 255),
    "window": (255, 255, 255), "windowtext": (0, 0, 0)})
CSS_WIDE = {"inherit", "initial", "unset", "revert", "revert-layer"}
DISPLAY_WORDS = {"none", "block", "inline", "inline-block", "flex", "inline-flex", "grid", "inline-grid", "flow",
                 "flow-root", "table", "inline-table", "table-row", "table-cell", "table-column", "table-caption",
                 "table-row-group", "table-header-group", "table-footer-group", "table-column-group", "list-item",
                 "contents", "run-in", "ruby", "ruby-base", "ruby-text", "ruby-base-container",
                 "ruby-text-container", "math", "-webkit-box", "-webkit-inline-box", "-ms-flexbox",
                 "-ms-inline-flexbox", "-webkit-flex", "-webkit-inline-flex", "-moz-box", "-ms-grid"}
FONT_SIZE_WORDS = {"xx-small", "x-small", "small", "medium", "large", "x-large", "xx-large", "xxx-large", "smaller",
                   "larger", "math"}
_NUM = r"[+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?"


def _num(t: str, pct: float = 100.0) -> float:
    t = t.strip()
    return float(t[:-1]) / 100 * pct if t.endswith("%") else float(t)


def _alpha(parts) -> float:
    return _num(parts[3], 1.0) if len(parts) > 3 else 1.0


def parse_color(v: str):
    """-> (r, g, b, alpha) in 0..255 / 0..1, or None when unknown (var(), gradients, currentColor...).
    lab() / lch() / oklab() / oklch() are approximated by their lightness (a grey of the same lightness)."""
    v = v.strip().lower()
    if not v or len(v) > 200 or "var(" in v or "gradient" in v or "url(" in v:
        return None
    if v == "transparent":
        return (0, 0, 0, 0.0)
    m = re.fullmatch(r"#([0-9a-f]{3,8})", v)
    if m:
        h = m.group(1)
        if len(h) in (3, 4):
            h = "".join(c * 2 for c in h)
        if len(h) not in (6, 8):
            return None
        a = int(h[6:8], 16) / 255 if len(h) == 8 else 1.0
        return (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), a)
    m = re.fullmatch(r"([a-z]+)\(([^()]*)\)", v)
    if m:
        fn, parts = m.group(1), [p for p in re.split(r"[\s,/]+", m.group(2)) if p]
        try:
            if fn in ("rgb", "rgba"):
                rgb = [_num(p, 255) for p in parts[:3]]
                if len(rgb) < 3:
                    return None
                return (*[int(max(0, min(255, x))) for x in rgb], _alpha(parts))
            if fn in ("hsl", "hsla", "hwb"):
                h = float(re.sub(r"deg$", "", parts[0])) / 360
                x, y = (_num(p, 1.0) if p.endswith("%") else float(p) / 100 for p in parts[1:3])
                if fn == "hwb":
                    if x + y >= 1:
                        g = round(255 * x / (x + y))
                        return (g, g, g, _alpha(parts))
                    r, g, b = colorsys.hsv_to_rgb(h % 1, 1.0, 1.0)
                    r, g, b = (c * (1 - x - y) + x for c in (r, g, b))
                else:
                    r, g, b = colorsys.hls_to_rgb(h % 1, max(0.0, min(1.0, y)), max(0.0, min(1.0, x)))
                return (round(r * 255), round(g * 255), round(b * 255), _alpha(parts))
            if fn in ("lab", "lch", "oklab", "oklch"):
                top = 1.0 if fn.startswith("ok") else 100.0
                light = _num(parts[0], top) / top
                g = round(255 * max(0.0, min(1.0, light)))
                return (g, g, g, _alpha(parts))
        except (ValueError, IndexError):
            return None
        return None
    if v in NAMED:
        return (*NAMED[v], 1.0)
    return None


@functools.lru_cache(maxsize=4096)
def first_color(v: str):
    """background shorthand: pick the first colour-looking token (one linear pass; cached per value)."""
    c = parse_color(v)
    if c:
        return c
    for tok in re.findall(r"#[0-9a-fA-F]{3,8}|\b[a-z]+\([^()]{0,200}\)|\b[a-z]+\b", v):
        c = parse_color(tok)
        if c:
            return c
    return None


UNITS = {"px": 1.0, "pt": 4 / 3, "pc": 16.0, "in": 96.0, "cm": 96 / 2.54, "mm": 96 / 25.4, "q": 96 / 101.6,
         "vw": 12.8, "vh": 8.0, "vmin": 8.0, "vmax": 12.8, "svw": 12.8, "lvw": 12.8, "dvw": 12.8, "svh": 8.0,
         "lvh": 8.0, "dvh": 8.0, "cqw": 12.8, "cqh": 8.0, "cqi": 12.8, "cqb": 8.0, "rem": 16.0}
REL_UNITS = {"em": 1.0, "%": 0.01, "ch": 0.5, "ex": 0.5, "cap": 0.7, "ic": 1.0, "lh": 1.2, "rlh": 1.2}


def length_px(v: str, base: float = 16.0):
    """CSS length in px (approximate), or None. Any unit, exponents allowed (1e-9px)."""
    v = v.strip().lower()
    m = re.match(r"^(" + _NUM + r")([a-z%]*)$", v)
    if not m:
        return None
    n, u = float(m.group(1)), m.group(2) or "px"
    if u in UNITS:
        return n * UNITS[u]
    if u in REL_UNITS:
        return n * base * REL_UNITS[u]
    return None


def valid_value(prop: str, v: str) -> bool:
    """Would a browser keep this declaration? Only the properties the visibility model reads are checked;
    anything with var() is kept (it is resolved later, as in a browser)."""
    lv = v.strip().lower()
    if not lv or "var(" in lv or lv in CSS_WIDE:
        return bool(lv)
    if prop == "display":
        return all(w in DISPLAY_WORDS for w in lv.split())
    if prop == "visibility":
        return lv in ("visible", "hidden", "collapse")
    if prop in ("opacity", "fill-opacity"):
        return re.fullmatch(_NUM + "%?", lv) is not None
    if prop in ("color", "background-color", "-webkit-text-fill-color", "fill"):
        return parse_color(lv) is not None or lv == "currentcolor" or re.match(r"[a-z-]+\(", lv) is not None
    if prop == "font-size":
        return length_px(lv) is not None or lv in FONT_SIZE_WORDS or re.match(r"[a-z-]+\(", lv) is not None
    return True


def parse_decls(s: str) -> tuple[dict, dict]:
    """-> (normal, !important) declarations, property names lower-cased. Comments and escapes are resolved
    first; a declaration a browser would drop (invalid value) is dropped, so an earlier valid one stays."""
    out, imp = {}, {}
    if "/*" in s:
        s = _strip_comments(s)
    for part in s.split(";"):
        if ":" not in part:
            continue
        k, v = part.split(":", 1)
        k = k.strip()
        v, n = re.subn(r"!\s*important\s*$", "", v.strip(), flags=re.I)
        v = v.strip()
        if not k or len(v) > MAX_VALUE:
            continue
        if k.startswith("--"):                         # custom property: case-sensitive, kept for var()
            (imp if n else out)[k] = v
            continue
        if "\\" in k or "\\" in v:
            k, v = _unescape(k), _unescape(v)
        k = k.lower()
        if k in RELEVANT and not valid_value(k, v):
            continue
        (imp if n else out)[k] = v
    return out, imp


# CSS escapes: hex (all of up to 6 digits, then one optional space) or one other character. Unambiguous: an
# escape can be split only one way, so no selector can make the matcher backtrack.
ESC = r"\\(?:[0-9a-fA-F]{1,6}(?![0-9a-fA-F])\s?|[^0-9a-fA-F\n])"


def _unescape(s: str) -> str:
    def one(m):
        h = m.group(0)[1:].strip()
        if not re.fullmatch(r"[0-9a-fA-F]{1,6}", h):
            return h
        n = int(h, 16)
        return chr(n) if 0 < n <= 0x10FFFF and not 0xD800 <= n <= 0xDFFF else "\ufffd"
    return re.sub(ESC, one, s)


IDENT = rf"(?:[\w-]|{ESC})+"
_COMPOUND = re.compile(rf"^(?P<tag>{IDENT}|\*)?(?P<rest>(?:[#.]{IDENT}|\[[^\]]*\])*)$")
_ATTR = re.compile(r"^\s*([\w-]+)\s*(?:([~|^$*]?=)\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s'\"\]]+))\s*([iIsS])?)?\s*$")
_ATTR_OPS = {"=": lambda h, v: h == v, "~=": lambda h, v: v in h.split(),
             "|=": lambda h, v: h == v or h.startswith(v + "-"), "^=": lambda h, v: bool(v) and h.startswith(v),
             "$=": lambda h, v: bool(v) and h.endswith(v), "*=": lambda h, v: bool(v) and v in h}
# A pseudo-class or pseudo-element, with a balanced argument (one level of nesting), not after a backslash.
_PSEUDO = re.compile(r"(?<!\\)::?[\w-]+(?:\((?:[^()]|\([^()]*\))*\))?")
_NOT = re.compile(r"(?<!\\):not\((?:[^()]|\([^()]*\))*\)", re.I)
_STATE = re.compile(r"(?<!\\):(hover|focus|focus-within|focus-visible|active|visited|target|target-within)\b", re.I)
_GENERATED = re.compile(r"(?<!\\)(?:::?(?:before|after|first-line|first-letter|marker|placeholder|selection|backdrop|"
                        r"file-selector-button|cue|spelling-error|grammar-error|target-text|highlight)\b|"
                        r"::(?:-webkit-|-moz-|-ms-))", re.I)     # vendor pseudo-CLASSES are not skipped
# HTML attributes whose values selectors match case-insensitively (HTML spec, "case-sensitivity of selectors")
CI_ATTRS = set("accept accept-charset align alink axis bgcolor charset checked clear codetype color compact declare "
               "defer dir direction disabled enctype face frame hreflang http-equiv lang language link media method "
               "multiple nohref noresize noshade nowrap readonly rel rev rules scope scrolling selected shape target "
               "text type valign valuetype vlink".split())


class Compound:
    __slots__ = ("tag", "ids", "classes", "attrs")

    def __init__(self, tag, ids, classes, attrs):
        self.tag, self.ids, self.classes, self.attrs = tag, ids, classes, attrs

    def match(self, node) -> bool:
        if node.tag == "#root" or (self.tag and self.tag != "*" and node.tag != self.tag):
            return False
        a = node.attrs
        if self.ids and a.get("id") not in self.ids:
            return False
        if self.classes and not self.classes <= node.classes:
            return False
        for name, op, val, ci in self.attrs:
            if name not in a:
                return False
            if op is not None:
                ci = ci or name in CI_ATTRS
                have = a[name].lower() if ci else a[name]
                if not _ATTR_OPS[op](have, val.lower() if ci else val):
                    return False
        return True


def parse_compound(s: str, quirks: bool = False):
    m = _COMPOUND.match(s)
    if not m:
        return None
    rest = m.group("rest")
    ids = {_unescape(x) for x in re.findall(rf"#({IDENT})", re.sub(r"\[[^\]]*\]", "", rest))}
    classes = {_unescape(x) for x in re.findall(rf"\.({IDENT})", re.sub(r"\[[^\]]*\]", "", rest))}
    attrs = []
    for body in re.findall(r"\[([^\]]*)\]", rest):
        mm = _ATTR.match(body)
        if not mm:
            return None
        name, op, v1, v2, v3, flag = mm.groups()
        attrs.append((name.lower(), op, next((v for v in (v1, v2, v3) if v is not None), None),
                      bool(flag and flag in "iI")))
    if quirks:                                          # quirks mode: class and id match case-insensitively
        ids, classes = {x.lower() for x in ids}, {x.lower() for x in classes}
    return Compound(_unescape(m.group("tag") or "").lower() or None, ids, classes, attrs)


class Selector:
    """parts[-1] matches the node; parts[i] relates to parts[i + 1] by combs[i] (" ", ">", "+", "~")."""
    __slots__ = ("parts", "combs", "spec")

    def __init__(self, parts, combs, spec=None):
        self.parts, self.combs = parts, combs
        self.spec = spec or (sum(len(p.ids) for p in parts), sum(len(p.classes) + len(p.attrs) for p in parts),
                             sum(1 for p in parts if p.tag and p.tag != "*"))

    @property
    def key(self):
        last = self.parts[-1]
        if last.ids:
            return ("id", next(iter(last.ids)))
        if last.classes:
            return ("class", next(iter(last.classes)))
        if last.tag and last.tag != "*":
            return ("tag", last.tag)
        return ("any", "")

    def match(self, node, memo: dict) -> bool:
        if len(self.parts) == 1:
            return self.parts[0].match(node)
        return self._at(len(self.parts) - 1, node, memo)

    def _at(self, i, node, memo) -> bool:
        """parts[i] matches node and parts[:i] match in the right relation. Memoised per (selector, i, node), and
        "some ancestor / earlier sibling matches" is memoised along the chain, so long chains stay linear."""
        key = (id(self), i, id(node))
        if key not in memo:
            memo[key] = self.parts[i].match(node) and (i == 0 or self._left(i, node, memo))
        return memo[key]

    def _left(self, i, node, memo) -> bool:
        comb = self.combs[i - 1]
        if comb in (">", "+"):
            nxt = node.parent if comb == ">" else node.prev
            return nxt is not None and self._at(i - 1, nxt, memo)
        step = (lambda n: n.parent) if comb == " " else (lambda n: n.prev)
        chain, cur = [], step(node)                 # "cur or something before it matches parts[i - 1]"
        while cur is not None and (id(self), i, id(cur), comb) not in memo:
            chain.append(cur)
            cur = step(cur)
        acc = memo[(id(self), i, id(cur), comb)] if cur is not None else False
        for x in reversed(chain):
            acc = acc or self._at(i - 1, x, memo)
            memo[(id(self), i, id(x), comb)] = acc
        return acc


_ANY = None


def _universal(fuzzy=True):
    return Selector([Compound("*", set(), set(), [])], []), fuzzy


def parse_selector(s: str, quirks: bool = False):
    """-> (Selector, fuzzy) or None (skipped). fuzzy: the selector matches a superset of the elements (pseudo-
    classes removed; a selector that cannot be parsed, or is invalid, matches every element)."""
    s = s.strip()
    if len(s) > MAX_SELECTOR:
        return _universal()
    m = re.fullmatch(r"(html)?:root", s, re.I)
    if m:                                               # the root element, with :root's specificity
        return Selector([Compound("html", set(), set(), [])], [], (0, 1, 1 if m.group(1) else 0)), False
    if not s or _STATE.search(_NOT.sub("", s)) or _GENERATED.search(s):
        return None
    stripped = _PSEUDO.sub("", s)
    fuzzy = stripped != s
    parts, combs, pending, pos, explicit = [], [], None, 0, False
    for m in _TOKEN.finditer(stripped):
        if m.start() != pos:                            # a character no token covers: invalid selector
            return _universal()
        pos = m.end()
        if m.group(1) or m.group(2):
            if m.group(1):
                if explicit or not parts:               # "> >" or a leading combinator: invalid
                    return _universal()
                explicit = True
            pending = m.group(1) or pending or " "
            continue
        c = parse_compound(m.group(3), quirks)
        if c is None:                                   # cannot parse it: may hide anything, never show
            return _universal()
        if parts:
            combs.append(pending or " ")
        parts.append(c)
        pending, explicit = None, False
    if pos != len(stripped) or explicit:                # trailing combinator or leftover characters
        return _universal()
    if not parts:
        if not fuzzy:
            return None
        parts = [Compound("*", set(), set(), [])]       # e.g. ":hover" stripped, ":not(.x)" alone: every element
    return Selector(parts, combs), fuzzy


_TOKEN = re.compile(rf"\s*([>+~])\s*|(\s+)|((?:[^\s>+~\[\]\\]|{ESC}|\[[^\]]*\])+)")


_SKIP_AT = re.compile(r"@(-[\w]+-)?(font-face|keyframes|page|counter-style|property|font-feature-values|"
                      r"font-palette-values|view-transition|import|charset|namespace)\b|@media\s+(only\s+)?print\s*$",
                      re.I)


_IMPORT = re.compile(r"""@import\s*(?:url\(\s*(?:"([^"\\\n]*)"|'([^'\\\n]*)'|([^\s()'"\\]*))\s*\)|"([^"\\\n]*)"|'([^'\\\n]*)')""",
                     re.I)


def imports(css: str):
    """The @import rules a browser follows: [(url, condition)] in order, read from the top of the sheet until the
    first other rule (later @imports are ignored by browsers). condition is the text after the URL (media query,
    layer(), supports()). A rule that cannot be read (escapes, odd syntax) raises Refused: it could load a sheet."""
    css, out, i = _strip_comments(css), [], 0
    while True:
        while True:                                       # whitespace and the CDO / CDC tokens
            while i < len(css) and css[i].isspace():
                i += 1
            if not css.startswith(("<!--", "-->"), i):
                break
            i += 4 if css.startswith("<!--", i) else 3
        low = css[i:i + 8].lower()
        if low.startswith(("@charset", "@layer")):
            j, k = css.find(";", i), css.find("{", i)
            if j < 0 or 0 <= k < j:                       # @layer x { ... } is a rule: imports end here
                return out
            i = j + 1
        elif low.startswith("@import"):
            j = css.find(";", i)
            stmt = css[i:j if j >= 0 else len(css)]
            m = _IMPORT.match(stmt)
            if not m or "{" in stmt or len(out) >= limits.MAX_STYLESHEETS:
                raise limits.Refused("a stylesheet has an @import that cannot be followed")
            url = next(g for g in m.groups() if g is not None)
            out.append((url.strip(), stmt[m.end():].strip()))
            if j < 0:
                return out
            i = j + 1
        else:
            return out


def _strip_comments(css: str) -> str:
    out, i = [], 0
    while (j := css.find("/*", i)) >= 0:
        out.append(css[i:j])
        k = css.find("*/", j + 2)
        if k < 0:
            return "".join(out)
        i = k + 2
    out.append(css[i:])
    return "".join(out)


def _blocks(css: str):
    """-> ([(prelude, body)], own): the top-level blocks in one pass over the braces (linear; quoted strings are
    skipped), and the text outside them (a style rule's own declarations, when it holds nested rules). An
    unclosed block runs to the end, as in a browser."""
    out, own, depth, start, head, prelude = [], [], 0, 0, 0, ""
    for m in re.finditer(r'"(?:[^"\\\n]|\\.)*"?|\'(?:[^\'\\\n]|\\.)*\'?|[{}]', css):
        if m.group() == "{":
            if depth == 0:
                prelude, start = css[head:m.start()], m.end()
            depth += 1
            if depth > MAX_NESTING:
                raise limits.Refused("a stylesheet is nested too deeply")
        elif m.group() == "}" and depth:
            depth -= 1
            if depth == 0:
                pre, _, sel = prelude.rpartition(";")        # "@import x; p" or "color: red; .nested"
                own.append(pre)
                out.append((sel.strip(), css[start:m.start()]))
                head = m.end()
        elif m.group() == "}":
            head = m.end()                                  # a stray "}"
    if depth:
        pre, _, sel = prelude.rpartition(";")
        own.append(pre)
        out.append((sel.strip(), css[start:]))
    else:
        own.append(css[head:])
    return out, ";".join(own)


MAX_NESTING = 32


def _nest(parent: str, child: str) -> str:
    """CSS nesting: "&" stands for the parent selector; without one the child is a descendant."""
    return child.replace("&", parent.strip()) if "&" in child else f"{parent.strip()} {child.strip()}"


UNLAYERED = 1 << 30
SCREEN = {"width": 1280.0, "height": 800.0}     # the one screen @media is evaluated for


def _media_feature(f: str):
    """One "(feature: value)" test -> True / False, or None when it cannot be evaluated."""
    name, colon, val = (x.strip() for x in f.partition(":"))
    if not colon:
        return {"color": True, "hover": True, "pointer": True, "any-hover": True, "any-pointer": True,
                "monochrome": False, "grid": False}.get(name)
    for pre, cmp in (("min-", lambda a, b: a >= b), ("max-", lambda a, b: a <= b), ("", lambda a, b: a == b)):
        for dim in ("width", "height", "device-width", "device-height"):
            if name == pre + dim:
                px = length_px(val)
                return None if px is None else cmp(SCREEN[dim.replace("device-", "")], px)
    fixed = {"prefers-color-scheme": "light", "orientation": "landscape", "hover": "hover", "any-hover": "hover",
             "pointer": "fine", "any-pointer": "fine", "prefers-reduced-motion": "no-preference",
             "prefers-contrast": "no-preference", "forced-colors": "none", "scripting": "enabled",
             "display-mode": "browser", "update": "fast", "inverted-colors": "none"}
    if name in fixed:
        return val == fixed[name]
    m = re.fullmatch(r"(?:-webkit-)?(min-|max-)?(?:device-pixel-ratio|resolution)", name.replace(
        "-webkit-max-", "max-").replace("-webkit-min-", "min-"))
    if m:
        try:
            n = float(re.sub(r"(dppx|x)$", "", val)) if "dpi" not in val else float(val[:-3]) / 96
        except ValueError:
            return None
        return {"min-": 1.0 >= n, "max-": 1.0 <= n}.get(m.group(1) or "", 1.0 == n)
    return None


def media_matches(q: str):
    """A media query list -> True / False, or None when it cannot be evaluated for the fixed screen."""
    q = " ".join(q.strip().lower().split())
    if not q:
        return True
    results = []
    for part in _split_list(q):
        part = part.strip()
        neg = part.startswith("not ")
        part = re.sub(r"^(not|only)\s+", "", part)
        m = re.match(r"([a-z-]+)(?:\s+and\s+|$)", part)
        ok = True
        if m and not part.startswith("("):
            ok = {"all": True, "screen": True}.get(m.group(1), False)
            part = part[m.end():]
        feats = re.findall(r"\(([^()]*)\)", part)
        if re.sub(r"\([^()]*\)|\band\b|\s", "", part):  # "or", nesting, ranges...: not evaluated
            results.append(None)
            continue
        for f in feats:
            r = _media_feature(f)
            ok = None if r is None or ok is None else (ok and r)
        results.append(None if ok is None else ok != neg)
    if any(r is True for r in results):
        return True
    return False if all(r is False for r in results) else None


def parse_stylesheet(css: str, quirks: bool = False, fuzzy: bool = False, layers: dict | None = None) -> list[tuple]:
    """-> [(Selector, fuzzy, normal decls, !important decls, layer rank)] in source order. Nested at-rule and
    nested style rule bodies are walked with an explicit stack, each with its context: inside a condition that
    cannot be evaluated the rules are fuzzy (may hide, never show); inside a false @media they are skipped.
    Nesting deeper than MAX_NESTING is a reject (checked in the first pass, so the work stays linear)."""
    css = _strip_comments(css)
    layers = {} if layers is None else layers           # shared by every sheet of one page
    for m in re.finditer(r"@layer\s+([^{};]*?)\s*([;{])", css):     # layer order: first appearance
        for name in m.group(1).split(","):
            if name.strip():
                layers.setdefault(name.strip(), len(layers))
    rules = []
    stack = [(iter(_blocks(css)[0]), None, (fuzzy, UNLAYERED))]
    while stack:
        it, parent, ctx = stack[-1]
        nxt = next(it, None)
        if nxt is None:
            stack.pop()
            continue
        prelude, body = nxt
        if prelude.startswith("@"):
            if _SKIP_AT.match(prelude):
                continue
            kind = re.match(r"@([\w-]*)", prelude).group(1).lower()
            if kind == "media":
                hit = media_matches(prelude[6:])
                if hit is False:
                    continue
                nctx = (ctx[0] or hit is None, ctx[1])
            elif kind == "layer":
                name = prelude[6:].strip() or f"#anonymous{len(layers)}"
                nctx = (ctx[0], layers.setdefault(name, len(layers)))
            else:                                           # @supports, @container, @scope, unknown: not evaluated
                nctx = (True, ctx[1])
            inner, own = _blocks(body)
            stack.append((iter(inner), parent, nctx))
            if parent is not None:                          # declarations directly in a nested at-rule
                _add(rules, parent, own, nctx, quirks)
            continue
        sels = _split_list(prelude) if parent is None else [_nest(p, c) for p in parent for c in _split_list(prelude)]
        inner, own = _blocks(body)
        if inner:                                           # nested rules (and at-rules) in a style rule
            stack.append((iter(inner), sels, ctx))
        _add(rules, sels, own, ctx, quirks)
    return rules


def _add(rules, sels, own, ctx, quirks):
    normal, imp = parse_decls(own)
    normal = {k: v for k, v in normal.items() if k in RELEVANT or k.startswith("--")}
    imp = {k: v for k, v in imp.items() if k in RELEVANT or k.startswith("--")}
    if not normal and not imp:
        return
    for sel in sels:
        got = parse_selector(sel, quirks)
        if got is not None:
            rules.append((got[0], got[1] or ctx[0], normal, imp, ctx[1]))


def _split_list(prelude: str) -> list[str]:
    """Split a selector list on commas that are not inside parentheses or brackets."""
    if "(" not in prelude and "[" not in prelude:
        return prelude.split(",")
    out, depth, cur = [], 0, []
    for ch in prelude:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    out.append("".join(cur))
    return out


class RuleIndex:
    MAX_WORK = 20_000_000                           # selector tests per page; more is a reject (quadratic input)

    def __init__(self, rules):
        self.by: dict = {}
        self.memo: dict = {}
        self.work = 0
        for order, (sel, fuzzy, normal, imp, rank) in enumerate(rules):
            self.by.setdefault(sel.key, []).append((sel.spec, order, sel, fuzzy, normal, imp, rank))

    MEMO_ENTRIES = 500_000                          # the match cache is only a cache: bounded, cleared when full

    def _cands(self, node):
        if len(self.memo) > self.MEMO_ENTRIES:
            self.memo.clear()
        cands = list(self.by.get(("any", ""), []))
        cands += self.by.get(("tag", node.tag), [])
        if node.attrs.get("id"):
            cands += self.by.get(("id", node.attrs["id"]), [])
        for c in node.classes:
            cands += self.by.get(("class", c), [])
        self.work += len(cands)
        if self.work > self.MAX_WORK:
            raise limits.Refused("the page's stylesheets are too costly to apply")
        return [c for c in cands if c[2].match(node, self.memo)]

    def styles_for(self, node, inline: str = "") -> tuple[dict, list[dict]]:
        """-> (the cascaded declarations, [declarations of fuzzy rules that match a superset of the node]).
        Normal declarations: later layers beat earlier ones and unlayered rules beat all layers; !important
        reverses the layer order."""
        exact, fuzzy = [], []
        for c in self._cands(node):
            (fuzzy if c[3] else exact).append(c)
        own, own_imp = parse_decls(inline) if inline else ({}, {})
        out = {}
        for c in sorted(exact, key=lambda x: (x[6], x[0], x[1])):
            out.update(c[4])
        out.update(own)
        for c in sorted(exact, key=lambda x: (-x[6], x[0], x[1])):
            out.update(c[5])
        out.update(own_imp)
        return out, [{**c[4], **c[5]} for c in sorted(fuzzy, key=lambda x: (x[0], x[1]))]
