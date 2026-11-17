"""HTML: visible text only, from inline styles, <style> blocks and linked stylesheets.

Static analysis only: no script is ever fetched or run. Linked stylesheets come as bytes from fetch_resource
(the worker host supplies them); without one, or when a sheet is missing, the page is a reject. Inline <svg> is dropped whole (its text is not trusted as visible), but a <style> in it applies to the page, as in a browser. @import rules are followed like links.

Hidden text falls into three classes, all left out of safe_text and counted:
  stealth    font-size 0, transparent / same-as-background colour, off-screen, scale(0): the classic tricks
             for showing text to crawlers and LLMs but not to people.
  collapsed  display:none, visibility:hidden, [hidden], <template>: menus, tabs, modals; common and
             usually legitimate.
  sr_only    the 1px "screen-reader only" accessibility pattern.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin

from .. import limits
from ..content import content_findings, contrast, hidden_text_finding
from ..findings import Finding, Report
from . import css as C

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
AUTOCLOSE = {"p": {"p", "div", "ul", "ol", "table", "h1", "h2", "h3", "h4", "h5", "h6", "section"},
             "li": {"li"}, "option": {"option"}, "td": {"td", "th", "tr"}, "th": {"td", "th", "tr"},
             "tr": {"tr"}, "dt": {"dt", "dd"}, "dd": {"dt", "dd"}}
BLOCK = {"p", "div", "section", "article", "header", "footer", "main", "aside", "nav", "li", "ul", "ol", "table",
         "tr", "td", "th", "h1", "h2", "h3", "h4", "h5", "h6", "br", "hr", "blockquote", "pre", "dl", "dt", "dd",
         "figure", "figcaption", "form", "fieldset", "address", "title", "caption"}
MAX_IMPORT_DEPTH = 4
SKIP = ("script", "style", "noscript", "svg", "head")      # never part of the visible body (title is added apart)
# Hidden by the browser's own stylesheet or by what the element is: fallback content of embedded things, ruby
# fallback parentheses, a <title> outside <head>. Counted as collapsed. Also: <dialog> without `open`, and
# everything but the first <summary> of a <details> without `open`.
ACTIVE_URL = ("javascript:", "vbscript:", "data:text/html", "data:application", "data:image/svg")   # run script
URL_ATTRS = ("href", "src", "action", "formaction", "data", "xlink:href", "srcdoc")
UA_HIDDEN = {"title", "noembed", "noframes", "iframe", "frame", "frameset", "video", "audio", "object", "embed",
             "applet", "rp", "datalist", "param", "canvas"}


class Node:
    __slots__ = ("tag", "attrs", "children", "parent", "classes", "prev")

    def __init__(self, tag, attrs, parent):
        self.tag, self.parent, self.children = tag, parent, []
        # the previous element sibling (for the + and ~ combinators)
        self.prev = next((c for c in reversed(parent.children) if isinstance(c, Node)), None) if parent else None
        self.attrs = {}
        for k, v in attrs:                      # a repeated attribute: the FIRST one counts, as in a browser
            self.attrs.setdefault(k.lower(), v if v is not None else "")
        self.classes = set(self.attrs.get("class", "").split())


# An end tag never closes an element outside the nearest one of these (the HTML "has an element in scope" rule).
SCOPE = {"td", "th", "table", "caption", "html", "template", "marquee", "object", "applet"}
RAWTEXT = ("script", "style")


class _Builder(HTMLParser):
    def __init__(self, quirks: bool = False):
        super().__init__(convert_charrefs=True)
        self.root = Node("#root", [], None)
        self.stack = [self.root]
        self.open: dict[str, int] = {}          # open elements per tag: an end tag with none open is O(1)
        self.comments: list[str] = []
        self.quirks = quirks

    def _push(self, n):
        self.stack.append(n)
        self.open[n.tag] = self.open.get(n.tag, 0) + 1

    def _pop_to(self, i):
        for n in self.stack[i:]:
            self.open[n.tag] -= 1
        del self.stack[i:]

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        closers = {t for t, trig in AUTOCLOSE.items() if tag in trig and not (t == "p" and tag == "table"
                                                                              and self.quirks)}
        while len(self.stack) > 1 and self.stack[-1].tag in closers:
            self._pop_to(len(self.stack) - 1)
        n = Node(tag, attrs, self.stack[-1])
        self.stack[-1].children.append(n)
        if tag not in VOID:
            self._push(n)

    def handle_startendtag(self, tag, attrs):
        # "/>" means nothing on an HTML element that is not void: it is an ordinary start tag
        self.handle_starttag(tag, attrs)
        if tag.lower() in RAWTEXT:
            self.set_cdata_mode(tag.lower())

    def handle_endtag(self, tag):
        tag = tag.lower()
        if not self.open.get(tag):
            return
        for i in range(len(self.stack) - 1, 0, -1):
            t = self.stack[i].tag
            if t == tag:
                self._pop_to(i)
                return
            if t in SCOPE:                      # e.g. </div> inside a table cell does not close the outer div
                return

    def handle_data(self, data):
        if data:
            self.stack[-1].children.append(data)

    def handle_comment(self, data):
        self.comments.append(data)


def parse(html: str, quirks: bool = False):
    """A parser failure is a reject: a partial tree could drop a later <style> that hides earlier text."""
    b = _Builder(quirks)
    try:
        b.feed(html)
        b.close()
    except Exception as e:
        raise limits.Refused(f"HTML could not be parsed ({type(e).__name__})") from None
    for n in iter_nodes(b.root):
        if n.tag == "frameset":                 # a browser shows the frames, never the rest of the page
            raise limits.Refused("HTML frameset pages are not accepted")
        if n.tag == "script":
            code = node_text(n)
            if "<!--" in code and re.search(r"<script[\s/>]", code, re.I):
                # "script data double escaped": a browser keeps reading script past the first </script>
                raise limits.Refused("a script that a browser parses differently is not accepted")
    _implicit_body(b.root)
    return b.root, b.comments


def _implicit_body(root) -> None:
    """A page without <body> still has one in the browser (body rules apply to its text): make it explicit."""
    if any(n.tag == "body" for n in iter_nodes(root)):
        return
    html = next((c for c in root.children if isinstance(c, Node) and c.tag == "html"), root)
    keep = [c for c in html.children if isinstance(c, Node) and c.tag == "head"]
    body = Node("body", [], None)
    body.parent = html
    body.children = [c for c in html.children if not (isinstance(c, Node) and c.tag == "head")]
    for c in body.children:
        if isinstance(c, Node):
            c.parent = body
    html.children = keep + [body]


def iter_nodes(root):
    st = [root]
    while st:
        n = st.pop()
        yield n
        st.extend(c for c in reversed(n.children) if isinstance(c, Node))


def node_text(n) -> str:
    out, st = [], [n]
    while st:
        x = st.pop()
        if isinstance(x, str):
            out.append(x)
        else:
            st.extend(reversed(x.children))
    return "".join(out)


# --------------------------------------------------------------------------- visibility


class _State:
    __slots__ = ("collapsed", "stealth", "sr_only", "opacity", "font", "color", "bg", "visibility", "clip_text",
                 "vars")

    def __init__(self):
        self.collapsed = self.stealth = self.sr_only = None
        self.opacity, self.font = 1.0, 16.0
        self.color = (0, 0, 0, 1.0)
        self.bg = "default"          # "default" (white), "unknown", an rgba tuple, or a list of them (gradient)
        self.visibility = "visible"
        self.clip_text = False       # background-clip: text over a background image: transparent colour intended
        self.vars = {}               # custom properties (--x), inherited

    def child(self):
        s = _State.__new__(_State)
        for k in _State.__slots__:
            setattr(s, k, getattr(self, k))
        return s


FONT_SIZES = {"1": "10px", "2": "13px", "3": "16px", "4": "18px", "5": "24px", "6": "32px", "7": "48px"}


def _legacy_color(v: str) -> str:
    v = v.strip()
    return "#" + v if re.fullmatch(r"[0-9a-fA-F]{3}|[0-9a-fA-F]{6}", v) else v


def _hints(node) -> dict:
    """Presentational HTML attributes, as the CSS a browser maps them to (author CSS overrides them)."""
    a, out = node.attrs, {}
    if node.tag == "font":
        if a.get("color"):
            out["color"] = _legacy_color(a["color"])
        if a.get("size"):
            sz = a["size"].strip()
            out["font-size"] = FONT_SIZES.get(sz, "16px" if not re.fullmatch(r"[+-]?\d+", sz) else
                                              FONT_SIZES[str(max(1, min(7, 3 + int(sz) if sz[0] in "+-" else int(sz))))])
    if node.tag == "body" and a.get("text"):
        out["color"] = _legacy_color(a["text"])
    if node.tag in ("body", "table", "tr", "td", "th") and a.get("bgcolor"):
        out["background-color"] = _legacy_color(a["bgcolor"])
    return out


def _resolve_vars(st: _State, decl: dict) -> dict:
    """Custom properties: --x declarations join the inherited set; var(--x, fallback) in a value is replaced.
    A var() that cannot be resolved makes the declaration invalid at computed-value time: it is dropped."""
    custom = {k: v for k, v in decl.items() if k.startswith("--")}
    if custom:
        st.vars = {**st.vars, **custom}
    out = {}
    for k, v in decl.items():
        if k.startswith("--"):
            continue
        for _ in range(8):
            if "var(" not in v:
                break
            v = re.sub(r"var\(\s*(--[\w-]+)\s*(?:,([^()]*))?\)",
                       lambda m: st.vars.get(m.group(1), m.group(2) if m.group(2) is not None else "\x00"), v)
        if "var(" in v or "\x00" in v or (k in C.RELEVANT and not C.valid_value(k, v)):
            continue
        out[k] = v.strip()
    return out


def _angle(t: str):
    m = re.fullmatch(r"(" + C._NUM + r")(deg|rad|turn|grad)?", t.strip())
    if not m:
        return None
    n = float(m.group(1))
    return {"deg": n, None: n, "rad": n * 57.29578, "turn": n * 360, "grad": n * 0.9}[m.group(2)] % 360


def _transform_hides(tr: str) -> bool:
    """A transform that leaves nothing to see: scaled to (near) zero, a singular matrix, turned edge-on."""
    for fn, args in re.findall(r"([a-z0-9]+)\(([^()]*)\)", tr.lower()):
        parts = [p for p in re.split(r"[\s,]+", args) if p]
        try:
            if fn in ("scale", "scalex", "scaley", "scale3d"):
                nums = [C._num(p, 1.0) for p in parts[:2 if fn != "scale3d" else 3]]
                if any(abs(n) <= 0.05 for n in nums):
                    return True
            elif fn == "matrix" and len(parts) == 6:
                a, b, c, d = (float(x) for x in parts[:4])
                if abs(a * d - b * c) < 0.01:
                    return True
            elif fn == "matrix3d" and len(parts) == 16:
                m = [float(x) for x in parts]
                if abs(m[0] * m[5] - m[1] * m[4]) < 0.01:
                    return True
            elif fn in ("rotatex", "rotatey"):
                a = _angle(parts[0])
                if a is not None and (abs(a - 90) < 1 or abs(a - 270) < 1):
                    return True
        except (ValueError, IndexError):
            continue
    return False


def _box(v: str, base: float):
    """A 1-4 value box shorthand (margin, inset) -> [top, right, bottom, left] in px (None where not a length)."""
    t = [C.length_px(x, base) for x in v.split()][:4]
    if not t:
        return [None] * 4
    t += [None] * (4 - len(t))
    top, right, bottom, left = t
    right = t[0] if len(v.split()) == 1 else right
    bottom = t[0] if len(v.split()) < 3 else bottom
    left = right if len(v.split()) < 4 else left
    return [top, right, bottom, left]


def _font_size(v: str):
    """The size in the font shorthand: the first token with a unit (or 0), before an optional '/line-height'."""
    for tok in v.split():
        tok = tok.split("/", 1)[0]
        if tok and (tok == "0" or C.length_px(tok) is not None and re.search(r"[a-z%]", tok)):
            return tok
    return None


def _apply(st: _State, node: Node, decl: dict) -> None:
    if "hidden" in node.attrs and node.tag not in ("input",):
        st.collapsed = st.collapsed or "hidden_attribute"
    if "popover" in node.attrs:
        st.collapsed = st.collapsed or "popover"
    if node.tag == "template":
        st.collapsed = st.collapsed or "template"
    if node.tag in UA_HIDDEN:
        st.collapsed = st.collapsed or "hidden_by_browser"
    if node.tag == "dialog" and "open" not in node.attrs:
        st.collapsed = st.collapsed or "closed_dialog"
    d = decl.get("display", "").lower()
    if d == "none":
        st.collapsed = st.collapsed or "display_none"
    if decl.get("content-visibility", "").strip().lower() == "hidden":
        st.collapsed = st.collapsed or "content_visibility"
    if any(k in decl for k in ("-webkit-line-clamp", "line-clamp")) and decl.get(
            "-webkit-line-clamp", decl.get("line-clamp", "")).strip().lower() not in ("none", "unset", "initial"):
        st.collapsed = st.collapsed or "line_clamp"           # lines past the clamp are not shown
    v = decl.get("visibility", "").lower()
    if v in ("hidden", "collapse", "visible"):
        st.visibility = v
    for k in ("opacity",):
        if k in decl:
            try:
                st.opacity *= max(0.0, min(1.0, C._num(decl[k], 1.0)))
            except ValueError:
                pass
    m = re.search(r"opacity\(\s*([^()\s]+)\s*\)", decl.get("filter", ""), re.I)
    if m:
        try:
            st.opacity *= max(0.0, min(1.0, C._num(m.group(1), 1.0)))
        except ValueError:
            pass
    zoom = decl.get("zoom", "").strip()
    if zoom:
        try:
            z = C._num(zoom, 1.0)
            if 0 <= z <= 0.05:
                st.stealth = st.stealth or "scaled_to_zero"
            elif z > 0:
                st.font *= z
        except ValueError:
            pass
    fs = decl.get("font-size")
    if fs is None and "font" in decl:
        fs = _font_size(decl["font"])
    if fs:
        px = C.length_px(fs, st.font)
        if px is not None:
            st.font = px
    col = decl.get("color")
    if col and col.strip().lower() not in ("inherit", "currentcolor"):
        st.color = C.parse_color(col)
    bimg = decl.get("background-image", "") + " " + decl.get("background", "")
    bgv = decl.get("background-color") or decl.get("background")
    if bgv:
        c = C.first_color(bgv)
        if c is None:
            if bgv.strip().lower() not in ("none", "inherit", "initial", "unset"):
                st.bg = "unknown"
        elif c[3] >= 0.5:
            st.bg = c
    if "gradient" in bimg.lower():                            # judge text against every colour stop
        stops = [C.parse_color(t) for t in re.findall(r"#[0-9a-fA-F]{3,8}|\b[a-z]+\([^()]{0,200}\)|\b[a-z]+\b",
                                                       bimg[bimg.lower().index("gradient") + 9:])]
        stops = [c for c in stops if c is not None and c[3] >= 0.5]
        st.bg = stops or "unknown"
    elif "url(" in bimg.lower():
        st.bg = "unknown"
    has_image = "gradient" in bimg.lower() or "url(" in bimg.lower()
    if "text" in (decl.get("background-clip", "") + decl.get("-webkit-background-clip", "")).lower():
        st.clip_text = has_image                              # gradient text paints only with an image
    tf = decl.get("-webkit-text-fill-color")
    if tf and not st.clip_text and tf.strip().lower() not in ("currentcolor", "inherit"):
        c = C.parse_color(tf)
        if c is not None:
            st.color = c
    pos = decl.get("position", "").lower()
    if pos in ("absolute", "fixed", "relative", "sticky"):
        offs = [C.length_px(decl.get(k, "x"), st.font) for k in ("left", "top", "right", "bottom")]
        offs += _box(decl.get("inset", ""), st.font)
        if any(px is not None and px <= -500 for px in offs):
            st.stealth = st.stealth or "off_screen"
    margins = [C.length_px(decl.get(k, "x"), st.font) for k in ("margin-left", "margin-top")]
    margins += [x for i, x in enumerate(_box(decl.get("margin", ""), st.font)) if i in (0, 3)]
    if any(px is not None and px <= -500 for px in margins):
        st.stealth = st.stealth or "off_screen"
    ls = C.length_px(decl.get("letter-spacing", "x"), st.font)
    if ls is not None and ls <= -0.4 * st.font:                # every glyph drawn on (nearly) one spot
        st.stealth = st.stealth or "glyphs_piled"
    ti = C.length_px(decl.get("text-indent", "x"), st.font)
    if ti is not None and ti <= -500:
        st.stealth = st.stealth or "off_screen"
    tr = decl.get("transform", "")
    if _transform_hides(tr) or _transform_hides(f"scale({decl.get('scale', '1')})".replace(" ", ",", 1)):
        st.stealth = st.stealth or "scaled_to_zero"
    if decl.get("backface-visibility", "").strip().lower() == "hidden" and re.search(r"rotate[xy]?\(", tr, re.I):
        for a in re.findall(r"rotate[xy]\(([^()]*)\)", tr, re.I):
            ang = _angle(a)
            if ang is not None and 90 < ang < 270:
                st.stealth = st.stealth or "scaled_to_zero"   # turned away, back face hidden
    for k in ("mask", "mask-image", "-webkit-mask", "-webkit-mask-image"):
        if decl.get(k, "none").strip().lower() not in ("none", "", "initial", "unset", "inherit"):
            st.stealth = st.stealth or "masked"
    moves = re.findall(r"translate(?:[xyz]|3d)?\(([^)]*)\)", tr, re.I) + [decl.get("translate", "")]
    for v in (x for arg in moves for x in re.split(r"[\s,]+", arg) if x):
        px = C.length_px(v, st.font)
        if px is not None and (px <= -500 or px >= 10000):
            st.stealth = st.stealth or "off_screen"
    clipv = decl.get("clip", "").lower()
    cpath = decl.get("clip-path", "").lower()
    rect = re.search(r"rect\(([^()]*)\)", clipv)
    if rect:
        r = [C.length_px(x, st.font) for x in re.split(r"[\s,]+", rect.group(1).strip()) if x]
        if len(r) == 4 and None not in r and (r[2] - r[0] <= 1 or r[1] - r[3] <= 1):
            st.sr_only = st.sr_only or "screen_reader_only"
    m = re.search(r"inset\(([^()]*)\)", cpath)
    if m and any((x.endswith("%") and C._num(x, 1.0) >= 0.5) for x in re.split(r"[\s,]+", m.group(1)) if
                 re.fullmatch(C._NUM + "%", x)):
        st.sr_only = st.sr_only or "screen_reader_only"
    if re.search(r"(circle|ellipse)\(\s*0", cpath):
        st.sr_only = st.sr_only or "screen_reader_only"
    tiny_box = any((C.length_px(decl.get(k, "x"), st.font) or 99) <= 1 for k in ("width", "height"))
    overflow = " ".join(decl.get(k, "") for k in ("overflow", "overflow-x", "overflow-y")).lower()
    overflow_hidden = any(w in overflow for w in ("hidden", "clip", "scroll", "auto"))
    if tiny_box and overflow_hidden and pos in ("absolute", "fixed"):
        st.sr_only = st.sr_only or "screen_reader_only"
    for k in ("height", "max-height", "width", "max-width"):
        px = C.length_px(decl.get(k, "x"), st.font)
        if px is not None and px <= 0 and overflow_hidden:
            st.collapsed = st.collapsed or "zero_size_box"


def _classify(st: _State):
    if st.collapsed:
        return "collapsed", st.collapsed
    if st.visibility in ("hidden", "collapse"):
        return "collapsed", "visibility_hidden"
    if st.opacity <= 0.05:
        return "stealth", "transparent"
    if st.stealth:
        return "stealth", st.stealth
    if st.font <= 1.0:
        return "stealth", "zero_font"
    if st.color is not None and not st.clip_text:
        alpha = st.color[3] * st.opacity                   # the colour's own alpha and the element's opacity
        if alpha <= 0.05:
            return "stealth", "transparent_color"
        bgs = [(255, 255, 255, 1.0)] if st.bg == "default" else st.bg if isinstance(st.bg, list) else \
            [] if st.bg == "unknown" else [st.bg]
        if bgs and all(contrast(*_painted(st.color, alpha, b)) < 1.15 for b in bgs):
            return "stealth", "same_as_background"
    if st.sr_only:
        return "sr_only", st.sr_only
    return "visible", None


def _painted(color, alpha, bg):
    """(text colour as painted over the background, background), channels 0..1."""
    b = [x / 255 for x in bg[:3]]
    return [x / 255 * alpha + y * (1 - alpha) for x, y in zip(color[:3], b)], b


# --------------------------------------------------------------------------- main entry


QUIRKS_OK = re.compile(r"^\ufeff?\s*(?:<!--.*?-->\s*)*<!doctype\s+html\b", re.I | re.S)


def _inside(n, tags) -> bool:
    p = n.parent
    while p is not None:
        if p.tag in tags:
            return True
        p = p.parent
    return False


def _sheet_mode(n, preferred):
    """None (a browser does not apply it), "exact", or "fuzzy" (may apply: its rules can only hide)."""
    if _inside(n, ("template",)):                       # a <style> inside inline <svg> styles the whole page
        return None
    if n.tag == "style" and n.attrs.get("type", "").strip().lower() not in ("", "text/css"):
        return None
    if n.tag == "link":
        rel = n.attrs.get("rel", "").lower().split()
        if "stylesheet" not in rel or "alternate" in rel or "disabled" in n.attrs or not n.attrs.get("href"):
            return None
    title = n.attrs.get("title", "").strip()
    if title and preferred is not None and title != preferred:      # another (alternate) style set
        return None
    hit = C.media_matches(n.attrs.get("media", ""))
    if hit is False:
        return None
    return "fuzzy" if hit is None or _inside(n, ("noscript",)) else "exact"


def scan_html(raw: bytes | str, name: str = "<bytes>", *, base_url: str | None = None, fetch_resource=None) -> Report:
    html = raw if isinstance(raw, str) else _decode(raw)
    rep = Report(path=name, format="html")
    quirks = not QUIRKS_OK.match(html[:4096])
    root, comments = parse(html, quirks)
    nodes = list(iter_nodes(root))
    if quirks:                                          # class and id match case-insensitively in quirks mode
        for n in nodes:
            n.classes = {c.lower() for c in n.classes}
            if "id" in n.attrs:
                n.attrs["id"] = n.attrs["id"].lower()

    # ---- stylesheets, in document order; links resolve against the first <base href>, as in a browser
    base = next((n.attrs["href"] for n in nodes if n.tag == "base" and n.attrs.get("href", "").strip()), None)
    base_url = urljoin(base_url or "", base.strip()) if base is not None else base_url
    sheet_nodes = [n for n in nodes if n.tag in ("style", "link")]
    meta = next((n.attrs.get("content", "") for n in nodes if n.tag == "meta"
                 and n.attrs.get("http-equiv", "").strip().lower() == "default-style"), "")
    # the preferred style set: the Default-Style meta, else the first titled sheet that applies
    preferred = meta.strip() or next((n.attrs.get("title", "").strip() for n in sheet_nodes
                                      if n.attrs.get("title", "").strip() and _sheet_mode(n, None) is not None), "")
    sheets, links, css_bytes = [], [], [0]

    def get(url):
        """A linked or imported sheet as text; None (and rep.error) when it is missing or over the limits: a sheet
        we cannot read could hide text, so the page is a reject (fail closed)."""
        if url not in links:
            links.append(url)
        data = fetch_resource(url, "text/css") if fetch_resource and len(links) <= limits.MAX_STYLESHEETS else None
        css_bytes[0] += len(data or b"")
        if data is None or css_bytes[0] > limits.MAX_STYLESHEET_BYTES:
            rep.error = (f"linked stylesheet could not be fetched or is over the limits "
                         f"({limits.MAX_STYLESHEETS} files, {limits.MAX_STYLESHEET_BYTES // limits.MB} MB)")
            return None
        return _decode(data)

    def add(text, sheet_url, mode, chain):
        """A sheet with its @import rules first (they come earlier in the cascade), as a browser applies it."""
        for href, cond in C.imports(text):
            url = urljoin(sheet_url or "", href)
            if url in chain:                              # an import loop: a browser skips it
                continue
            if len(chain) >= MAX_IMPORT_DEPTH:
                raise limits.Refused("stylesheets import each other too deeply")
            hit = None if re.search(r"\b(layer|supports)\b", cond, re.I) else C.media_matches(cond)
            if hit is False:
                continue
            sub = get(url)
            if sub is None:
                return False
            if not add(sub, url, "fuzzy" if hit is None else mode, chain + (url,)):
                return False
        sheets.append((text, mode))
        return True

    seen = set()
    for n in sheet_nodes:
        mode = _sheet_mode(n, preferred)
        if mode is None:
            continue
        if n.tag == "style":
            text = node_text(n)
            if _inside(n, ("svg",)):                     # SVG (XML) content: CDATA is markup, entities are decoded
                m = re.fullmatch(r"\s*<!\[CDATA\[(.*)\]\]>\s*", text, re.S)
                text = m.group(1) if m else text
                if "<" in text or "&" in text:
                    rep.error = "a <style> inside <svg> uses markup or character references, which is not accepted"
                    return rep
            if not add(text, base_url, mode, ()):
                return rep
            continue
        url = urljoin(base_url or "", n.attrs["href"].strip())
        if url in seen:                                   # each URL once, however often it is linked
            continue
        seen.add(url)
        text = get(url)
        if text is None or not add(text, url, mode, (url,)):
            return rep
    layers: dict = {}
    rules = [r for text, mode in sheets for r in C.parse_stylesheet(text, quirks, mode == "fuzzy", layers)]
    rules = C.RuleIndex(rules)

    # ---- active content: never run, only counted (strict=True rejects on it)
    for n in nodes:
        typ = n.attrs.get("type", "").lower()
        if n.tag == "script" and "json" not in typ:     # any type but data blocks may run (ecmascript, jscript...)
            rep.findings.append(Finding(check="scripts", message="<script> element"))
        refresh = n.tag == "meta" and n.attrs.get("http-equiv", "").strip().lower() == "refresh"
        urls = [n.attrs.get(k, "") for k in URL_ATTRS] + (
            [re.sub(r"^[^;]*;\s*(url\s*=\s*)?['\"]?", "", n.attrs.get("content", ""), flags=re.I)] if refresh else [])
        if any(k.startswith("on") or k == "srcdoc" for k in n.attrs) or any(
                re.sub(r"[\s\x00-\x1f]", "", u).lower().startswith(ACTIVE_URL) for u in urls):
            rep.findings.append(Finding(check="scripts",
                                        message="event handler, srcdoc or script URL (javascript:, vbscript:, data:)"))
        if n.tag in ("iframe", "frame") and n.attrs.get("src", "").strip():
            rep.findings.append(Finding(check="remote_content", message=f"<{n.tag}> loads another document"))
        if n.tag in ("object", "embed", "applet"):
            rep.findings.append(Finding(check="plugin_content", message=f"<{n.tag}> plugin content"))

    # ---- walk
    buckets: dict[tuple, list[str]] = {}
    # the page title: plain text directly inside the first <title> of the first top-level <head>
    head = next((h for h in nodes if h.tag == "head" and h.parent is not None
                 and h.parent.tag in ("#root", "html")), None)
    title = next((t for t in (head.children if head else []) if isinstance(t, Node) and t.tag == "title"), None)
    visible = ["".join(c for c in title.children if isinstance(c, str)) + "\n"] if title is not None else []
    shown_options = set()
    for sel in (n for n in nodes if n.tag == "select"):
        opts = [o for o in iter_nodes(sel) if o.tag == "option"]
        pick = next((o for o in opts if "selected" in o.attrs), opts[0] if opts else None)
        if pick is not None:
            shown_options.add(id(pick))
    stack = [(root, _State())]
    while stack:
        node, st = stack.pop()
        if isinstance(node, str):
            cat, reason = _classify(st)
            if cat == "visible":
                visible.append(node)
            elif node.strip():
                buckets.setdefault((cat, reason), []).append(node)
            continue
        if node.tag == "#block":
            visible.append("\n")
            continue
        if node.tag.rsplit(":", 1)[-1] in SKIP:      # also <svg:svg> and other prefixed names
            continue
        st = st.child()
        decl, fuzzy = rules.styles_for(node, node.attrs.get("style", ""))
        decl = _resolve_vars(st, {**_hints(node), **decl})
        _apply(st, node, decl)
        if node.tag in ("progress", "meter", "annotation", "annotation-xml") or (
                node.tag == "option" and id(node) not in shown_options):
            st.collapsed = st.collapsed or "hidden_by_browser"     # fallback content, closed <select> options
        for fd in fuzzy:                         # a rule we cannot match exactly may hide the node, never show it
            if _classify(st)[0] != "visible":
                break
            trial = st.child()
            _apply(trial, node, _resolve_vars(trial, fd))
            if _classify(trial)[0] != "visible":
                st = trial
        block = node.tag in BLOCK
        if block:
            stack.append((Node("#block", [], None), st))
        kids = [c for c in node.children if isinstance(c, Node)]
        closed, keep = None, None
        if node.tag == "details" and "open" not in node.attrs:      # only the first <summary> shows
            closed = st.child()
            closed.collapsed = closed.collapsed or "closed_details"
            keep = next((c for c in kids if c.tag == "summary"), None)
        elif node.tag == "semantics":                                # MathML: only the first child is rendered
            closed = st.child()
            closed.collapsed = closed.collapsed or "hidden_by_browser"
            keep = kids[0] if kids else None
        elif any(c.tag == "template" and ("shadowrootmode" in c.attrs or "shadowroot" in c.attrs) for c in kids):
            closed = st.child()                                      # a shadow host shows its shadow tree only
            closed.collapsed = closed.collapsed or "shadow_host"
        for c in reversed(node.children):
            stack.append((c, st if closed is None or c is keep else closed))
        if block:
            stack.append((Node("#block", [], None), st))

    text = re.sub(r"[ \t\r\f\v]+", " ", "".join(visible))
    text = re.sub(r"\n\s*\n+", "\n\n", text).strip() + "\n"
    rep.safe_pages = [text]

    # ---- hidden text: counted, never kept
    rep.hidden_texts = [t for (cat, _), texts in buckets.items() if cat != "visible" for t in texts]
    for (cat, reason), texts in buckets.items():
        joined = " ".join(" ".join(t.split()) for t in texts)
        n_alnum = sum(c.isalnum() for c in joined)
        if cat == "stealth":
            rep.findings += hidden_text_finding(joined, "the page", reason, count=len(texts))
        elif cat == "sr_only" and n_alnum >= 3:
            rep.findings.append(Finding(check="hidden_text", message="long screen-reader-only text"))
        elif cat == "collapsed" and n_alnum >= 3:
            rep.findings.append(Finding("collapsed_text", f"{n_alnum} characters of initially hidden content "
                                                          f"({reason}); excluded from safe text"))
    for c in comments:
        if not c.strip().startswith(("[if", "<![endif")):
            rep.findings += content_findings(c, "html_comment", side_channel=True)
    rep.findings += content_findings(text, "visible text")
    return rep


def _decode(b: bytes) -> str:
    """Strict: UTF-8 (with or without a byte-order mark) or UTF-16 with a byte-order mark. Anything else (legacy
    charsets, bad bytes, UTF-16 without a mark) is refused; nothing is guessed or replaced."""
    try:
        if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
            return b.decode("utf-16")
        return b.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise limits.Refused("text is not valid UTF-8, or UTF-16 with a byte-order mark") from None
