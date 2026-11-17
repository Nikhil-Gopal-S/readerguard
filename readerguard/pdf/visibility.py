"""Per-span visibility: is this text actually drawn where a human reader can see it?

Approach ("render differential"): render every page twice, once as-is and once with all text
removed (text-only redaction, images and vector graphics kept). A span a human can see changes the
pixels inside its box; a span that is white-on-white, covered by a shape, image or annotation, clipped
away, transparent, or drawn in an invisible render mode does not. Both renders include annotations, so text
under an opaque annotation box counts as hidden. An invisible OCR layer over a scanned image is dropped too. On top of that, a few cheap
metadata rules (render mode, opacity, size, page bounds) explain *why* a span is hidden.

Coordinates: texttrace / rawdict boxes are in unrotated page space; pixmaps are rendered in
rotated space, so boxes go through page.rotation_matrix before indexing pixels.
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field

import numpy as np
import pymupdf

from .. import limits
from ..content import contrast
from ..findings import Finding

INK_DELTA = 16          # per-channel difference (0..255) that counts as "this pixel was painted"
MIN_INK = 0.004         # fraction of inked pixels below which a span is treated as not drawn
HIDDEN_CONTRAST = 1.15  # WCAG contrast ratio below which text is unreadable (e.g. #F2F2F2 on white)
FAINT_CONTRAST = 1.5    # below this, text is very hard to see (#D0D0D0 on white); flagged, dropped
MIN_HEIGHT = 1.5        # points; glyphs shorter than this are not legible at any normal zoom
MIN_ADVANCE = 0.3       # points per character; catches horizontal squashing (Tz 1)
SCAN_IMAGE_COVER = 0.5  # an image covering this share of the page makes it a scan
ZOOM = 2.0              # render scale (144 dpi) for the ink comparison

OCCLUDERS = ("fill-path", "fill-image", "fill-shade", "fill-imgmask")


def _rgb(color) -> tuple[float, float, float]:
    if color is None:
        return (0.0, 0.0, 0.0)
    c = tuple(color)
    if len(c) == 1:
        return (c[0],) * 3
    if len(c) == 3:
        return c
    if len(c) == 4:
        cy, m, y, k = c
        return ((1 - cy) * (1 - k), (1 - m) * (1 - k), (1 - y) * (1 - k))
    return (0.0, 0.0, 0.0)


def _pix(page, zoom) -> np.ndarray:
    r = page.rect * pymupdf.Matrix(zoom, zoom)
    if r.width * r.height > limits.MAX_IMAGE_PIXELS:
        raise limits.OverLimit(f"page {page.number + 1} renders larger than the "
                         f"{limits.MAX_IMAGE_PIXELS // 1_000_000} megapixel limit")
    pm = page.get_pixmap(matrix=pymupdf.Matrix(zoom, zoom), alpha=False, colorspace=pymupdf.csRGB, annots=True)
    return np.frombuffer(pm.samples, dtype=np.uint8).reshape(pm.height, pm.width, pm.n)[:, :, :3]


def strip_text(doc) -> "pymupdf.Document":
    """A copy of the document with every text object removed, all other content intact."""
    bare = pymupdf.open("pdf", doc.tobytes())
    for p in bare:
        p.add_redact_annot(p.rect * p.derotation_matrix)
        p.apply_redactions(images=pymupdf.PDF_REDACT_IMAGE_NONE,
                           graphics=pymupdf.PDF_REDACT_LINE_ART_NONE,
                           text=pymupdf.PDF_REDACT_TEXT_REMOVE)
    return bare


@dataclass
class PageResult:
    findings: list[Finding] = field(default_factory=list)
    safe_text: str = ""
    raw_text: str = ""
    ocr_layer_spans: int = 0


def _advance(s) -> float:
    """Average width per character, measured line by line: one span can hold a whole page of lines (one text
    object), and its box width divided by all its characters would look squashed."""
    lines: dict[float, list] = {}
    for c in s["chars"]:
        lines.setdefault(round(c[2][1], 1), []).append(c[3])
    width = sum(max(b[2] for b in bs) - min(b[0] for b in bs) for bs in lines.values())
    return width / max(1, len(s["chars"]))


def _covered(box, over) -> bool:
    """At least 80% of the box lies under the given opaque rectangles (overlaps may count twice)."""
    a = box.get_area()
    return a > 0 and sum((r & box).get_area() for r in over) >= 0.8 * a


def _span_text(s) -> str:
    return "".join(chr(c[0]) for c in s["chars"])


def _key(origin, ch) -> tuple:
    # ligatures: the tracer reports "ﬁ" as one char, the extractor as "f" + "i" at the same origin
    if len(ch) == 1 and ord(ch) >= 0xFB00:
        ch = unicodedata.normalize("NFKC", ch)[:1] or ch
    return (int(origin[0] * 10 + 0.5), int(origin[1] * 10 + 0.5), ch)


# Text extraction for safe_text: ActualText replacements ignored (the tracer never sees them), and no CID
# fallback for glyphs without a Unicode mapping (the tracer reports U+FFFD for those; so must the extractor).
RAW_FLAGS = (pymupdf.TEXTFLAGS_RAWDICT | pymupdf.TEXT_IGNORE_ACTUALTEXT) & ~pymupdf.TEXT_CID_FOR_UNKNOWN_UNICODE
MATCH_TOL = 1.0         # points: an extracted character must sit inside a visible traced glyph's box (+ this)
OWN_SHARE = 0.5         # a glyph whose box is more than half under LATER glyphs cannot show its own ink


def _blend(color, bg, opacity: float):
    """The colour as painted: the fill colour composited over the background at the span's opacity."""
    a = max(0.0, min(1.0, float(opacity)))
    return tuple(c * a + b * (1 - a) for c, b in zip(color, bg))


def _chars_of(ch: str) -> str:
    # ligatures: the tracer reports "\ufb01" as one char, the extractor as "f" + "i"
    return unicodedata.normalize("NFKC", ch) or ch if len(ch) == 1 and ord(ch) >= 0xFB00 else ch


class _Visible:
    """Visible traced glyphs, for the allow-list lookup: by exact (character, origin) first (the common case,
    one set lookup), else by character and position inside the glyph box (index built on the first miss)."""
    STEP = 12.0

    def __init__(self):
        self.by: dict = {}
        self.exact: set = set()
        self.pending: list = []

    def add(self, ch: str, box, origin) -> None:
        self.exact.add((ch, int(origin[0] * 10 + 0.5), int(origin[1] * 10 + 0.5)))
        self.pending.append((ch, box))

    def add_many(self, glyphs) -> None:
        """glyphs: (code, box, span, origin) tuples."""
        for code, box, _, o in glyphs:
            self.exact.add((chr(code), int(o[0] * 10 + 0.5), int(o[1] * 10 + 0.5)))
            self.pending.append((chr(code), box))

    def _index(self, ch: str, box) -> None:
        x0, y0, x1, y1 = box[0] - MATCH_TOL, box[1] - MATCH_TOL, box[2] + MATCH_TOL, box[3] + MATCH_TOL
        st = self.STEP
        for c in _chars_of(ch):
            for by in range(int(y0 // st), int(y1 // st) + 1):
                for bx in range(int(x0 // st), int(x1 // st) + 1):
                    self.by.setdefault((c, by, bx), []).append((x0, y0, x1, y1))

    def has(self, ch: str, origin) -> bool:
        x, y = origin
        if (ch, int(x * 10 + 0.5), int(y * 10 + 0.5)) in self.exact:
            return True
        if self.pending:
            for c, b in self.pending:
                self._index(c, b)
            self.pending = []
        return any(b[0] <= x <= b[2] and b[1] <= y <= b[3]
                   for b in self.by.get((ch, int(y // self.STEP), int(x // self.STEP)), ()))


def analyze_page(page, bare_page, pno: int) -> PageResult:
    """safe_text is built from an ALLOW-list: an extracted character is kept only when a traced glyph with the same
    character, judged visible, sits at its position. Text the tracer never reports (clip-only render mode,
    ActualText replacements, glyphs the extractor decodes differently) can therefore never reach safe_text."""
    res = PageResult()
    blocks = [b for b in page.get_text("rawdict", flags=RAW_FLAGS)["blocks"] if b.get("type") == 0]
    res.raw_text = "".join(c["c"] for b in blocks for ln in b["lines"] for sp in ln["spans"] for c in sp["chars"])
    trace = sorted(page.get_texttrace(), key=lambda s: s["seqno"])
    zoom = ZOOM
    if not trace:
        if sum(c.isalnum() for c in res.raw_text) >= 3:      # extracted, but nothing was drawn: not visible
            res.findings.append(Finding("hidden_text", "hidden text (not_rendered): text a parser extracts but "
                                                       "that is never drawn", pno))
        return res

    w, h = page.cropbox.width, page.cropbox.height
    unrot = pymupdf.Rect(0, 0, w, h)
    rot = page.rotation_matrix
    full, bare = _pix(page, zoom), _pix(bare_page, zoom)
    H, W = full.shape[:2]
    diff = np.maximum(full, bare)
    diff -= np.minimum(full, bare)
    painted = (diff[..., 0] >= INK_DELTA) | (diff[..., 1] >= INK_DELTA) | (diff[..., 2] >= INK_DELTA)

    log = page.get_bboxlog()
    images = [pymupdf.Rect(r) for t, r in log if t in ("fill-image", "fill-imgmask")]
    img_cover = max((r & unrot).get_area() for r in images) / unrot.get_area() if images else 0.0
    is_scan = img_cover >= SCAN_IMAGE_COVER
    annots = [a.rect * page.derotation_matrix for a in page.annots()]     # drawn after (over) all page content
    # annotations the text-stripping step removed from the bare copy (FreeText, Redact): whatever lies under them
    # cannot be judged by ink, so it is treated as covered
    kept = {a.xref for a in bare_page.annots()}
    dropped = [a.rect * page.derotation_matrix for a in page.annots() if a.xref not in kept]

    def later(seq: int) -> list:
        """Opaque things drawn after (over) the text object with this sequence number."""
        return [pymupdf.Rect(r) for t, r in log[seq + 1:] if t in OCCLUDERS] + annots

    def area(box, trim=0.2):
        """The pixel area of a page box, as (rows, columns) slices; vertically trimmed to the glyph body."""
        px = (box * rot) * pymupdf.Matrix(zoom, zoom)
        dy = px.height * trim
        x0, x1 = max(0, int(px.x0)), min(W, int(np.ceil(px.x1)))
        y0, y1 = max(0, int(px.y0 + dy)), min(H, int(np.ceil(px.y1 - dy)))
        return None if x1 - x0 < 1 or y1 - y0 < 1 else (slice(y0, y1), slice(x0, x1))

    def ink(sl) -> float:
        return painted[sl].mean()

    def bg(sl):
        return np.median(bare[sl].reshape(-1, 3), axis=0) / 255.0

    def uniform(sl) -> bool:
        return np.ptp(bare[sl].reshape(-1, 3), axis=0).max() < INK_DELTA

    # ---- glyph ownership: each pixel belongs to the LAST glyph drawn over it. A glyph's own ink is counted on
    # the pixels it owns only, so text drawn over a hidden glyph cannot lend it ink, and glyphs piled on one spot
    # (negative character spacing, text printed over text) own almost nothing.
    glyphs, of_span = [], {}
    for si, s in enumerate(trace):
        for ch in s["chars"]:
            if chr(ch[0]).strip():
                of_span.setdefault(si, []).append(len(glyphs))
                glyphs.append((ch[0], tuple(ch[3]), si, ch[2]))
    n = len(glyphs)
    owner = np.full((H, W), -1, np.int32)
    slices: list = [None] * n
    if n:
        # every glyph box to pixel bounds at once: rotate, zoom, take the bounding box of the four corners
        b = np.array([g[1] for g in glyphs], dtype=np.float64).reshape(n, 4)
        m = rot * pymupdf.Matrix(zoom, zoom)
        xs = np.stack([b[:, 0], b[:, 2], b[:, 0], b[:, 2]], axis=1)
        ys = np.stack([b[:, 1], b[:, 1], b[:, 3], b[:, 3]], axis=1)
        px, py = m.a * xs + m.c * ys + m.e, m.b * xs + m.d * ys + m.f
        x0 = np.clip(np.floor(px.min(axis=1)), 0, W).astype(int)
        x1 = np.clip(np.ceil(px.max(axis=1)), 0, W).astype(int)
        y0 = np.clip(np.floor(py.min(axis=1)), 0, H).astype(int)
        y1 = np.clip(np.ceil(py.max(axis=1)), 0, H).astype(int)
        paints = [trace[g[2]]["type"] != 3 and trace[g[2]].get("opacity", 1.0) >= 0.05 for g in glyphs]
        for g, a, b_, c, d, p_ in zip(range(n), y0.tolist(), y1.tolist(), x0.tolist(), x1.tolist(), paints):
            if d > c and b_ > a:
                slices[g] = (slice(a, b_), slice(c, d))
                if p_:
                    owner[a:b_, c:d] = g
    flat = owner.ravel()
    sel = flat >= 0
    own = flat[sel]
    owned = np.bincount(own, minlength=n)
    inked = np.bincount(own, weights=painted.ravel()[sel], minlength=n)
    later_cache: dict = {}

    def later_of(seq):
        if seq not in later_cache:
            later_cache[seq] = later(seq)
        return later_cache[seq]

    # per-glyph verdicts for all glyphs at once; only the rare overlapped / ink-less ones need a closer look
    if n:
        bx = np.array([g[1] for g in glyphs], dtype=np.float64).reshape(n, 4)
        cx, cy = (bx[:, 0] + bx[:, 2]) / 2, (bx[:, 1] + bx[:, 3]) / 2
        total = np.clip(x1 - x0, 0, None) * np.clip(y1 - y0, 0, None)
        verdict = np.select(
            [~((cx >= 0) & (cx <= w) & (cy >= 0) & (cy <= h)), total == 0, owned < OWN_SHARE * total,
             inked < np.maximum(1.0, MIN_INK * owned)],
            [1, 2, 3, 4], 0)
    else:
        verdict = np.zeros(0, int)
    NAMES = {1: "off_page", 2: "tiny"}

    def glyph_reason(g: int, seq, color, opacity, flat_bg) -> str | None:
        code, (bx0, by0, bx1, by1), _, _ = glyphs[g]
        v = int(verdict[g])
        if dropped and v != 1:
            cb = pymupdf.Rect(bx0, by0, bx1, by1)
            if any((r & cb).get_area() >= 0.5 * max(cb.get_area(), 1e-6) for r in dropped):
                return "covered"
        if v == 0:
            if flat_bg:                                  # one background colour: the span's contrast decided
                return None
            b = bg(slices[g])                            # else this glyph against what is under it
            c = contrast(_blend(color, tuple(b), opacity), b)
            return "low_contrast" if c < HIDDEN_CONTRAST else "faint" if c < FAINT_CONTRAST else None
        if v == 3:
            region = owner[slices[g]].ravel()
            others = np.bincount(region[region > g], minlength=n)
            top = int(others.argmax()) if others.any() else -1
            same = top >= 0 and glyphs[top][0] == code and abs(glyphs[top][1][0] - bx0) < 2
            return "duplicate" if same else "overlapped"
        if v == 4:
            cb = pymupdf.Rect(bx0, by0, bx1, by1)
            return "covered" if _covered(cb, [r for r in later_of(seq) if r.intersects(cb)]) else "not_rendered"
        return NAMES[v]

    visible = _Visible()
    groups: dict[str, list] = {}        # reason -> [text]
    # MuPDF's extractor drops characters outside the active clip path (and the page); the tracer keeps them.
    # Such glyphs paint nothing, so the ink test drops them, and the allow-list never sees them extracted.

    for si, s in enumerate(trace):
        text = _span_text(s)
        if not text.strip():
            continue
        box = pymupdf.Rect(s["bbox"])
        opacity = s.get("opacity", 1.0)
        reason = None
        if s["type"] == 3:
            if is_scan and any((box & r).get_area() > 0 for r in images):
                res.ocr_layer_spans += 1          # invisible OCR text over a scan: dropped (the scan is pixels)
                continue
            reason = "invisible_render_mode"
        elif opacity < 0.05:
            reason = "transparent"
        elif not unrot.contains(pymupdf.Point((box.x0 + box.x1) / 2, (box.y0 + box.y1) / 2)) or (
                box.get_area() > 0 and (box & unrot).get_area() < 0.5 * box.get_area()):
            reason = "off_page"
        elif box.height < MIN_HEIGHT or _advance(s) < MIN_ADVANCE:
            reason = "tiny"
        else:
            sl = area(box)
            if sl is None:
                reason = "tiny"
            else:
                b = bg(sl)
                c, flat_bg = contrast(_blend(_rgb(s.get("color")), tuple(b), opacity), b), uniform(sl)
                if ink(sl) < MIN_INK:
                    if _covered(box, later(s["seqno"])):
                        reason = "covered"
                    elif c < HIDDEN_CONTRAST:
                        reason = "low_contrast"
                    else:
                        reason = "not_rendered"
                elif flat_bg and c < HIDDEN_CONTRAST:
                    reason = "low_contrast"
                elif flat_bg and c < FAINT_CONTRAST:
                    reason = "faint"
                else:                                       # visible as a whole: now character by character
                    hidden, color = {}, _rgb(s.get("color"))
                    ids = of_span.get(si, [])
                    if flat_bg and ids:                     # the common case, in bulk: glyphs with no verdict
                        ok = verdict[ids] == 0
                        clear = [g for g, k in zip(ids, ok.tolist()) if k] if not dropped else []
                        visible.add_many(glyphs[g] for g in clear)
                        ids = [g for g, k in zip(ids, ok.tolist()) if not k] if not dropped else ids
                    for g in ids:
                        why = glyph_reason(g, s["seqno"], color, opacity, flat_bg)
                        if why is None:
                            visible.add(chr(glyphs[g][0]), glyphs[g][1], glyphs[g][3])
                        elif why != "duplicate":            # a second copy of a visible glyph (fake bold)
                            hidden.setdefault(why, []).append(chr(glyphs[g][0]))
                    for why, chars in hidden.items():
                        groups.setdefault(why, []).append("".join(chars))
        if reason is not None:
            groups.setdefault(reason, []).append(text)

    if res.ocr_layer_spans:
        res.findings.append(Finding(check="ocr_layer", page=pno,
                                    message=f"{res.ocr_layer_spans} span(s) of invisible OCR text over a scanned "
                                            "image (ask for page images to read a scan)"))
    for reason, items in groups.items():               # counted when the hidden text has 3+ letters or digits
        if sum(ch.isalnum() for t in items for ch in t) < 3:
            continue
        res.findings.append(
            Finding("faint_text", f"{len(items)} text span(s) with near-background colour", pno) if reason == "faint"
            else Finding("hidden_text", f"hidden text ({reason}): {len(items)} text span(s) a parser extracts but "
                                        "a reader cannot see", pno))
    res.safe_text = _rebuild(blocks, visible)
    kept_chars = sum(ch.isalnum() for ch in res.safe_text)
    if sum(ch.isalnum() for ch in res.raw_text) - kept_chars >= 3 and not any(
            f.check in ("hidden_text", "ocr_layer") for f in res.findings):
        res.findings.append(Finding("hidden_text", "hidden text (not_rendered): extracted text with no visible "
                                                   "glyph under it", pno))
    return res


def _rebuild(blocks, visible: _Visible) -> str:
    """Page text in PyMuPDF's reading order, keeping only characters a visible traced glyph vouches for (spaces
    the extractor inserts between words are kept)."""
    out = []
    for b in blocks:
        lines = []
        for ln in b["lines"]:
            s = "".join(c["c"] for sp in ln["spans"] for c in sp["chars"]
                        if not c["c"].strip() or c.get("synthetic") or visible.has(c["c"], c["origin"]))
            if s.strip():
                lines.append(s)
        if lines:
            out.append("\n".join(lines))
    return "\n".join(out) + ("\n" if out else "")
