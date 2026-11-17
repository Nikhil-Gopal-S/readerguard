"""Office documents: OOXML only (docx/docm, pptx/pptm, xlsx/xlsm). Any other zip is a reject.

Active content: VBA macros, Excel 4.0 macro sheets and Auto_Open names, ActiveX, embedded OLE objects,
DDE fields, formulas and links, remote templates / frames / OLE links (template injection, NTLM leaks over UNC
paths, ms-msdt: "Follina"-style URIs).
Hidden text: Word hidden runs (w:vanish), white / tiny text (theme colours, styles, table styles and shading
resolved), field codes, unused headers / notes, hidden or off-page text boxes, tracked deletions; hidden slides
and shapes, off-slide and covered shapes; hidden / zero-size rows and columns, very-hidden sheets, ';;;' number
formats, white fonts (theme / indexed / rich-text runs), merged and conditionally formatted cells, cells under
drawings.
Side channels: comments, speaker notes, document properties, custom XML.

The package is read the way Office reads it: part names case-insensitive and percent-decoded, relationship
types matched in full, attributes by their exact (qualified) name, and elements and attributes in a namespace
that mc:Ignorable lists (and Office does not know) dropped before any check. Transitional and Strict OOXML
namespaces both work. Anything that cannot be resolved (a colour, a style part) counts as hidden.
"""
from __future__ import annotations

import colorsys
import io
import re
import zipfile
from urllib.parse import unquote

from defusedxml import ElementTree as ET

from .. import limits
from ..content import content_findings, contrast, hidden_text_finding
from ..findings import Finding, Report

DANGEROUS_URI = re.compile(r"^(ms-msdt|search-ms|ms-officecmd|mhtml|ms-word|ms-excel|ms-powerpoint|its|mk):", re.I)
# Part names a reason may quote: fixed names (digits vary). Other names came from the file and are not quoted.
KNOWN_PART = re.compile(r"(\[Content_Types\]|word/(document|styles|settings|comments|commentsExtended|"
                        r"numbering|footnotes|endnotes|header\d*|footer\d*)|"
                        r"xl/(workbook|styles|sharedStrings|worksheets/sheet\d+)|"
                        r"ppt/(presentation|slides/slide\d+|notesSlides/notesSlide\d+)|docProps/(core|app|custom))\.xml")
EXEC_NAME = re.compile(rb"[\w\- ]{1,64}\.(exe|scr|bat|cmd|ps1|vbs|js|jse|wsf|hta|dll|lnk|msi|jar|com|cpl)\b", re.I)

MC_NS = "http://schemas.openxmlformats.org/markup-compatibility/2006"
REL_NS = ("http://schemas.openxmlformats.org/officeDocument/2006/relationships",
          "http://purl.oclc.org/ooxml/officeDocument/relationships")
REL_TYPES = REL_NS + ("http://schemas.microsoft.com/office/2006/relationships",
                      "http://schemas.microsoft.com/office/2007/relationships",
                      "http://schemas.microsoft.com/office/2011/relationships")
# Relationship kinds a part has at most one of; the part must exist when it is named.
SINGLE = {"styles", "theme", "sharedStrings", "settings", "slideLayout", "slideMaster", "footnotes", "endnotes",
          "officeDocument"}
MAX_FORMULA = 8192          # Excel's own limit on a formula's length


def ln(tag) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def ns(tag) -> str:
    return tag[1:].split("}", 1)[0] if isinstance(tag, str) and tag.startswith("{") else ""


def attr(el, name, default=None):
    """The attribute by its exact name: in the element's own namespace (w:val on a w: element), with no
    namespace (state, hidden, x), or in the relationships namespace (r:id). An attribute with the same local
    name in any other namespace is never read: it may be a decoy Office ignores."""
    if el is None:
        return default
    a = el.attrib
    own = ns(el.tag)
    for k in ((f"{{{own}}}{name}" if own else name), name, *(f"{{{n}}}{name}" for n in REL_NS)):
        if k in a:
            return a[k]
    return default


def rid(el):
    """The r:id of an element (relationships namespace only: sldId and sheet also have a plain id / sheetId)."""
    return next((el.attrib[k] for k in (f"{{{n}}}id" for n in REL_NS) if k in el.attrib), None) \
        if el is not None else None


def kids(el, name):
    return [c for c in el if ln(c.tag) == name] if el is not None else []


def first(el, name):
    if el is None:
        return None
    for c in el.iter():
        if ln(c.tag) == name:
            return c
    return None


def child(el, name):
    return next((c for c in el if ln(c.tag) == name), None) if el is not None else None


def _true(v, default=False) -> bool:
    """xsd:boolean: "1" / "true" and "0" / "false"; anything else is a reject (Office would not open it)."""
    if v is None:
        return default
    v = v.strip().lower()
    if v in ("1", "true", "on"):
        return True
    if v in ("0", "false", "off"):
        return False
    raise limits.Refused("a document attribute has a value Office does not accept")


class Pkg:
    def __init__(self, raw: bytes, rep: Report):
        self.z = zipfile.ZipFile(io.BytesIO(raw))
        self.names = self.z.namelist()
        self.rep = rep
        self.cache: dict = {}
        infos = self.z.infolist()
        total = sum(i.file_size for i in infos)
        if (len(infos) > limits.MAX_ZIP_ENTRIES or total > limits.MAX_ZIP_BYTES
                or total > limits.MAX_ZIP_RATIO * max(1, sum(i.compress_size for i in infos))
                or any(i.file_size > 1_000_000 and i.file_size > limits.MAX_ZIP_RATIO * max(1, i.compress_size)
                       for i in infos)):
            raise limits.OverLimit("archive is over the limits (entry count / expanded size / compression ratio)")
        if any(i.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) for i in infos):
            raise limits.Refused("archive uses a compression method Office files do not use")
        # OPC part names are case-insensitive: two entries that differ only in case are ambiguous
        self.lower = {}
        for n in self.names:
            if n.lower() in self.lower:
                raise limits.Refused("archive has two parts whose names differ only in case")
            self.lower[n.lower()] = n

    def name(self, n):
        """The archive entry for a part name (case-insensitive), or None."""
        return self.lower.get((n or "").lower())

    def read(self, name) -> bytes:
        info = self.z.getinfo(self.name(name) or name)
        with self.z.open(info) as f:        # bounded: a part that lies about its size cannot inflate past it
            return f.read(info.file_size + 1)

    def xml(self, name):
        """The part parsed (XXE-safe, no DTD), with what Office does not render removed: markup-compatibility
        branches it would not take, and elements / attributes in ignorable namespaces it does not know."""
        real = self.name(name)
        if real is None:
            return None
        if real in self.cache:
            return self.cache[real]
        try:
            raw = self.read(real)
            root = ET.fromstring(raw, forbid_dtd=True)
        except Exception as e:
            shown = real if KNOWN_PART.fullmatch(real) else "an XML part"
            self.rep.findings.append(Finding(check="malformed_xml",
                                             message=f"cannot parse {shown}: {type(e).__name__}"))
            root = None
        if root is not None:
            nsmap = _prefixes(raw)
            _alternate_content(root, nsmap)
            _drop_ignorable(root, nsmap)
        self.cache[real] = root
        return root

    def rels(self, part):
        d, f = part.rsplit("/", 1) if "/" in part else ("", part)
        root = self.xml(f"{d}/_rels/{f}.rels" if d else f"_rels/{f}.rels")
        out = {}
        if root is not None:
            for r in root:
                if ln(r.tag) == "Relationship":
                    out.setdefault(attr(r, "Id"), (attr(r, "Type", "") or "", attr(r, "Target", "") or "",
                                                   attr(r, "TargetMode", "") or ""))
        return out

    def target(self, part, rid) -> str | None:
        """The part an internal relationship id of `part` points to (None when unknown or external)."""
        typ, tgt, mode = self.rels(part).get(rid, ("", "", "External"))
        return None if mode == "External" else _resolve(part, tgt)

    def related(self, part, kind) -> list[str]:
        """Internal relationship targets of `part` whose type is exactly the OOXML (or Microsoft) type `kind`.
        A target that is not in the package is a reject (Office would apply it; we cannot check it)."""
        out = [_resolve(part, tgt) for typ, tgt, mode in self.rels(part).values()
               if typ in {f"{b}/{kind}" for b in REL_TYPES} and mode != "External"]
        if kind in SINGLE and len(out) > 1:
            raise limits.Refused(f"a part has more than one {kind} relationship")
        missing = [t for t in out if self.name(t) is None]
        if missing:
            raise limits.Refused(f"a {kind} part the document relies on is missing")
        return [self.name(t) for t in out]


# Namespaces Office understands in mc:Choice Requires="..." (Word, PowerPoint, Excel 2010 and later).
_MS = "http://schemas.microsoft.com/office/"
KNOWN_NS = {_MS + x for x in (
    "word/2010/wordprocessingShape", "word/2010/wordprocessingGroup", "word/2010/wordprocessingCanvas",
    "word/2010/wordprocessingInk", "word/2010/wordprocessingDrawing", "word/2010/wordml", "word/2012/wordml",
    "word/2015/wordml/symex", "word/2016/wordml/cid", "word/2018/wordml", "word/2018/wordml/cex",
    "word/2020/wordml/sdtdatahash", "word/2023/wordml/word16du", "drawing/2010/main", "drawing/2014/main",
    "drawing/2016/ink", "drawing/2017/model3d", "drawing/2014/chartex", "drawing/2015/9/8/chartex",
    "drawing/2007/8/2/chart", "drawing/2012/chart", "drawing/2014/chart", "drawing/2010/slicer",
    "powerpoint/2010/main", "powerpoint/2012/main", "spreadsheetml/2009/9/main", "spreadsheetml/2009/9/ac",
    "spreadsheetml/2010/11/main", "spreadsheetml/2010/11/ac", "spreadsheetml/2014/revision",
    "spreadsheetml/2015/revision2", "spreadsheetml/2016/revision3", "spreadsheetml/2017/richdata")} | {
    "urn:schemas-microsoft-com:vml", "urn:schemas-microsoft-com:office:office", "urn:schemas-microsoft-com:office:word",
    "http://schemas.openxmlformats.org/officeDocument/2006/math",
    "http://schemas.openxmlformats.org/drawingml/2006/main",
    "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}


def _prefixes(raw: bytes) -> dict[str, set]:
    out: dict[str, set] = {}
    for p, u in re.findall(rb"xmlns:([\w.-]+)\s*=\s*[\"']([^\"']*)[\"']", raw):
        out.setdefault(p.decode("utf-8", "replace"), set()).add(u.decode("utf-8", "replace"))
    return out


def _alternate_content(root, nsmap) -> None:
    """mc:AlternateContent: Office renders the first Choice whose required namespaces it understands, else the
    Fallback. Keep the first Choice only when every prefix it requires is declared (anywhere in the part) with
    known namespaces; drop every other branch, Fallback included. An unknown first Choice drops all branches."""
    acs = [e for e in root.iter() if ln(e.tag) == "AlternateContent"]
    for ac in acs:
        choice = next((c for c in ac if ln(c.tag) == "Choice"), None)
        keep = choice if choice is not None and all(
            nsmap.get(p, {None}) <= KNOWN_NS for p in (attr(choice, "Requires", "") or "").split()) else None
        for c in list(ac):
            if c is not keep:
                ac.remove(c)


def _drop_ignorable(root, nsmap) -> None:
    """Office drops elements (with their content) and attributes whose namespace mc:Ignorable lists, when it
    does not understand that namespace. So do we, before any check reads them."""
    prefixes = set()
    for el in root.iter():
        prefixes.update((el.attrib.get(f"{{{MC_NS}}}Ignorable") or "").split())
    bad = {u for p in prefixes for u in nsmap.get(p, ())} - KNOWN_NS
    if not bad:
        return
    for el in list(root.iter()):
        for c in [c for c in el if ns(c.tag) in bad]:
            el.remove(c)
        for k in [k for k in el.attrib if ns(k) in bad]:
            del el.attrib[k]


def _resolve(base_part: str, target: str) -> str:
    target = unquote(target)                          # part names are percent-encoded URIs
    if target.startswith("/"):
        return target[1:]
    parts = base_part.split("/")[:-1] + target.split("/")
    out = []
    for p in parts:
        if p == "..":
            if out:
                out.pop()
        elif p and p != ".":
            out.append(p)
    return "/".join(out)


def _all_text(el) -> str:
    return " ".join(t.text for t in el.iter() if ln(t.tag) in ("t", "delText", "instrText") and t.text) if el is not None else ""


# --------------------------------------------------------------------------- colours

def _hex(c):
    try:
        return tuple(int(c[i:i + 2], 16) / 255 for i in (0, 2, 4)) if c and len(c) >= 6 else None
    except ValueError:
        return None


def _pct(v, default=None):
    """A DrawingML percentage: 1/1000 % as an integer ("50000") or "50%" (Strict). -> fraction."""
    if v is None:
        return default
    v = v.strip()
    try:
        return float(v[:-1]) / 100 if v.endswith("%") else int(v) / 100000
    except ValueError:
        raise limits.Refused("a colour value Office does not accept") from None


def _hls_adjust(rgb, f):
    h, l, s = colorsys.rgb_to_hls(*rgb)
    return colorsys.hls_to_rgb(h, max(0.0, min(1.0, f(l))), s)


THEME_ORDER = ["lt1", "dk1", "lt2", "dk2", "accent1", "accent2", "accent3", "accent4", "accent5", "accent6",
               "hlink", "folHlink"]          # Excel's theme="N" index (light and dark swapped, as Excel does)


def _theme_colors(pkg: Pkg, theme_part: str | None) -> dict:
    """Theme colour name (dk1, lt1, accent1, ...) -> RGB (0..1)."""
    colors = {}
    th = pkg.xml(theme_part) if theme_part else None
    for el in (first(th, "clrScheme") if th is not None else None) or []:
        c = next(iter(el), None)
        if c is not None:
            colors[ln(el.tag)] = _hex(attr(c, "val", "") if ln(c.tag) == "srgbClr" else attr(c, "lastClr", ""))
    colors.setdefault("lt1", (1.0, 1.0, 1.0))
    colors.setdefault("dk1", (0.0, 0.0, 0.0))
    return colors


# --------------------------------------------------------------------------- shared OOXML checks

OLE_RELS = {"oleObject", "package"}
ACTIVEX_RELS = {"control", "activeXControlBinary", "activeXControl"}
MACRO_RELS = {"vbaProject", "vbaProjectSignature", "wordVbaData", "xlMacrosheet", "xlIntlMacrosheet",
              "vbaProjectSignatureAgile", "vbaProjectSignatureV3"}


def _content_types(pkg: Pkg) -> list[tuple[str, str, str]]:
    """[Content_Types].xml parsed (any encoding the XML declares): (Override|Default, part or extension, type)."""
    ct = pkg.xml("[Content_Types].xml")
    return [(ln(el.tag), (attr(el, "PartName", "") or attr(el, "Extension", "") or "").lstrip("/").lower(),
             (attr(el, "ContentType", "") or "").lower()) for el in (ct if ct is not None else [])]


def _all_rels(pkg: Pkg):
    """(source part, type, target, mode) of every relationship in the package."""
    for n in pkg.names:
        if n.endswith(".rels") and "_rels/" in n:
            d, f = n.rsplit("_rels/", 1)
            src = d + f[:-5]
            for typ, tgt, mode in pkg.rels(src).values():
                yield src, typ, tgt, mode


def _typed_parts(pkg: Pkg) -> tuple[set, set]:
    """(OLE object / package parts, ActiveX parts), found by folder name, by internal relationship type and by
    content type ([Content_Types].xml Override and Default), so no part name can hide one."""
    ole = {n for n in pkg.names if "/embeddings/" in n.lower()}
    ax = {n for n in pkg.names if "/activex/" in n.lower()}
    for src, typ, tgt, mode in _all_rels(pkg):
        kind = typ.rsplit("/", 1)[-1]
        if mode != "External" and kind in OLE_RELS | ACTIVEX_RELS:
            (ole if kind in OLE_RELS else ax).add(pkg.name(_resolve(src, tgt)) or _resolve(src, tgt))
    for tag, key, typ in _content_types(pkg):
        bucket = ole if "oleobject" in typ else ax if "activex" in typ else None
        if bucket is None:
            continue
        if tag == "Override":
            bucket.add(pkg.name(key) or key)
        elif tag == "Default":
            bucket.update(n for n in pkg.names if n.lower().endswith("." + key))
    return ole, ax


def common_checks(pkg: Pkg, rep: Report) -> None:
    names, F = pkg.names, rep.findings
    cts = _content_types(pkg)
    rels = list(_all_rels(pkg))
    kinds = {typ.rsplit("/", 1)[-1] for _, typ, _, _ in rels}
    vba = [n for n in names if n.lower().endswith(("vbaproject.bin", "vbadata.xml"))]
    if (vba or kinds & {"vbaProject", "vbaProjectSignature", "wordVbaData"}
            or any("macroenabled" in t or "vbaproject" in t for _, _, t in cts)):
        F.append(Finding(check="macros", message="document contains VBA macros"))
    macro_sheets = any("/macrosheets/" in n.lower() or "/intlmacrosheets/" in n.lower() for n in names) or bool(
        kinds & {"xlMacrosheet", "xlIntlMacrosheet"}) or any("macrosheet" in t for _, _, t in cts)
    if not macro_sheets:
        for n in names:
            if n.lower().endswith(".xml") and not n.lower().endswith(".rels"):
                root = pkg.xml(n)
                if root is not None and ln(root.tag) == "macrosheet":
                    macro_sheets = True
                    break
    if macro_sheets:
        F.append(Finding(check="macros", message="workbook contains Excel 4.0 (XLM) macro sheets"))
    ole, ax = _typed_parts(pkg)
    if ax:
        F.append(Finding(check="activex", message="document contains ActiveX controls"))
    emb = sorted(n for n in ole if n in names)
    if emb:
        exe = [m.group(0).decode("latin-1") for n in emb for m in [EXEC_NAME.search(pkg.read(n)[:5_000_000])] if m]
        if exe:
            F.append(Finding(check="embedded_executable", message="embedded object packages an executable or script"))
        else:
            F.append(Finding(check="embedded_object", message=f"{len(emb)} embedded OLE object(s) or package(s)"))

    ext_links = 0
    for src, typ, tgt, mode in rels:
        kind = typ.rsplit("/", 1)[-1]
        if DANGEROUS_URI.match(tgt):
            F.append(Finding(check="dangerous_uri", message="relationship uses a protocol handler that can run code"))
            continue
        if mode != "External":
            continue
        unc = tgt.startswith(("\\\\", "file:", "smb:")) or re.match(r"^[a-z]+://\d+\.\d+\.\d+\.\d+", tgt, re.I)
        if kind in ("attachedTemplate", "oleObject", "frame", "subDocument", "control", "aFChunk", "package"):
            F.append(Finding(check="remote_content",
                             message=f"loads a remote {kind} when opened (template / OLE injection)"))
        elif unc:
            F.append(Finding(check="remote_content",
                             message="external link to a file share or raw IP (credential / NTLM leak)"))
        elif kind == "image":
            F.append(Finding(check="remote_content", message="remote image (tracking beacon when opened)"))
        elif kind == "externalLinkPath":
            F.append(Finding(check="external_link", message="workbook links to an external workbook"))
        else:
            ext_links += 1
    if ext_links:
        F.append(Finding(check="hyperlinks", message=f"{ext_links} external hyperlink(s)"))
    # external link parts, however they are reached: DDE / OLE links run commands, external books load files
    for n in names:
        root = pkg.xml(n) if n.lower().endswith(".xml") and "externallink" in n.lower() else None
        if root is None or ln(root.tag) != "externalLink":
            continue
        if any(ln(e.tag) in ("ddeLink", "oleLink") for e in root.iter()):
            F.append(Finding(check="dde", message="workbook has a DDE / OLE link that can launch a command"))
        if any(ln(e.tag) == "externalBook" for e in root.iter()):
            F.append(Finding(check="external_link", message="workbook links to an external workbook"))

    for part, fields in (("docProps/core.xml", ("title", "subject", "description", "keywords", "creator")),
                         ("docProps/app.xml", ("Company", "Manager")), ("docProps/custom.xml", None)):
        root = pkg.xml(part)
        if root is None:
            continue
        items = ([(ln(el.tag), (el.text or "").strip()) for el in root.iter() if ln(el.tag) in fields]
                 if fields else
                 [("custom", " ".join(t.strip() for t in el.itertext()))
                  for el in root if ln(el.tag) == "property"])
        for name, txt in items:
            if not txt:
                continue
            F.extend(content_findings(txt, f"properties.{name}"))
    for n in names:
        if n.startswith("customXml/item") and n.endswith(".xml") and "Props" not in n:
            root = pkg.xml(n)
            txt = " ".join(t.strip() for t in (root.itertext() if root is not None else []) if t.strip())
            F.extend(content_findings(txt, "custom_xml", side_channel=True))


# --------------------------------------------------------------------------- DOCX

HIGHLIGHT = {"black": "000000", "blue": "0000FF", "cyan": "00FFFF", "green": "00FF00", "magenta": "FF00FF",
             "red": "FF0000", "yellow": "FFFF00", "white": "FFFFFF", "darkBlue": "000080", "darkCyan": "008080",
             "darkGreen": "008000", "darkMagenta": "800080", "darkRed": "800000", "darkYellow": "808000",
             "darkGray": "808080", "lightGray": "C0C0C0"}
WORD_THEME = {"dark1": "dk1", "light1": "lt1", "dark2": "dk2", "light2": "lt2", "text1": "dk1", "background1": "lt1",
              "text2": "dk2", "background2": "lt2", "hyperlink": "hlink", "followedHyperlink": "folHlink",
              **{f"accent{i}": f"accent{i}" for i in range(1, 7)}}
UNRESOLVED = "unresolved"


def _word_color(el, theme, val_attr="val", theme_attr="themeColor"):
    """RGB (0..1) of a Word colour element: themeColor (with tint / shade) wins over the literal value; "auto"
    is black. UNRESOLVED when a theme colour cannot be resolved; None when no colour is set."""
    tc = attr(el, theme_attr)
    if tc:
        rgb = theme.get(WORD_THEME.get(tc, tc))
        if rgb is None:
            return UNRESOLVED
        tint, shade = attr(el, "themeTint"), attr(el, "themeShade")
        try:
            if tint:
                t = int(tint, 16) / 255
                rgb = tuple(c * t + (1 - t) for c in rgb)
            if shade:
                s = int(shade, 16) / 255
                rgb = tuple(c * s for c in rgb)
        except ValueError:
            return UNRESOLVED
        return rgb
    v = attr(el, val_attr)
    if not v or v.lower() == "auto":
        return None
    return _hex(v) or UNRESOLVED


def _rpr_flags(rpr, theme) -> dict:
    f = {}
    if rpr is None:
        return f
    for c in rpr:
        name = ln(c.tag)
        v = attr(c, "val")
        if name in ("vanish", "specVanish", "webHidden") and v not in ("0", "false", "off"):
            f["vanish"] = True
        elif name in ("vanish", "specVanish", "webHidden"):
            f["vanish"] = False
        elif name == "color":
            col = _word_color(c, theme)
            if col is not None:
                f["color"] = col
        elif name in ("sz", "szCs") and v and v.isdigit():
            f[name] = int(v)
        elif name == "shd":
            col = _word_color(c, theme, "fill", "themeFill")
            if col is not None:
                f["bg"] = col
        elif name == "highlight" and v and v != "none":
            f["bg"] = _hex(HIGHLIGHT[v]) if v in HIGHLIGHT else UNRESOLVED
        elif name == "rStyle" and v:
            f["rStyle"] = v
    return f


def _run_reason(fl: dict, bgs: list) -> str | None:
    if fl.get("vanish"):
        return "hidden_run"
    if any(fl.get(k) is not None and fl[k] <= 2 for k in ("sz", "szCs")):
        return "tiny_font"
    col = fl.get("color", (0.0, 0.0, 0.0))
    bg = fl.get("bg") or next((b for b in bgs if b is not None), (1.0, 1.0, 1.0))
    if UNRESOLVED in (col, bg):
        return "unresolved_color"
    if contrast(col, bg) < 1.15:
        return "same_as_background"
    return None


class _Styles:
    """Word styles: run properties per style id (basedOn resolved), the document defaults, the default paragraph
    and character styles, and table styles with their conditional (tblStylePr) variants."""

    def __init__(self, root, theme):
        self.styles, self.defaults, self.default_para, self.default_char, self.table = {}, {}, None, None, {}
        if root is None:
            return
        for st in root.iter():
            if ln(st.tag) != "style":
                continue
            sid, typ = attr(st, "styleId"), attr(st, "type")
            based = child(st, "basedOn")
            self.styles[sid] = (_rpr_flags(child(st, "rPr"), theme), attr(based, "val") if based is not None else None)
            if _true(attr(st, "default"), False):
                if typ == "paragraph" and self.default_para is None:
                    self.default_para = sid
                elif typ == "character" and self.default_char is None:
                    self.default_char = sid
            if typ == "table":
                self.table[sid] = [_rpr_flags(first(x, "rPr"), theme) for x in kids(st, "tblStylePr")]
        dd = first(root, "rPrDefault")
        self.defaults = _rpr_flags(first(dd, "rPr"), theme) if dd is not None else {}

    def flags(self, sid, depth=0) -> dict:
        if not sid or sid not in self.styles or depth > 8:
            return {}
        fl, based = self.styles[sid]
        return {**self.flags(based, depth + 1), **fl}


def _word_page(root) -> tuple[float, float]:
    """Page width and height in EMU from the last section's w:pgSz (twips); Letter when absent."""
    sz = None
    for e in root.iter():
        if ln(e.tag) == "pgSz":
            sz = e
    try:
        return (int(attr(sz, "w", "12240")) * 635, int(attr(sz, "h", "15840")) * 635)
    except (TypeError, ValueError):
        return (12240 * 635, 15840 * 635)


def _box_hidden(p, parent, page) -> str | None:
    """A paragraph inside a text box or frame Word does not draw: a hidden shape, VML visibility:hidden /
    display:none, or an anchor placed off the page."""
    anc = parent.get(p)
    while anc is not None:
        k = ln(anc.tag)
        if k in ("anchor", "inline"):
            dp = child(anc, "docPr")
            if dp is not None and _true(attr(dp, "hidden"), False):
                return "hidden_shape"
            ext = child(anc, "extent")
            cx, cy = (int(attr(ext, "cx", "1") or 1), int(attr(ext, "cy", "1") or 1)) if ext is not None else (1, 1)
            if cx <= 0 or cy <= 0:
                return "hidden_shape"
            for axis, size, limit in (("positionH", cx, page[0]), ("positionV", cy, page[1])):
                pos = child(anc, axis)
                off = child(pos, "posOffset") if pos is not None else None
                if off is not None and off.text:
                    try:
                        o = int(off.text)
                    except ValueError:
                        return "off_page"
                    if o >= limit or o + size <= 0:
                        return "off_page"
        elif ns(anc.tag) == "urn:schemas-microsoft-com:vml":
            style = (attr(anc, "style", "") or "").replace(" ", "").lower()
            if "visibility:hidden" in style or "display:none" in style:
                return "hidden_shape"
        elif k == "framePr":
            pass
        anc = parent.get(anc)
    return None


def scan_docx(pkg: Pkg, rep: Report, doc_main: str) -> None:
    theme = _theme_colors(pkg, next(iter(pkg.related(doc_main, "theme")), None))
    sroot = next((x for x in map(pkg.xml, pkg.related(doc_main, "styles")) if x is not None), None)
    styles = _Styles(sroot, theme)
    settings = next((x for x in map(pkg.xml, pkg.related(doc_main, "settings")) if x is not None), None)
    if settings is None:
        settings = pkg.xml("word/settings.xml")
    even_odd = settings is not None and first(settings, "evenAndOddHeaders") is not None and _true(
        attr(first(settings, "evenAndOddHeaders"), "val"), True)
    show_bg = settings is not None and first(settings, "displayBackgroundShape") is not None

    main = pkg.xml(doc_main)
    buckets: dict[str, list[str]] = {}
    fields: list[str] = []
    visible_pages = []
    if main is None:
        rep.safe_pages = []
        return
    page = _word_page(main)
    page_bg = (1.0, 1.0, 1.0)
    bgel = first(main, "background")
    if show_bg and bgel is not None:                   # Word shows w:background only when settings ask for it
        col = _word_color(bgel, theme, "color")
        page_bg = col if col not in (None, UNRESOLVED) else page_bg

    # headers / footers Word actually shows: referenced from a section, of an active type
    active, notes = set(), {"footnote": set(), "endnote": set()}
    for sect in (e for e in main.iter() if ln(e.tag) == "sectPr"):
        title_pg = first(sect, "titlePg") is not None and _true(attr(first(sect, "titlePg"), "val"), True)
        for ref in sect:
            if ln(ref.tag) in ("headerReference", "footerReference"):
                typ = attr(ref, "type", "default")
                if typ == "default" or (typ == "first" and title_pg) or (typ == "even" and even_odd):
                    tgt = pkg.target(doc_main, rid(ref))
                    if tgt and pkg.name(tgt):
                        active.add(pkg.name(tgt))
    for e in main.iter():
        if ln(e.tag) in ("footnoteReference", "endnoteReference"):
            notes[ln(e.tag)[:-9]].add(attr(e, "id"))
    parts = [(doc_main, main)]
    for k in ("header", "footer"):
        for n in pkg.related(doc_main, k):
            if n in active:
                parts.append((n, pkg.xml(n)))
            else:
                buckets.setdefault("unused_header_footer", []).append(_all_text(pkg.xml(n)))
    for k in ("footnotes", "endnotes"):
        for n in pkg.related(doc_main, k):
            root = pkg.xml(n)
            if root is None:
                continue
            for note in list(root):
                if ln(note.tag) not in ("footnote", "endnote"):
                    continue
                if attr(note, "type") in ("separator", "continuationSeparator", "continuationNotice") or \
                        attr(note, "id") not in notes[ln(note.tag)]:
                    root.remove(note)
                    if attr(note, "type") is None:
                        buckets.setdefault("unreferenced_note", []).append(_all_text(note))
            parts.append((n, root))

    for part, root in parts:
        if root is None:
            continue
        parent = {c: p for p in root.iter() for c in p}
        lines = []
        stack: list[list] = []                          # open fields: [state "code" | "result", code text]
        for p in root.iter():
            if ln(p.tag) != "p":
                continue
            ppr = child(p, "pPr")
            pstyle = child(ppr, "pStyle")
            pfl = styles.flags(attr(pstyle, "val") if pstyle is not None else styles.default_para)
            pbg = _word_color(child(ppr, "shd"), theme, "fill", "themeFill") if ppr is not None else None
            # enclosing table cell shading and table style
            cell_bg, table_variants, anc = None, [{}], parent.get(p)
            while anc is not None and ln(anc.tag) != "body":
                if ln(anc.tag) == "tc" and cell_bg is None:
                    tcpr = child(anc, "tcPr")
                    cell_bg = _word_color(child(tcpr, "shd"), theme, "fill", "themeFill") if tcpr is not None else None
                if ln(anc.tag) == "tbl" and table_variants == [{}]:
                    tst = first(child(anc, "tblPr"), "tblStyle")
                    sid = attr(tst, "val") if tst is not None else None
                    if sid:
                        base = styles.flags(sid)
                        table_variants = [base] + [{**base, **v} for v in styles.table.get(sid, [])]
                anc = parent.get(anc)
            box = _box_hidden(p, parent, page)
            vis = []
            for r in p.iter():
                if ln(r.tag) != "r":
                    continue
                anc, deleted, own_p = parent.get(r), False, True
                while anc is not None and anc is not p:
                    if ln(anc.tag) in ("del", "moveFrom"):
                        deleted = True
                    if ln(anc.tag) == "p":
                        own_p = False
                        break
                    anc = parent.get(anc)
                if not own_p:
                    continue
                rfl = _rpr_flags(child(r, "rPr"), theme)
                rstyle = styles.flags(rfl.get("rStyle") or styles.default_char)
                txt = ""
                for t in r:
                    k = ln(t.tag)
                    if k == "fldChar":
                        typ = attr(t, "fldCharType")
                        if typ == "begin":
                            stack.append(["code", ""])
                        elif typ == "separate" and stack:
                            stack[-1][0] = "result"
                        elif typ == "end" and stack:
                            fields.append(stack.pop()[1])
                    elif k == "instrText":
                        if stack:
                            stack[-1][1] += t.text or ""
                        else:
                            fields.append(t.text or "")
                    elif k in ("t", "delText"):
                        txt += t.text or ""
                    elif k == "tab":
                        txt += "\t"
                    elif k in ("br", "cr"):
                        txt += "\n"
                if not txt:
                    continue
                reason = ("tracked_deletion" if deleted else "field_code" if any(s[0] == "code" for s in stack)
                          else box)
                if reason is None:
                    for tv in table_variants:          # any table-style variant that hides it, hides it
                        fl = {**styles.defaults, **tv, **pfl, **rstyle, **rfl}
                        reason = _run_reason(fl, [pbg, cell_bg, page_bg])
                        if reason:
                            break
                if reason:
                    buckets.setdefault(reason, []).append(txt)
                else:
                    vis.append(txt)
            for fs in p.iter():
                if ln(fs.tag) == "fldSimple" and attr(fs, "instr"):
                    fields.append(attr(fs, "instr"))
            if vis:
                lines.append("".join(vis))
        fields += [s[1] for s in stack]
        visible_pages.append("\n".join(lines))
        if any(ln(e.tag) == "altChunk" for e in root.iter()):
            rep.findings.append(Finding(check="alt_chunk",
                                        message="document imports an embedded HTML/RTF/MHT chunk (altChunk)"))
            for rid, (typ, tgt, mode) in pkg.rels(part).items():
                if typ.endswith("/aFChunk") and mode != "External":
                    target = pkg.name(_resolve(part, tgt))
                    if target:
                        from .html import scan_html
                        sub = scan_html(pkg.read(target), target)
                        rep.findings += [f for f in sub.findings if f.check != "collapsed_text"]

    rep.safe_pages = [p for p in visible_pages]
    _field_checks(fields, rep)
    _report_buckets(rep, buckets)
    for part, ch in (("word/comments.xml", "comments"), ("word/commentsExtended.xml", "comments"),
                     ("word/glossary/document.xml", "glossary")):
        txt = _all_text(pkg.xml(part)) if pkg.name(part) else ""
        rep.findings += content_findings(txt, ch, side_channel=True)
    if settings is not None:
        dv = " ".join(attr(e, "val", "") or "" for e in settings.iter() if ln(e.tag) == "docVar")
        rep.findings += content_findings(dv, "document_variables", side_channel=True)


REMOTE_FIELD = re.compile(r"\b(INCLUDETEXT|INCLUDEPICTURE|IMPORT|LINK)\b", re.I)


def _field_checks(fields, rep):
    """Each field code joined from all its instrText pieces (Word reads them as one)."""
    for f in fields:
        s = " ".join(f.split())[:MAX_FORMULA]
        if re.search(r"\bDDE(AUTO)?\b", s, re.I):
            rep.findings.append(Finding(check="dde", message="DDE field: can launch a command when the document opens"))
        else:
            m = REMOTE_FIELD.search(s)
            if m and re.search(r"https?:|\\\\|file:", s[m.end():], re.I):
                rep.findings.append(Finding(check="remote_content", message="field pulls remote content when updated"))


def _report_buckets(rep, buckets, collapsed=()):
    for reason, texts in buckets.items():
        joined = " ".join(" ".join(t.split()) for t in texts)
        rep.findings += content_findings(joined, f"hidden text ({reason})")
        if reason in collapsed:
            if sum(c.isalnum() for c in joined) >= 3:
                rep.findings.append(Finding(check="collapsed_text",
                                            message=f"{len(texts)} hidden item(s) ({reason}); excluded from safe text"))
            continue
        rep.findings += hidden_text_finding(joined, rep.format, reason, count=len(texts))


# --------------------------------------------------------------------------- PPTX

PRESET = {"white": "FFFFFF", "black": "000000"}


def _theme(pkg: Pkg, master: str | None) -> dict:
    """Scheme colour name -> RGB (0..1), through the master's colour map (bg1 -> lt1, ...) and its theme."""
    colors = _theme_colors(pkg, next(iter(pkg.related(master, "theme")), None) if master else None)
    cmap = first(pkg.xml(master), "clrMap") if master else None
    alias = {"bg1": "lt1", "tx1": "dk1", "bg2": "lt2", "tx2": "dk2"}
    for k in alias:
        alias[k] = attr(cmap, k, alias[k]) if cmap is not None else alias[k]
    return {**colors, **{k: colors.get(v) for k, v in alias.items()}}


def _color(fill, theme):
    """(RGB 0..1, alpha 0..1) of a fill's colour (srgbClr, sysClr, schemeClr, prstClr, scrgbClr, hslClr) with its
    transforms (lumMod, lumOff, tint, shade, alpha) applied; None when there is none or it is unknown."""
    c = next(iter(fill), None) if fill is not None else None
    k = ln(c.tag) if c is not None else ""
    if k == "srgbClr":
        rgb = _hex(attr(c, "val", ""))
    elif k == "sysClr":
        rgb = _hex(attr(c, "lastClr", ""))
    elif k == "schemeClr":
        rgb = theme.get(attr(c, "val", ""))
    elif k == "prstClr":
        rgb = _hex(PRESET.get(attr(c, "val", ""), ""))
    elif k == "scrgbClr":
        rgb = tuple(max(0.0, min(1.0, _pct(attr(c, x, "0")))) for x in ("r", "g", "b"))
    elif k == "hslClr":
        rgb = colorsys.hls_to_rgb((_pct(attr(c, "hue", "0")) or 0) * 100000 / 21600000 % 1,
                                  _pct(attr(c, "lum", "0")), _pct(attr(c, "sat", "0")))
    else:
        return None
    if rgb is None:
        return None
    alpha = 1.0
    for t in c:
        n, v = ln(t.tag), _pct(attr(t, "val"), None)
        if v is None:
            continue
        if n == "lumMod":
            rgb = _hls_adjust(rgb, lambda l, v=v: l * v)
        elif n == "lumOff":
            rgb = _hls_adjust(rgb, lambda l, v=v: l + v)
        elif n == "tint":
            rgb = tuple(x * v + (1 - v) for x in rgb)
        elif n == "shade":
            rgb = tuple(x * v for x in rgb)
        elif n == "alpha":
            alpha = max(0.0, min(1.0, v))
        elif n == "alphaMod":
            alpha *= max(0.0, v)
    return tuple(rgb), alpha


def _fill_of(el, theme):
    """The colour of el's own fill child; "other" for a picture / gradient / pattern fill; "none" for noFill;
    None when it sets none."""
    if el is None:
        return None
    for c in el:
        k = ln(c.tag)
        if k == "solidFill":
            got = _color(c, theme)
            return got if got is not None else "other"
        if k in ("gradFill", "blipFill", "pattFill", "grpFill"):
            return "other"
        if k == "noFill":
            return "none"
    return None


def _slide_bg(pkg: Pkg, chain: list[str], theme):
    """Slide background: the first <p:bg> along slide -> layout -> master. White when none sets one; None when
    it is not one known colour (picture, gradient...): then colour checks are skipped."""
    for part in chain:
        root = pkg.xml(part)
        bg = first(root, "bg") if root is not None else None
        if bg is None:
            continue
        pr, ref = first(bg, "bgPr"), first(bg, "bgRef")
        got = _fill_of(pr, theme) if pr is not None else _color(ref, theme) if ref is not None else None
        return None if got in (None, "other", "none") else got[0]
    return (1.0, 1.0, 1.0)


def _int(el, name, default=0):
    try:
        return int(attr(el, name, str(default)) or default)
    except ValueError:
        raise limits.Refused("a shape position Office does not accept") from None


def _xfrm(el):
    """(x, y, cx, cy, chx, chy, chcx, chcy) of a shape's / group's xfrm, or None."""
    pr = next((c for c in el if ln(c.tag) in ("spPr", "grpSpPr")), None)
    xf = next((c for c in (pr if pr is not None else el) if ln(c.tag) == "xfrm"), None)
    if xf is None:
        return None
    o, e, co, ce = (child(xf, n) for n in ("off", "ext", "chOff", "chExt"))
    if o is None or e is None:
        return None
    x, y, cx, cy = _int(o, "x"), _int(o, "y"), _int(e, "cx"), _int(e, "cy")
    return (x, y, cx, cy, _int(co, "x", x) if co is not None else x, _int(co, "y", y) if co is not None else y,
            _int(ce, "cx", cx) if ce is not None else cx, _int(ce, "cy", cy) if ce is not None else cy)


def _placeholder(sp):
    nv = next((c for c in sp if ln(c.tag).startswith("nv")), None)
    ph = first(nv, "ph") if nv is not None else None
    return None if ph is None else (attr(ph, "type", "body") or "body", attr(ph, "idx", "0") or "0")


def _shapes(tree, ph_xfrm):
    """(shape, hidden, rect in slide EMU or None) for every sp / pic / graphicFrame under a spTree, in z-order,
    walking groups (a hidden group hides everything in it; child coordinates go through the group transform).
    A placeholder without its own position takes the layout's / master's (ph_xfrm)."""
    out, stack = [], [(c, False, None, None) for c in reversed(list(tree))]
    while stack:
        el, hidden, tf, grect = stack.pop()
        k = ln(el.tag)
        if k not in ("sp", "pic", "graphicFrame", "grpSp", "cxnSp"):
            continue
        nv = next((c for c in el if ln(c.tag).startswith("nv")), None)
        cnv = next((c for c in nv if ln(c.tag) == "cNvPr"), None) if nv is not None else None
        hidden = hidden or (cnv is not None and _true(attr(cnv, "hidden"), False))
        xf = _xfrm(el)
        if xf is None and k != "grpSp":
            ph = _placeholder(el)
            xf = ph_xfrm.get(ph) or ph_xfrm.get((ph[0], None)) if ph else None
        rect = grect                                        # no position of its own: where its group is
        if xf is not None:
            x, y, cx, cy = xf[:4]
            if tf is not None:                              # map child coordinates through each ancestor group
                for gx, gy, gcx, gcy, chx, chy, chcx, chcy in tf:
                    sx, sy = gcx / chcx if chcx else 1.0, gcy / chcy if chcy else 1.0
                    x, y, cx, cy = gx + (x - chx) * sx, gy + (y - chy) * sy, cx * sx, cy * sy
            rect = (x, y, cx, cy)
        if k == "grpSp":
            tfs = ([xf] if xf is not None else []) + list(tf or [])
            stack.extend((c, hidden, tfs, rect) for c in reversed(list(el)))
        else:
            out.append((el, hidden, rect))
    return out


def _ph_positions(pkg, parts) -> dict:
    """Placeholder (type, idx) -> xfrm, from the layout first, then the master (the first one found wins)."""
    out: dict = {}
    for part in parts:
        root = pkg.xml(part) if part else None
        tree = first(root, "spTree") if root is not None else None
        for sp in (tree.iter() if tree is not None else []):
            if ln(sp.tag) != "sp":
                continue
            ph, xf = _placeholder(sp), _xfrm(sp)
            if ph and xf:
                out.setdefault(ph, xf)
                out.setdefault((ph[0], None), xf)
    return out


def _lst_styles(pkg, parts) -> dict:
    """Placeholder type -> [lstStyle elements] from layout / master placeholders, then the master txStyles."""
    out: dict = {}
    master_styles = None
    for part in parts:
        root = pkg.xml(part) if part else None
        if root is None:
            continue
        for sp in root.iter():
            if ln(sp.tag) == "sp" and _placeholder(sp):
                lst = first(sp, "lstStyle")
                if lst is not None:
                    out.setdefault(_placeholder(sp)[0], []).append(lst)
        tx = first(root, "txStyles")
        if tx is not None:
            master_styles = tx
    if master_styles is not None:
        for typ, name in (("title", "titleStyle"), ("ctrTitle", "titleStyle"), ("body", "bodyStyle"),
                          ("subTitle", "bodyStyle"), ("obj", "bodyStyle"), (None, "otherStyle")):
            st = child(master_styles, name)
            if st is not None:
                out.setdefault(typ, []).append(st)
    return out


def _run_props(chain, theme):
    """(size in 1/100 pt or None, fill) of a run: the first value along its property chain (run rPr, the
    paragraph's level defRPr, the shape's list style, the placeholder's, the master's text styles), the shape
    style's fontRef colour last."""
    sz, fill = None, None
    for el in chain:
        if el is None:
            continue
        if sz is None and attr(el, "sz"):
            v = attr(el, "sz")
            if not v.isdigit():
                raise limits.Refused("a font size Office does not accept")
            sz = int(v)
        if fill is None and ln(el.tag) != "fontRef":
            fill = _fill_of(el, theme)
        elif fill is None:
            got = _color(el, theme)
            fill = got if got is not None else None
    return sz, fill


def _a_run_reason(chain, bg, theme, scale) -> str | None:
    sz, fill = _run_props(chain, theme)
    if sz is not None and sz * scale <= 150:
        return "tiny_font"
    if fill == "none":
        return "no_fill"
    if isinstance(fill, tuple):
        rgb, alpha = fill
        if alpha < 0.05:
            return "transparent"
        if bg is not None and contrast(tuple(c * alpha + b * (1 - alpha) for c, b in zip(rgb, bg)), bg) < 1.15:
            return "same_as_background"
    return None


def _covers(a, b) -> bool:
    """Rectangle a (x, y, cx, cy) covers at least 90% of rectangle b."""
    if a is None or b is None or b[2] <= 0 or b[3] <= 0:
        return False
    w = max(0, min(a[0] + a[2], b[0] + b[2]) - max(a[0], b[0]))
    h = max(0, min(a[1] + a[3], b[1] + b[3]) - max(a[1], b[1]))
    return w * h >= 0.9 * b[2] * b[3]


def scan_pptx(pkg: Pkg, rep: Report, main: str) -> None:
    pres = pkg.xml(main)
    sz = first(pres, "sldSz") if pres is not None else None
    W, H = (_int(sz, "cx", 9144000), _int(sz, "cy", 6858000)) if sz is not None else (9144000, 6858000)
    lst = first(pres, "sldIdLst") if pres is not None else None
    slides = [pkg.target(main, rid(s)) for s in (lst if lst is not None else []) if ln(s.tag) == "sldId"]
    slides = [pkg.name(s) for s in slides if s and pkg.name(s)]
    buckets: dict[str, list[str]] = {}
    for sn in slides:
        root = pkg.xml(sn)
        if root is None:
            rep.safe_pages.append("")
            continue
        layout = next(iter(pkg.related(sn, "slideLayout")), None)
        master = next(iter(pkg.related(layout, "slideMaster")), None) if layout else None
        theme = _theme(pkg, master)
        hidden_slide = not _true(attr(root, "show"), True)
        slide_bg = _slide_bg(pkg, [x for x in (sn, layout, master) if x], theme)
        tree = first(root, "spTree")
        ph_xfrm = _ph_positions(pkg, [layout, master])
        lst_styles = _lst_styles(pkg, [layout, master])
        shapes = _shapes(tree, ph_xfrm) if tree is not None else []
        lines = []
        for i, (sp, shape_hidden, rect) in enumerate(shapes):
            off_slide = rect is not None and (rect[0] >= W or rect[1] >= H or rect[0] + rect[2] <= 0
                                              or rect[1] + rect[3] <= 0)
            covered = rect is not None and any(
                _covers(r2, rect) and not h2 and (ln(s2.tag) == "pic" or _fill_of(child(s2, "spPr"), theme)
                                                   not in (None, "none"))
                for s2, h2, r2 in shapes[i + 1:])
            shape_fill = _fill_of(child(sp, "spPr"), theme)
            bg = slide_bg if shape_fill in (None, "none") else None if shape_fill == "other" else shape_fill[0]
            ph = _placeholder(sp)
            inherited = lst_styles.get(ph[0] if ph else None, []) + (lst_styles.get(None, []) if ph else [])
            style = child(sp, "style")
            font_ref = child(style, "fontRef") if style is not None else None
            cell_of = {b: tc for tc in sp.iter() if ln(tc.tag) == "tc" for b in tc if ln(b.tag) == "txBody"}
            for body in (e for e in sp.iter() if ln(e.tag) == "txBody"):
                bpr = child(body, "bodyPr")
                fit = child(bpr, "normAutofit") if bpr is not None else None
                scale = _pct(attr(fit, "fontScale"), 1.0) if fit is not None else 1.0
                own_lst = child(body, "lstStyle")
                cell = cell_of.get(body)
                cell_fill = _fill_of(child(cell, "tcPr"), theme) if cell is not None else None
                body_bg = bg if cell_fill in (None, "none") else None if cell_fill == "other" else cell_fill[0]
                for p in body:
                    if ln(p.tag) != "p":
                        continue
                    ppr = child(p, "pPr")
                    lvl = (attr(ppr, "lvl", "0") or "0") if ppr is not None else "0"
                    lvl_name = f"lvl{int(lvl) + 1 if lvl.isdigit() else 1}pPr"
                    level = [child(child(s, lvl_name), "defRPr") for s in [own_lst] + inherited if s is not None]
                    vis = []
                    for r in p:
                        if ln(r.tag) not in ("r", "fld"):
                            continue
                        t = child(r, "t")
                        txt = (t.text or "") if t is not None else ""
                        if not txt:
                            continue
                        chain = [child(r, "rPr"), child(ppr, "defRPr") if ppr is not None else None] + level + [font_ref]
                        reason = ("hidden_slide" if hidden_slide else "hidden_shape" if shape_hidden else
                                  "off_slide" if off_slide else "covered" if covered else
                                  _a_run_reason(chain, body_bg, theme, scale))
                        if reason:
                            buckets.setdefault(reason, []).append(txt)
                        else:
                            vis.append(txt)
                    if vis:
                        lines.append("".join(vis))
        rep.safe_pages.append("\n".join(lines))
    _report_buckets(rep, buckets)
    notes = " ".join(_all_text(pkg.xml(n)) for n in pkg.names if re.match(r"ppt/notesSlides/notesSlide\d+\.xml$", n))
    rep.findings += content_findings(notes, "speaker_notes")
    if notes.strip():
        rep.findings.append(Finding(check="side_channel_text",
                                    message="slides have speaker notes (many loaders index them)"))
    comments = " ".join(_all_text(pkg.xml(n)) for n in pkg.names if "/comments/" in n and n.endswith(".xml"))
    rep.findings += content_findings(comments, "comments", side_channel=True)


# --------------------------------------------------------------------------- XLSX

DANGER_FN = re.compile(r"\b(WEBSERVICE|CALL|REGISTER|EXEC|REGISTER\.ID|FOPEN|FWRITE|URLDOWNLOADTOFILE|SHELL)\s*\(", re.I)
DDE_FORMULA = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z0-9_]{1,255}\|'?[^'!]{0,1000}'?!", re.I)

FMT_COLORS = {"white": "FFFFFF", "black": "000000", "red": "FF0000", "green": "00FF00", "blue": "0000FF",
              "yellow": "FFFF00", "magenta": "FF00FF", "cyan": "00FFFF", "color1": "000000", "color2": "FFFFFF"}
INDEXED = ("000000 FFFFFF FF0000 00FF00 0000FF FFFF00 FF00FF 00FFFF 000000 FFFFFF FF0000 00FF00 0000FF FFFF00 FF00FF "
           "00FFFF 800000 008000 000080 808000 800080 008080 C0C0C0 808080 9999FF 993366 FFFFCC CCFFFF 660066 FF8080 "
           "0066CC CCCCFF 000080 FF00FF FFFF00 00FFFF 800080 800000 008080 0000FF 00CCFF CCFFFF CCFFCC FFFF99 99CCFF "
           "FF99CC CC99FF FFCC99 3366FF 33CCCC 99CC00 FFCC00 FF9900 FF6600 666699 969696 003366 339966 003300 333300 "
           "993300 993366 333399 333333 000000 FFFFFF").split()        # 64: system foreground, 65: background


def _sections(code: str) -> list[str]:
    """A number format split on ";" outside quotes and escapes."""
    out, cur, quoted, esc = [], [], False, False
    for ch in code:
        if esc:
            esc = False
        elif ch == "\\":
            esc = True
        elif ch == '"':
            quoted = not quoted
        elif ch == ";" and not quoted:
            out.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    out.append("".join(cur))
    return out


def _text_format(code: str):
    """How a number format shows a text value: "hidden" (no @ in a text section: the string is not shown), an
    RGB colour (a [Colour] in the section that shows it), or None (shown as is)."""
    secs = _sections(code)
    bare = [re.sub(r'"[^"]*"|\\.', "", x) for x in secs]
    if len(secs) >= 4:
        t = 3
    else:
        t = next((i for i, x in enumerate(bare) if "@" in x), None)
        if t is None:
            return None
    if "@" not in bare[t]:
        return "hidden"
    m = re.search(r"\[\s*(color\s*\d+|[a-z]+)\s*\]", bare[t], re.I)
    return _hex(FMT_COLORS.get(re.sub(r"\s", "", m.group(1).lower()), "")) if m else None


class _XlColors:
    """Spreadsheet colours: rgb, theme (with tint), indexed (default or the workbook's own palette), auto."""

    def __init__(self, styles, theme):
        self.theme = theme
        self.indexed = list(INDEXED)
        custom = first(styles, "indexedColors") if styles is not None else None
        for i, c in enumerate(kids(custom, "rgbColor")):
            if i < len(self.indexed):
                self.indexed[i] = (attr(c, "rgb", "") or "")[-6:]

    def __call__(self, el, auto=(0.0, 0.0, 0.0)):
        """RGB 0..1; `auto` for automatic; UNRESOLVED when it cannot be resolved; None when no colour is set."""
        if el is None:
            return None
        if _true(attr(el, "auto"), False):
            return auto
        if attr(el, "rgb"):
            rgb = _hex(attr(el, "rgb")[-6:])
        elif attr(el, "theme") is not None:
            try:
                rgb = self.theme.get(THEME_ORDER[int(attr(el, "theme"))])
            except (ValueError, IndexError):
                return UNRESOLVED
        elif attr(el, "indexed") is not None:
            try:
                rgb = _hex(self.indexed[int(attr(el, "indexed"))])
            except (ValueError, IndexError):
                return UNRESOLVED
        else:
            return None
        if rgb is None:
            return UNRESOLVED
        tint = attr(el, "tint")
        if tint:
            try:
                t = float(tint)
            except ValueError:
                return UNRESOLVED
            rgb = _hls_adjust(rgb, lambda l: l * (1 + t) if t < 0 else l * (1 - t) + t)
        return tuple(rgb)


def _cell_ref(ref: str):
    m = re.fullmatch(r"\$?([A-Za-z]{1,3})\$?(\d{1,7})", ref or "")
    if not m:
        return None
    return _col_index(m.group(1)), int(m.group(2))


def _ranges(sqref: str):
    """'A1:B2 C3' -> [(c0, r0, c1, r1)]; None when a part cannot be read."""
    out = []
    for part in (sqref or "").split():
        a, _, b = part.partition(":")
        p, q = _cell_ref(a), _cell_ref(b or a)
        if p is None or q is None:
            return None
        out.append((min(p[0], q[0]), min(p[1], q[1]), max(p[0], q[0]), max(p[1], q[1])))
    return out


def _run_hidden(rpr, colors, bg) -> str | None:
    """A rich-text run's own font: white / tiny."""
    if rpr is None:
        return None
    s = child(rpr, "sz")
    try:
        if s is not None and float(attr(s, "val", "11")) <= 1:
            return "tiny_font"
    except ValueError:
        return "tiny_font"
    col = colors(child(rpr, "color"))
    if col == UNRESOLVED:
        return "unresolved_color"
    if col is not None and contrast(col, bg) < 1.15:
        return "same_as_background"
    return None


def _string_runs(si):
    """(text, rPr or None) pieces of a shared or inline string: <t> and rich-text <r>; phonetic <rPh> skipped."""
    out = []
    for ch in si:
        if ln(ch.tag) == "t":
            out.append((ch.text or "", None))
        elif ln(ch.tag) == "r":
            out.append(("".join(t.text or "" for t in ch if ln(t.tag) == "t"), child(ch, "rPr")))
    return out


def scan_xlsx(pkg: Pkg, rep: Report, main: str) -> None:
    wb = pkg.xml(main)
    if wb is None:
        rep.error = "the workbook part is missing"
        return
    for dn in wb.iter():
        if ln(dn.tag) == "definedName" and re.match(r"^(_xlnm\.)?auto_(open|close)", attr(dn, "name", "") or "", re.I):
            rep.findings.append(Finding(check="macros", message="Auto_Open name runs macros on open"))
    theme = _theme_colors(pkg, next(iter(pkg.related(main, "theme")), None))
    st = next((x for x in map(pkg.xml, pkg.related(main, "styles")) if x is not None), None)
    colors = _XlColors(st, theme)
    ss = next((x for x in map(pkg.xml, pkg.related(main, "sharedStrings")) if x is not None), None)
    shared = [_string_runs(si) for si in (ss if ss is not None else []) if ln(si.tag) == "si"]
    fonts, fills, xfs, hide_fmt, text_fmt, dxfs = [], [], [], set(), {}, []
    if st is not None:
        for nf in st.iter():
            if ln(nf.tag) != "numFmt":
                continue
            code = attr(nf, "formatCode", "") or ""
            if re.fullmatch(r'\s*;\s*;\s*;\s*(@\s*)?', code):
                hide_fmt.add(attr(nf, "numFmtId"))
            elif _text_format(code) is not None:
                text_fmt[attr(nf, "numFmtId")] = _text_format(code)
        fonts_el, fills_el, xfs_el = child(st, "fonts"), child(st, "fills"), child(st, "cellXfs")
        for f in kids(fonts_el, "font"):
            c, s = child(f, "color"), child(f, "sz")
            try:
                size = float(attr(s, "val", "11")) if s is not None else 11.0
            except ValueError:
                size = 0.0
            fonts.append((colors(c), size))
        for f in kids(fills_el, "fill"):
            pat = child(f, "patternFill")
            solid = pat is not None and attr(pat, "patternType") == "solid"
            fills.append(colors(child(pat, "fgColor"), auto=(1.0, 1.0, 1.0)) if solid else None)
        for x in kids(xfs_el, "xf"):
            xfs.append((_int(x, "fontId"), _int(x, "fillId"), attr(x, "numFmtId", "0")))
        dxf_el = child(st, "dxfs")
        for d in kids(dxf_el, "dxf"):
            font = child(d, "font")
            dxfs.append(child(d, "numFmt") is not None or (font is not None and any(
                ln(c.tag) in ("color", "sz", "vertAlign") for c in font)))

    buckets: dict[str, list[str]] = {}
    for sh in wb.iter():
        if ln(sh.tag) != "sheet":
            continue
        name, state = attr(sh, "name", "?") or "?", attr(sh, "state", "visible") or "visible"
        if state not in ("visible", "hidden", "veryHidden"):
            raise limits.Refused("a sheet state Office does not accept")
        part = pkg.target(main, rid(sh))
        part = pkg.name(part) if part else None
        root = pkg.xml(part) if part else None
        if root is None:
            continue
        hidden_cols = []
        for c in root.iter():
            if ln(c.tag) == "col":
                try:
                    width = float(attr(c, "width", "9") or 9)
                except ValueError:
                    width = 0.0
                if _true(attr(c, "hidden"), False) or width < 0.5:
                    hidden_cols.append((_int(c, "min"), _int(c, "max")))
        fmt = first(root, "sheetFormatPr")
        zero_height = fmt is not None and _true(attr(fmt, "zeroHeight"), False)
        merged = [r for m in root.iter() if ln(m.tag) == "mergeCell" for r in (_ranges(attr(m, "ref", "")) or [])]
        cond = []
        for cf in root.iter():
            if ln(cf.tag) != "conditionalFormatting":
                continue
            ids = [attr(r, "dxfId") for r in kids(cf, "cfRule")]
            if any(i is None or not i.isdigit() or int(i) >= len(dxfs) or dxfs[int(i)] for i in ids if i is not None):
                rs = _ranges(attr(cf, "sqref", ""))
                if rs is None:
                    raise limits.Refused("a conditional format range cannot be read")
                cond += rs
        covered = _drawing_cover(pkg, part, colors)
        visible_sheet = state == "visible"
        lines = [f"## {name[:31]}"] if visible_sheet else []
        row_no = 0
        for row in root.iter():
            if ln(row.tag) != "row":
                continue
            row_no = int(attr(row, "r")) if (attr(row, "r") or "").isdigit() else row_no + 1
            try:
                ht = float(attr(row, "ht")) if attr(row, "ht") is not None else None
            except ValueError:
                ht = 0.0
            row_hidden = _true(attr(row, "hidden"), False) or (ht is not None and ht < 1) or (
                zero_height and not _true(attr(row, "customHeight"), False))
            cells, col_no = [], 0
            for c in row:
                if ln(c.tag) != "c":
                    continue
                ref = _cell_ref(attr(c, "r", ""))
                if attr(c, "r") is not None and ref is None:
                    raise limits.Refused("a cell reference cannot be read")
                col_no = ref[0] if ref else col_no + 1
                f = child(c, "f")
                if f is not None and f.text:
                    if len(f.text) > MAX_FORMULA:
                        raise limits.Refused("a formula is longer than Excel allows")
                    if DANGER_FN.search(f.text):
                        rep.findings.append(Finding(check="dangerous_formula",
                                                    message="formula calls a network/system function"))
                    if DDE_FORMULA.search(f.text):
                        rep.findings.append(Finding(check="dde", message="DDE formula can launch a command"))
                t = attr(c, "t", "n")
                v = child(c, "v")
                if t == "s" and v is not None and v.text and v.text.isdigit() and int(v.text) < len(shared):
                    runs = shared[int(v.text)]
                elif t == "inlineStr":
                    runs = _string_runs(child(c, "is")) if child(c, "is") is not None else []
                elif v is not None and v.text:
                    runs = [(v.text, None)]
                else:
                    continue
                reason, bg, font_reason = None, (1.0, 1.0, 1.0), None
                if state == "veryHidden":
                    reason = "very_hidden_sheet"
                elif state == "hidden":
                    reason = "hidden_sheet"
                elif row_hidden:
                    reason = "hidden_row"
                elif any(a <= col_no <= b for a, b in hidden_cols):
                    reason = "hidden_column"
                elif any(c0 <= col_no <= c1 and r0 <= row_no <= r1 and (col_no, row_no) != (c0, r0)
                         for c0, r0, c1, r1 in merged):
                    reason = "merged_cell"
                elif any(c0 <= col_no <= c1 and r0 <= row_no <= r1 for c0, r0, c1, r1 in cond):
                    reason = "conditional_format"
                elif any(c0 <= col_no <= c1 and r0 <= row_no <= r1 for c0, r0, c1, r1 in covered):
                    reason = "covered"
                else:
                    s = _int(c, "s")
                    if s < len(xfs):
                        fid, flid, nfid = xfs[s]
                        tf = text_fmt.get(nfid) if t in ("s", "inlineStr", "str") else None
                        fill = fills[flid] if flid < len(fills) else None
                        if fill == UNRESOLVED:
                            reason = "unresolved_color"
                        bg = fill if fill not in (None, UNRESOLVED) else bg
                        if reason:
                            pass
                        elif nfid in hide_fmt or tf == "hidden":
                            reason = "format_hides_value"
                        elif tf and contrast(tf, bg) < 1.15:
                            reason = "same_as_background"
                        elif fid < len(fonts):
                            fcol, fsz = fonts[fid]
                            if fsz <= 1:
                                font_reason = "tiny_font"
                            elif fcol == UNRESOLVED:
                                font_reason = "unresolved_color"
                            elif fcol and contrast(fcol, bg) < 1.15:
                                font_reason = "same_as_background"
                shown = []
                for text, rpr in runs:
                    why = reason or _run_hidden(rpr, colors, bg) or (font_reason if child(rpr, "color") is None
                                                                    or font_reason == "tiny_font" else None)
                    if why:
                        if t in ("s", "inlineStr", "str") or reason:
                            buckets.setdefault(why, []).append(text)
                    else:
                        shown.append(text)
                if shown:
                    cells.append("".join(shown))
            if cells:
                lines.append("\t".join(cells))
        if not visible_sheet:                          # its name is not shown either
            buckets.setdefault("very_hidden_sheet" if state == "veryHidden" else "hidden_sheet", []).append(name)
        rep.safe_pages.append("\n".join(lines))
    _report_buckets(rep, buckets,
                    collapsed=("hidden_row", "hidden_column"))
    comments = " ".join(_all_text(pkg.xml(n)) for n in pkg.names
                        if re.match(r"xl/(comments\d*|threadedComments/.*)\.xml$", n))
    rep.findings += content_findings(comments, "cell_comments", side_channel=True)


def _drawing_cover(pkg: Pkg, sheet_part: str, colors) -> list:
    """Cell ranges under a filled shape or picture of the sheet's drawing (drawn over the cells)."""
    out = []
    for d in pkg.related(sheet_part, "drawing"):
        root = pkg.xml(d)
        for anchor in (root if root is not None else []):
            if ln(anchor.tag) not in ("twoCellAnchor", "oneCellAnchor", "absoluteAnchor"):
                continue
            filled = any(ln(e.tag) == "pic" for e in anchor.iter()) or any(
                ln(e.tag) == "spPr" and _fill_of(e, {}) not in (None, "none") for e in anchor.iter())
            if not filled:
                continue
            fr, to = child(anchor, "from"), child(anchor, "to")
            if fr is None:
                if ln(anchor.tag) == "absoluteAnchor":
                    out.append((1, 1, 16384, 1048576))      # position in EMU: may lie over any cell
                continue
            try:
                c0, r0 = int(child(fr, "col").text) + 1, int(child(fr, "row").text) + 1
                if to is not None:
                    c1, r1 = int(child(to, "col").text), int(child(to, "row").text)
                    c1 += 1 if int(child(to, "colOff").text or 0) > 0 else 0
                    r1 += 1 if int(child(to, "rowOff").text or 0) > 0 else 0
                else:
                    c1, r1 = c0, r0
            except (AttributeError, TypeError, ValueError):
                raise limits.Refused("a drawing anchor cannot be read") from None
            out.append((c0, r0, max(c0, c1), max(r0, r1)))
    return out


def _col_index(ref: str) -> int:
    n = 0
    for ch in re.match(r"[A-Z]*", ref.upper()).group(0):
        n = n * 26 + ord(ch) - 64
    return n


# --------------------------------------------------------------------------- entry points

KINDS = {"document": "docx", "presentation": "pptx", "workbook": "xlsx"}     # root element of the main part
FIXED = {"docx": "word/document.xml", "pptx": "ppt/presentation.xml", "xlsx": "xl/workbook.xml"}


def scan_ooxml(raw: bytes, name: str = "<bytes>") -> Report:
    """A zip must be DOCX, XLSX or PPTX (decided from its entries, after the archive limits); else a reject."""
    rep = Report(path=name, format="zip")
    try:
        pkg = Pkg(raw, rep)
    except (zipfile.BadZipFile, ValueError) as e:
        ours = isinstance(e, (limits.Refused, zipfile.BadZipFile))      # the central directory's messages are fixed
        rep.error = str(e) if ours else f"not a zip file ({type(e).__name__})"
        rep.findings.append(Finding(check="malformed_archive", message=rep.error))
        return rep
    # Office opens the part the package relationship names (officeDocument), whatever it is called.
    try:
        mains = pkg.related("", "officeDocument")
    except limits.Refused as e:
        rep.error = str(e)
        return rep
    root = pkg.xml(mains[0]) if len(mains) == 1 else None
    kind = KINDS.get(ln(root.tag)) if root is not None else None
    if kind is None:
        rep.error = "zip archive is not a DOCX, XLSX or PPTX document"
        return rep
    if any(pkg.name(fixed) and pkg.name(fixed) != mains[0] for fixed in FIXED.values()):
        rep.error = "the document's main part is not the one its standard name suggests"
        return rep
    rep.format = kind
    try:
        {"docx": scan_docx, "pptx": scan_pptx, "xlsx": scan_xlsx}[kind](pkg, rep, mains[0])
    except ValueError as e:                          # only our own messages: a parse error can quote the file
        rep.error = str(e) if isinstance(e, limits.Refused) else f"cannot read the {kind} ({type(e).__name__})"
    common_checks(pkg, rep)
    rep.findings += content_findings("\n\f".join(rep.safe_pages), "visible text")
    return rep
