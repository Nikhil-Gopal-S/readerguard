"""Document-level checks: active content, side channels that carry text outside the page content,
and structural tricks (hidden layers)."""
from __future__ import annotations

import re

import pymupdf

from ..findings import Finding

_ACTIVE = [
    (re.compile(rb"/(JS|JavaScript)\b"), "javascript", "document contains JavaScript"),
    (re.compile(rb"/Launch\b"), "launch_action", "document contains a Launch action (runs an external program)"),
    (re.compile(rb"/(SubmitForm|ImportData)\b"), "form_action", "document submits or imports form data"),
    (re.compile(rb"/RichMedia\b|/XFA\b"), "rich_content", "document contains RichMedia or XFA content"),
]


def side_channel_texts(doc) -> list[tuple[str, int | None, str]]:
    """(channel, page, text) for text that lives outside the page content stream.

    Many RAG loaders copy these into chunk text or metadata (titles, keywords, comments)."""
    out: list[tuple[str, int | None, str]] = []
    for k, v in (doc.metadata or {}).items():
        if v and k not in ("format", "encryption", "creationDate", "modDate"):
            out.append((f"metadata.{k}", None, str(v)))
    try:
        xmp = doc.get_xml_metadata()
    except Exception:
        xmp = ""
    if xmp:
        body = re.sub(r"<[^>]+>", " ", xmp)
        out.append(("xmp", None, body))
    for pno, page in enumerate(doc):
        for a in page.annots() or []:
            info = a.info or {}
            text = " ".join(x for x in (info.get("content"), info.get("title"), info.get("subject")) if x)
            if text.strip():
                hidden = bool(a.flags & (pymupdf.PDF_ANNOT_IS_HIDDEN | pymupdf.PDF_ANNOT_IS_NO_VIEW))
                out.append((f"annotation.{a.type[1]}{'.hidden' if hidden else ''}", pno, text))
        for wdg in page.widgets() or []:
            if wdg.field_value and str(wdg.field_value).strip() not in ("", "Off"):
                out.append(("form_field", pno, str(wdg.field_value)))
    for i in range(doc.embfile_count()):
        info = doc.embfile_info(i)
        out.append(("embedded_file.name", None, f"{info.get('filename', '')} {info.get('description', '')}"))
        try:
            data = doc.embfile_get(i)
            if len(data) < 2_000_000:
                out.append(("embedded_file.content", None, data.decode("utf-8", "ignore")))
        except Exception:
            pass
    return out


# A text render mode that adds glyphs to the clip path (4-7). The text-stripped copy loses such clips, so the ink
# test cannot judge what is painted through them, and clip-only text (7) is never traced: refused outright.
_CLIP_TR = re.compile(rb"(?:^|[\s\[\]()<>/{}])\+?0*[4-7](?:\.0*)?(?:\s|%[^\r\n]*[\r\n])+Tr(?![^\s\[\]()<>/{}%])")


def uses_clip_text(doc) -> bool:
    """Any content stream (pages, forms, Type3 glyphs, annotation appearances) that sets render mode 4-7."""
    for x in range(1, doc.xref_length()):
        try:
            if not doc.xref_is_stream(x) or doc.xref_get_key(x, "Subtype")[1] == "/Image":
                continue
            data = doc.xref_stream(x)
        except Exception:
            continue
        if data and b"Tr" in data and _CLIP_TR.search(data):
            return True
    return False


def structural_findings(doc) -> list[Finding]:
    f: list[Finding] = []
    seen = set()
    for x in range(1, doc.xref_length()):
        try:
            obj = doc.xref_object(x, compressed=False).encode("latin-1", "ignore")
        except Exception:
            continue
        for rx, check, msg in _ACTIVE:
            if check not in seen and rx.search(obj):
                seen.add(check)
                f.append(Finding(check=check, message=msg))
    cat = doc.pdf_catalog()
    oa = doc.xref_get_key(cat, "OpenAction")
    if oa[0] != "null" and "javascript" in seen:
        f.append(Finding(check="open_action", message="JavaScript runs when the document opens"))

    try:
        ocgs = doc.get_ocgs() or {}
    except Exception:
        ocgs = {}
    off = [v.get("name", "?") for v in ocgs.values() if not v.get("on", True)]
    if off:
        f.append(Finding(check="hidden_layer",
                         message=f"{len(off)} optional-content layer(s) are off by default; their text is "
                                 "invisible in viewers but extracted by some parsers"))

    # attached files: the EmbeddedFiles name tree, file attachment annotations, and any other file
    # specification that carries an embedded stream (/EF), wherever it is referenced from
    n = doc.embfile_count() + sum(a.type[0] == pymupdf.PDF_ANNOT_FILE_ATTACHMENT for p in doc for a in p.annots())
    ef = sum(doc.xref_get_key(x, "EF")[0] != "null" for x in range(1, doc.xref_length()))
    n = max(n, ef)
    if n:
        f.append(Finding(check="embedded_file",
                         message=f"{n} embedded file(s); loaders that unpack attachments will ingest them"))
    return f
