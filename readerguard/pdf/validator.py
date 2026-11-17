"""PDF: visible-only text, removal counts and, on request, page PNGs (rendered with annotations)."""
from __future__ import annotations

import pymupdf

from .. import limits
from ..content import content_findings
from ..findings import Report
from . import structure
from .visibility import analyze_page, strip_text

pymupdf.TOOLS.mupdf_display_errors(False)


def scan_pdf(raw: bytes, name: str = "<bytes>", *, page_images: bool = False) -> Report:
    rep = Report(path=name, format="pdf")
    try:
        doc = pymupdf.open("pdf", raw)
    except Exception as e:
        rep.error = f"cannot open PDF ({type(e).__name__})"   # MuPDF's message can quote the file
        return rep
    if doc.needs_pass:
        rep.error = "encrypted PDF (password required), contents cannot be inspected"
        return rep
    if doc.page_count > limits.MAX_PDF_PAGES:
        rep.error = f"PDF has {doc.page_count} pages, over the {limits.MAX_PDF_PAGES}-page limit"
        return rep
    if page_images and doc.page_count > limits.MAX_PAGE_IMAGES:
        raise limits.OverLimit(f"PDF has {doc.page_count} pages, over the {limits.MAX_PAGE_IMAGES}-page limit "
                               "for page images")

    if structure.uses_clip_text(doc):
        raise limits.Refused("PDF draws text as a clipping path (text render modes 4-7), which is not accepted")
    rep.findings += structure.structural_findings(doc)
    bare = strip_text(doc)
    for pno in range(doc.page_count):
        page = doc[pno]
        pr = analyze_page(page, bare[pno], pno)
        rep.findings += pr.findings
        rep.safe_pages.append(pr.safe_text)
        rep.findings += content_findings(pr.safe_text, "page_text", pno)

    if page_images:
        rep.images = [page_png(doc[pno]) for pno in range(doc.page_count)]

    for channel, pno, text in structure.side_channel_texts(doc):
        side = channel.startswith(("annotation", "embedded_file.content", "form_field"))
        rep.findings += content_findings(text, channel, pno, side_channel=side)
    return rep


def page_png(page) -> bytes:
    """The page as a new PNG, annotations included, scaled so its longer side is MAX_IMAGE_PX."""
    z = limits.MAX_IMAGE_PX / max(1.0, page.rect.width, page.rect.height)
    pm = page.get_pixmap(matrix=pymupdf.Matrix(z, z), alpha=False, colorspace=pymupdf.csRGB, annots=True)
    return pm.tobytes("png")
