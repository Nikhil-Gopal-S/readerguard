"""Time scan() end to end (gate + worker child) on synthetic PDFs, to set MAX_PDF_PAGES and WORKER_SECONDS.

    .venv/bin/python -m bench.timing                 # 10, 50, 100, 200, 400 pages
    .venv/bin/python -m bench.timing 25 300          # other sizes

Each page: a text column (~45 lines), a picture on every 4th page, and hidden spans (white text, 1 pt text,
text under a box) on every 3rd. The caps are lifted for the run so the real time is measured. Extra rows time
a "dense" PDF (about 1,000 small spans per page), a "block" PDF (about 2,000 words in one text object per page,
the slowest case), WORKER_CONCURRENCY scans at once, and page_images=True at MAX_PAGE_IMAGES pages.
"""
from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor

import pymupdf

from readerguard import limits, scan

WORDS = ("the quarterly report covers revenue costs and outlook for each region with notes on hiring "
         "supply contracts and the risks the board asked about in march").split()


def picture(seed: int) -> bytes:
    pm = pymupdf.Pixmap(pymupdf.csRGB, pymupdf.IRect(0, 0, 400, 300), False)
    pm.set_rect(pm.irect, ((seed * 37) % 256, 120, 200))
    for x in range(0, 400, 7):                           # some structure so it is not a flat fill
        pm.set_rect(pymupdf.IRect(x, 0, x + 3, 300), ((x * seed) % 256, 40, 90))
    return pm.tobytes("png")


def make_pdf(pages: int, dense: bool = False, block: bool = False) -> bytes:
    doc = pymupdf.open()
    for p in range(pages):
        page = doc.new_page()                            # A4-ish 595 x 842
        if block:                                        # slowest case: ~2,000 words in one text object per page
            tw = pymupdf.TextWriter(page.rect)
            tw.fill_textbox(pymupdf.Rect(30, 30, 565, 812), " ".join(f"word{i % 12}" for i in range(2000)),
                            fontsize=6)
            tw.write_text(page)
            continue
        if dense:                                        # slow case: ~1,000 small spans per page
            page.insert_font(fontname="helv")            # one text object per word, written directly
            ops = [f"BT /helv 6 Tf {w % 3 / 3:.2f} 0 0 rg 1 0 0 1 {30 + 45 * w} {812 - 9 * line} Tm (word{w}) Tj ET"
                   for line in range(90) for w in range(12)]
            xref = doc.get_new_xref()
            doc.update_object(xref, "<<>>")
            doc.update_stream(xref, "\n".join(ops).encode())
            doc.xref_set_key(page.xref, "Contents", f"{xref} 0 R")
            continue
        y = 60
        for line in range(45):
            words = [WORDS[(p * 7 + line * 3 + i) % len(WORDS)] for i in range(14)]
            page.insert_text((50, y), " ".join(words), fontsize=9)
            y += 16
        if p % 4 == 0:
            page.insert_image(pymupdf.Rect(300, 600, 540, 780), stream=picture(p + 1))
        if p % 3 == 0:
            page.insert_text((50, 790), "white text the reader never sees", fontsize=9, color=(1, 1, 1))
            page.insert_text((50, 800), "one point text nobody can read", fontsize=1)
            page.insert_text((50, 815), "text hidden under a box", fontsize=9)
            page.draw_rect(pymupdf.Rect(45, 805, 250, 820), color=(1, 1, 1), fill=(1, 1, 1))
    return doc.tobytes(garbage=3, deflate=True)


def timed(raw: bytes, **kw) -> tuple[float, object]:
    t = time.perf_counter()
    r = scan(raw, name="timing.pdf", **kw)
    return time.perf_counter() - t, r


def main(sizes: list[int]) -> None:
    cap, timeout, k = limits.MAX_PDF_PAGES, limits.WORKER_SECONDS, limits.WORKER_CONCURRENCY
    limits.MAX_PDF_PAGES = max(sizes + [limits.MAX_PDF_PAGES])   # measure past the cap
    limits.WORKER_SECONDS = 3600
    print(f"{'pages':>6} {'MB':>6} {'total s':>8} {'s/page':>7}  result")
    for n in sizes:
        raw = make_pdf(n)
        secs, r = timed(raw)
        state = "accept" if r.safe else f"reject: {r.message}"
        print(f"{n:>6} {len(raw) / 1e6:>6.2f} {secs:>8.2f} {secs / n:>7.3f}  {state}, removed={r.removed}")
    for label, kw in (("dense pages", {"dense": True}), ("one text block per page", {"block": True})):
        secs, r = timed(make_pdf(cap, **kw))
        print(f"{cap:>6} {'':>6} {secs:>8.2f} {secs / cap:>7.3f}  {label}: {'accept' if r.safe else r.message}")
    raw = make_pdf(cap)
    with ThreadPoolExecutor(k) as ex:
        worst = max(s for s, _ in ex.map(lambda _: timed(raw), range(k)))
    print(f"{cap:>6} {'':>6} {worst:>8.2f} {worst / cap:>7.3f}  slowest of {k} scans at once")
    n = limits.MAX_PAGE_IMAGES
    secs, r = timed(make_pdf(n), page_images=True)
    print(f"{n:>6} {'':>6} {secs:>8.2f} {secs / n:>7.3f}  page_images=True: {len(r.safe_images)} PNGs")
    print(f"cap: {cap} pages, worker timeout: {timeout} s")


if __name__ == "__main__":
    main([int(a) for a in sys.argv[1:]] or [10, 50, 100, 200, 400])
