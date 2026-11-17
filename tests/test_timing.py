"""The PDF page cap and the worker timeout are set together from bench/timing.py (see bench/TIMING.md)."""
import pymupdf

from bench.timing import make_pdf
from readerguard import limits, scan

SLOWEST_SECONDS_PER_PAGE = 0.15   # slowest measured (0.134, block pages; bench/TIMING.md), rounded up


def test_page_cap_fits_the_worker_timeout_with_2x_headroom():
    assert limits.MAX_PDF_PAGES * SLOWEST_SECONDS_PER_PAGE * 2 <= limits.WORKER_SECONDS


def test_page_images_cap_is_within_the_page_cap():
    assert limits.MAX_PAGE_IMAGES <= limits.MAX_PDF_PAGES


def test_synthetic_pdf_scans_with_its_hidden_spans_removed():
    r = scan(make_pdf(4), name="t.pdf")
    assert r.safe and r.removed == {"hidden_text": 6}   # pages 0 and 3, three hidden spans each
    assert "quarterly report" in r.safe_text and "white text" not in r.safe_text


def test_dense_synthetic_pdf_is_one_span_per_word_and_all_visible():
    raw = make_pdf(1, dense=True)
    assert len(list(pymupdf.open("pdf", raw)[0].get_texttrace())) == 1080
    r = scan(raw, name="d.pdf")
    assert r.safe and not r.removed and r.safe_text.count("word11") == 90


def test_block_synthetic_pdf_is_one_span_per_page_and_all_visible():
    raw = make_pdf(1, block=True)
    assert len(list(pymupdf.open("pdf", raw)[0].get_texttrace())) == 1
    r = scan(raw, name="b.pdf")
    assert r.safe and not r.removed and r.safe_text.count("word11") == 2000 // 12
