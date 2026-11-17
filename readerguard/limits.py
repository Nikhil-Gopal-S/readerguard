"""Every cap in one place. Going over any of them is a reject.

MAX_PDF_PAGES and WORKER_SECONDS are set together from bench/timing.py (numbers in bench/TIMING.md): the
slowest measured PDF takes about 0.125 s per page (under 0.15 s), so 200 pages finish in about 25 s, over 2x
inside 60 s.
Raise one only with the other, and re-run the benchmark on the machine that will run the scans.
"""
MB = 1_000_000


class Refused(ValueError):
    """An extractor refused the input. Its message is ours (no file content), so the reject reason keeps it."""


class OverLimit(Refused):
    """An extractor went over a cap."""


MAX_FILE_BYTES = 25 * MB             # any input: bytes, path, file object, fetched body
MAX_SAFE_TEXT_BYTES = 5 * MB         # rebuilt text, UTF-8 encoded

MAX_PDF_PAGES = 200
MAX_PAGE_IMAGES = 50                 # page PNGs per PDF, when asked for

MAX_IMAGE_PIXELS = 40_000_000        # width x height allowed to be decoded
MAX_IMAGE_PX = 1568                  # longest side of a rebuilt image

MAX_ZIP_ENTRIES = 1000               # Office (DOCX / XLSX / PPTX) archives
MAX_ZIP_BYTES = 100 * MB             # total expanded size
MAX_ZIP_RATIO = 100                  # expanded : compressed

WORKER_SECONDS = 60
WORKER_MEMORY_BYTES = 1_000_000_000
WORKER_CONCURRENCY = 4               # per host PROCESS: a server with N processes runs up to N x 4 workers
MAX_FINDINGS = 10_000                # removal / reject notes per input; more is a reject
# the child's JSON reply (ASCII): safe_text (at most 6 bytes per escaped character), findings, base64 page PNGs
MAX_WORKER_OUTPUT_BYTES = 6 * MAX_SAFE_TEXT_BYTES + 120 * MB

FETCH_SECONDS = 20
MAX_REDIRECTS = 3
MAX_STYLESHEETS = 20
MAX_STYLESHEET_BYTES = 5 * MB        # all linked stylesheets of one page together
IOC_MAX_AGE_SECONDS = 24 * 3600      # domain threat lists older than this are a reject (see ioc.py)
