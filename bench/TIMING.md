# PDF timing: page cap and worker timeout

`MAX_PDF_PAGES` and `WORKER_SECONDS` in `readerguard/limits.py` are set together from this run.

Run it with `.venv/bin/python -m bench.timing`. It builds synthetic PDFs with pymupdf and times `scan()` from end
to end: the gate, the worker child process (start-up, rlimits, JSON reply) and the host checks. The caps are
lifted during the run so the real time is measured.

- **Ordinary pages:** about 45 lines of text, a picture on every 4th page, and three hidden spans (white text,
  1 pt text, text under a box) on every 3rd page.
- **Dense pages:** 1,080 separate 6 pt words per page, each in its own text object. Every span gets its own
  pixel check.
- **Block pages:** about 2,000 6 pt words per page, written as one text object (pymupdf `TextWriter`, as some PDF
  makers do). This is the slowest case.

## Measured (2026-11-17)

Machine: Apple M1 Pro (10 cores, 16 GB), macOS, Python 3.11, PyMuPDF 2.1.

| PDF | pages | total s | s / page |
|---|---:|---:|---:|
| ordinary | 10 | 0.93 | 0.093 |
| ordinary | 50 | 2.73 | 0.055 |
| ordinary | 100 | 5.00 | 0.050 |
| ordinary | 200 | 9.78 | 0.049 |
| ordinary | 400 | 19.72 | 0.049 |
| dense | 200 | 21.19 | 0.106 |
| block (re-run with the visibility fix below) | 200 | 24.94 | 0.125 |
| ordinary, 4 scans at once (slowest) | 200 | 10.37 | 0.052 |
| dense, 4 scans at once (slowest) | 200 | 22.01 | 0.110 |
| ordinary, `page_images=True` | 50 | 4.41 | 0.088 |

Re-measured after the per-glyph visibility pass (safe_text built from an allow-list of visible traced glyphs, each
glyph judged on the pixels it owns), same machine:

| PDF | pages | total s | s / page |
|---|---:|---:|---:|
| ordinary | 200 | 13.30 | 0.066 |
| dense | 200 | 25.98 | 0.130 |
| block | 200 | 26.74 | 0.134 |
| ordinary, 4 scans at once (slowest) | 200 | 14.23 | 0.071 |
| ordinary, `page_images=True` | 50 | 5.47 | 0.109 |

The time grows in a straight line with the number of pages. There is a fixed cost of about 0.5 s for each child
process. Block pages are the slowest layout that reaches 200 pages: about 25 s. One content stream per word
(what one `insert_text` call per word writes) took 0.16 to 0.19 s per page at 50 pages. But such a file
passes the 25 MB input cap at about 130 pages, so it cannot reach the page cap. At the size cap it takes about 25 s.

Block pages used to be rejected as "no visible text". The "tiny" check divided a span's box width by all its
characters, so a span holding a whole page of lines looked squashed. `pdf/visibility.py` now measures width per
character line by line (`_advance`). Tests are in `tests/test_pdf.py`.

## Caps

- **`MAX_PDF_PAGES = 200`, `WORKER_SECONDS = 60` (unchanged).** The slowest measured case at the page cap (block pages)
  takes about 25 s, which leaves about 2.4x headroom. Ordinary pages take about 10 s, which leaves about 6x. Running
  four scans at once (`WORKER_CONCURRENCY`) barely changes the time on 10 cores.
- **`MAX_PAGE_IMAGES = 50`:** takes about 4.5 s, well inside the limit.
- `tests/test_timing.py` checks that `MAX_PDF_PAGES x 0.15 s x 2 <= WORKER_SECONDS`, so neither cap can be raised
  without the other.

## Caveats

- These are synthetic pages. Real PDFs with heavy vector art or large images can render more slowly per page.
- The child's CPU rlimit is also `WORKER_SECONDS`, so a slower CPU turns into rejects, never hangs.
- The container recipe in the README (`--cpus 2`) with 4 scans at once gives each scan about half a core. That
  roughly doubles these times, which puts the dense case near the limit. Re-run this script on the production
  host, and raise `WORKER_SECONDS` there (or lower `WORKER_CONCURRENCY`) if the slowest row is over half of it.
