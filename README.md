# ReaderGuard

**The AI reads only what a person can see, rebuilt from scratch. That does not make it safe or true.**

ReaderGuard is a Python library and command-line tool. You give it a file or a web link. It never passes the
original on. Instead it rebuilds the input into **only what a person can see**: plain text, or fresh PNG
images. Anything that goes wrong is a reject.

You get one of two answers:

- **accept**: here is the visible text (`safe_text`) and/or rebuilt images (`safe_images`), plus a count of
  what was left out (for example `{"hidden_text": 3, "macros": 1}`).
- **reject**: here is the reason. No content.

It works on PDF, web pages, Word, PowerPoint, Excel, Markdown, plain text and images.

## The problem

AI apps read documents for you: a chatbot answers from company files, an assistant summarises a web page, a
support bot reads an uploaded PDF. To do that, the app uses a *loader* that pulls the text out of the file. A
loader does not look at the page the way a person does. It takes **all** the text, including text nobody can
see:

- white text on a white background, or text so small it is invisible
- text off the edge of the page, behind an image, or under a box
- hidden slides, sheets, rows, comments and speaker notes
- invisible Unicode characters
- metadata (author, title, photo EXIF data)

A person checking the document sees nothing wrong. The AI reads every word. An attacker can use this to give
the AI orders (*prompt injection*) or to plant false facts.

ReaderGuard closes that gap by giving the AI only what a person would see. It does **not** judge the visible
words. A visible lie or a visible "ignore your instructions" stays in `safe_text`. That is why the promise
ends with "that does not make it safe or true", and why your app must also follow the
[rules for your app](#rules-for-your-app).

## How it works

Six parts. The first one needs the network; everything after it can run with no network at all.

```
   file / bytes                              URL
        |                                     |
        |              [1] SAFE FETCHER  (network, parses nothing)
        |              http/https, ports 80/443, IPv4 only, threat lists,
        |              public addresses only, <=3 redirects, 20 s, size cap
        +------------------+------------------+
                           v
 ===== in production, everything below runs with no network =====
   [2] GATE  (reads the first bytes only)
       size cap -> type from content: pdf | image | zip | text
       anything else -> reject; the file gets a random ID
                           v
   +-------------------------------------------------------------+
   | [3] WORKER  a fresh child process for every file            |
   |     time, CPU and memory caps; at most 4 at once            |
   |                                                             |
   | [4] REBUILD  keep only what a person can see                |
   |     zip   : must be Word / Excel / PowerPoint, else reject  |
   |     text  : visible text only                               |
   |     image : first frame -> flatten -> resize -> new PNG     |
   |     PDF   : text that makes ink on the page (+ page PNGs)   |
   |     and a count of everything it left out                   |
   +-------------------------------------------------------------+
                           v
   [5] FINISH + VERDICT  (the worker's output is not trusted)
       size cap, valid UTF-8, invisible Unicode removed here
       reject  |  accept (+ removed counts)
                           v
   safe_text / safe_images only            the original is dropped
                           v
   [6] RULES FOR YOUR APP: serve safely, prompt safely
```

1. **Safe fetcher.** Turns a URL into bytes and parses nothing. Only `http` and `https` on ports 80 and 443,
   IPv4 only. Before any lookup it checks the host against local [threat lists](#domain-threat-lists). Every
   address the name resolves to must be public, and it connects to that checked address (TLS is still checked
   against the host name). At most 3 redirects, each checked again. One 20-second deadline, a size cap, no
   compression, no proxies, no cookies, no passwords.
2. **Gate.** Size cap first. Then it picks a family from the first bytes of the content (PDF, image, zip or
   text). The file name plays no part, and the result gets a random ID instead.
3. **Worker.** Every file is parsed in a fresh child process with time, CPU and memory caps and a kill timer.
   A file that crashes or hangs the parser is a reject and cannot hurt the next file. The worker is for
   crashes and hangs; the real security wall is the [container](#production-recipe) around the scan step.
4. **Rebuild.** One extractor per family keeps only what a person can see. Metadata, comments, notes, alt
   text, hidden parts, macros and scripts are left out and counted.
5. **Finish and verdict.** The worker's reply is checked again: size, valid UTF-8, the right shape. Invisible
   Unicode is removed here. Any error anywhere is a reject.
6. **Rules for your app.** Not code: a short list of things your app must do. See
   [Rules for your app](#rules-for-your-app).

**How each family is rebuilt:**

- **PDF:** each page is drawn twice, with and without its text. Text is kept only if it puts ink on the page,
  checked character by character where something is drawn over a line or the background under it changes.
  Annotations are drawn too, so text under a box counts as hidden, even when the box covers only part of a line. Invisible OCR layers are dropped, so a
  scanned PDF has no visible text: ask for page images (`page_images=True`) or it is rejected.
- **Web pages:** visible text after inline styles, `<style>` blocks and linked stylesheets are applied
  (zero size, same colour as the background, transparent, off screen, `display:none` and so on), with
  specificity and `!important`. Rules inside `@media` (all but print-only), `@supports`, `@layer` and nested
  rules apply without checking their conditions. Elements the browser hides by itself (`<title>` in the body, a
  closed `<dialog>` or `<details>`, fallback content of `<iframe>`, `<video>`, `<object>` and so on) are left
  out. A rule whose selector uses a pseudo-class ReaderGuard does not evaluate (`:nth-child`, `:not`, `:has`...)
  may hide text but never show it. Scripts are never fetched or run.
- **Word, PowerPoint, Excel:** visible text only, from the parts Office itself opens (found through the
  package relationships, not by file name). Hidden text, slides, sheets, rows, columns, shapes and groups,
  comments, notes, tracked deletions and markup-compatibility fallbacks are left out. XML is read with
  `defusedxml`, which blocks XXE.
- **Markdown and plain text:** comments are dropped (an unclosed `<!--` runs to the end, as it does when
  rendered), raw HTML goes through the web page rules, and links and images keep their label only (the link
  target is dropped).
- **Images:** first frame only, flattened onto white, 8-bit RGB, shrunk with an averaging filter so the
  longer side is at most 1568 px, saved as a brand-new PNG with no metadata. Text drawn inside the image is
  not read.
- **Invisible Unicode (all text):** control and format characters, private-use and unassigned characters,
  variation selectors (except the emoji one) and Hangul fillers are removed. Single joiners needed for emoji,
  Persian and Indian scripts are kept.

## Accept or reject

| result | when | your app gets |
|---|---|---|
| **reject** | the link could not be fetched or is on a threat list, a limit was hit, the file type is not accepted, bad text encoding, encrypted PDF, the worker crashed or timed out, its output was bad, a linked stylesheet is missing, or nothing visible is left | a reason, no content |
| **accept** | the rebuild worked | `safe_text` and/or `safe_images`, the type, SHA-256 of the input, a random ID, and `removed` counts |

- **Hidden content is removed and counted, not rejected.** Normal documents hide small things too (menu
  labels, screen-reader hints), so rejecting them would cause many false alarms.
- **One switch: `strict=True`** (CLI `--strict`) rejects when *active* content was removed: macros, scripts,
  PDF JavaScript and actions, embedded files, DDE, remote templates and similar. It does not judge intent.
- **The original is never released.** Keep it only if you must, in a private quarantine (see the rules).

## Quick start

### Install

You need Python 3.10 or newer. ReaderGuard is not on PyPI yet:

```bash
git clone https://github.com/udayalluym/readerguard.git && cd readerguard
python -m venv .venv && source .venv/bin/activate
pip install -e .
pip install pytest && pytest tests/        # check that it works (the tests never use the network)
```

It depends on PyMuPDF, NumPy, Pillow and defusedxml.

### Python

```python
from pathlib import Path
from readerguard import scan

r = scan(Path("upload.docx")) # or raw bytes, an open file, or a URL string. scan() never raises.

r.safe          # True = accept, False = reject
r.message       # 'accepted (removed: hidden_text x1)' or 'rejected: <reason>'
r.safe_text     # only the text a person can see (empty on reject). Give this to your AI.
r.safe_images   # rebuilt PNGs: an image input, or PDF pages with page_images=True
r.removed       # {'hidden_text': 1}: what was left out
r.reasons       # reject: why; accept: what was removed
r.to_dict()     # JSON-ready: safe, message, reasons, removed, format, family, sha256, id, error, ...
```

### Command line

```bash
readerguard scan report.docx https://example.com uploads/   # files, folders (every file, any name) or links
readerguard scan --json --strict uploads/                   # one JSON line per file
readerguard scan --json --with-text - < upload.pdf          # read standard input; JSON includes safe_text
readerguard scan --json --resources sheets.json - < page.html # a page's linked stylesheets, {url: base64}
readerguard text --strict page.html -o page.txt             # save only the visible text
readerguard update-ioc                                      # download the threat lists
```

Exit codes: `0` everything accepted, `1` anything rejected.

### Options

```python
scan(src, strict=False, name=None, fetch_options=FetchOptions(...), page_images=False, resources=None)
FetchOptions(timeout=20, max_bytes=25_000_000, max_redirects=3, allow_private=False, fetch_resources=True,
             ioc="auto", ioc_dir=None, ioc_max_age=86400)
```

- `strict=True`: reject when active content was removed.
- `page_images=True` (PDF): also return each page as a new PNG (at most 50 pages; more is a reject).
- `resources={url: bytes}` (web pages, and raw HTML in Markdown): the page's linked stylesheets. A page whose
  sheet is missing is rejected and lists it in `missing_stylesheets`. Fetch those with
  `readerguard.fetch.fetch` (never a plain HTTP client: the page chose those URLs) and scan again with
  `resources=`. A URL scan fetches its own sheets this way.
- `allow_private=True`: allow internal addresses. For development only.
- `ioc`: the threat-list mode, see below.

## Supported files

The type is decided from the content only. The file name plays no part.

| family | accepted | output |
|---|---|---|
| PDF | `.pdf` (not encrypted) | text; page PNGs with `page_images=True` |
| Office (zip) | Word `.docx` `.docm`, PowerPoint `.pptx` `.pptm`, Excel `.xlsx` `.xlsm` | text |
| Text | web pages and any `http(s)` link, Markdown, plain text, CSV, JSON and other text, in UTF-8 or UTF-16 with a byte-order mark | text |
| Image | PNG, JPEG, GIF (first frame), WebP | a new PNG |

**Always rejected:** programs and `#!` scripts; old Office (`.doc` `.xls` `.ppt`), RTF and OpenDocument (save
as `.docx` / `.xlsx` / `.pptx` or PDF); SVG; BMP and TIFF; compressed archives and zip files that are not
Word, Excel or PowerPoint; any other binary file; text in other encodings (for example Windows-1252 or
Shift-JIS); encrypted PDFs.

## Limits

Every cap lives in [`readerguard/limits.py`](readerguard/limits.py). Going over any of them is a reject.
The PDF page cap and the worker time limit are set together from a benchmark
([`bench/TIMING.md`](bench/TIMING.md)): 200 ordinary pages take about 10 s, 200 very dense pages about 25 s, so the
60-second limit leaves about 2x headroom on the slowest case. Slower or shared CPUs need a longer limit.

| what | limit |
|---|---|
| any input (file, bytes, fetched body) | 25 MB |
| `safe_text` | 5 MB |
| PDF | 200 pages; page images for at most 50 pages |
| image | 40 megapixels to decode; output at most 1568 px on the longer side |
| Office zip | 1,000 entries, 100 MB unpacked, 100:1 compression ratio |
| worker | 60 s, 1 GB memory, 4 at once per host process (a server with N processes runs up to N x 4) |
| fetch | 20 s in total, 3 redirects |
| linked stylesheets | 20 files, 5 MB in total per page |
| threat lists | older than 24 hours is a reject |

Memory caps do not always work on macOS. The kill timer and the output checks still apply.

## Domain threat lists

Before the fetcher looks up a host, it checks the URL against local lists of known bad sites. It does this for
the page, for every redirect, and for every linked stylesheet. There is never a per-URL call to an outside
service.

- **URLhaus host file** (abuse.ch, malware): a listed host also blocks all its subdomains.
- **OpenPhish community feed** (phishing): exact URLs only, never the whole host, because phishing pages often
  sit on shared hosting.
- **Your own lists:** any `*.hosts` file in the list folder, one host per line, `#` for comments.

Hosts are compared after lower-casing, removing a trailing dot, converting international names to `xn--`
form, and normalising IP addresses (including odd spellings such as `2130706433` for `127.0.0.1`). A hit is a
reject, for example `blocked: evil.com is on URLhaus (malware)`.

The lists live in `~/.cache/readerguard/ioc/` (change it with `--ioc-dir` or `FetchOptions(ioc_dir=...)`).
Download them with `readerguard update-ioc` and refresh them every hour from cron, on the machine that fetches:

```cron
0 * * * *  /path/to/.venv/bin/readerguard update-ioc --ioc-dir /var/lib/readerguard/ioc
```

Modes (`--ioc` / `FetchOptions(ioc=...)`):

- `auto` (default): checked when the lists exist; skipped when none have been downloaded; **lists older than
  24 hours make every URL scan a reject**, so a broken cron job is noticed.
- `required`: also a reject when no lists have been downloaded. Use this in production.
- `off`: never checked.

## Production recipe

Keep two rules: **the part with network never parses, and the part that parses has no network.**

- **Outside** (your app): fetch URLs with `readerguard.fetch.fetch`, which has network but parses nothing,
  and run `update-ioc` from cron. Give this step no route to internal networks or the cloud metadata address;
  ReaderGuard's own address check is the second layer, not the only one.
- **Inside** (the scan container): run `scan` on the bytes, with no network, no secrets, a read-only disk and
  a non-root user. If a file exploits a parser bug, it lands somewhere with nothing to steal and nowhere to
  send it.

Build the scan image from the [Dockerfile](Dockerfile) and run it like this:

```bash
docker build -t readerguard-scan .

docker run --rm -i --network none --read-only --tmpfs /tmp:size=512m \
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 2g --cpus 2 \
  readerguard-scan scan --json --with-text - < upload.pdf
```

The container writes only to `/tmp` (the worker passes each file through temporary files there). Do not
mount anything you care about, and do not pass any secrets or credentials into it.

From Python, the outside step looks like this. Web pages usually link stylesheets, which the scan step
cannot fetch: it lists them in `missing_stylesheets`, the outside step fetches them with the same safe
fetcher, and the page is scanned once more with `--resources`.

```python
import base64, json, os, subprocess, tempfile
from pathlib import Path
from urllib.parse import urljoin
from readerguard.fetch import FetchOptions, fetch, resource_fetcher   # outside: network, no parsing

OPT = FetchOptions(ioc="required", ioc_dir="/var/lib/readerguard/ioc")   # the folder the cron job fills
BOX = ["docker", "run", "--rm", "-i", "--network", "none", "--read-only", "--tmpfs", "/tmp:size=512m",
       "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "64",
       "--memory", "2g", "--cpus", "2"]

def scan_in_box(body: bytes, ctype: str, sheets: dict[str, bytes] | None = None) -> dict:
    """Raises if the container fails: treat that as a reject."""
    with tempfile.TemporaryDirectory() as job:
        os.chmod(job, 0o755)                                     # readable by the container's user
        Path(job, "sheets.json").write_text(json.dumps(
            {url: base64.b64encode(css).decode() for url, css in (sheets or {}).items()}))
        cmd = BOX + ["-v", f"{job}:/job:ro", "readerguard-scan", "scan", "--json", "--with-text",
                     "--content-type", ctype,    # the page's own type: a web page is read as HTML, not Markdown
                     "--resources", "/job/sheets.json", "-"]  # add --with-images for rebuilt PNGs
        out = subprocess.run(cmd, input=body, capture_output=True, timeout=180)
        return json.loads(out.stdout)            # safe, message, removed, safe_text, sha256, id, ...

page = fetch("https://example.com/pricing", OPT)
ctype = page.headers.get("content-type", "")     # with its charset: a 7-bit stateful charset is a reject
if "stylesheet" in page.headers.get("link", "").lower():
    raise ValueError("reject: the server links a stylesheet in a Link header")
result = scan_in_box(page.body, ctype)
if result["missing_stylesheets"]:                # absolute when the page has <base href>, else as written
    get = resource_fetcher(OPT)                  # same rules as the page; 20 files / 5 MB in total
    sheets = {href: get(urljoin(page.final_url, href)) for href in result["missing_stylesheets"]}
    if None not in sheets.values():              # a sheet that cannot be fetched: the reject stands
        result = scan_in_box(page.body, ctype, sheets)
```

`--with-images` adds the rebuilt PNGs to the JSON as base64 (`safe_images`) and turns on page images for
PDFs.

For development, `scan("https://...")` does both steps in one process. That contains crashes and hangs only,
not parser exploits.

## Rules for your app

A scanner cannot fix how your app serves files or what the AI does next. These rules are part of the deal.

**Deployment**

- Run the scan step with no outbound network and no secrets.
- Give the fetch step no route to internal networks or the cloud metadata address.

**Serving (web)**

- Store only ReaderGuard's outputs, under the random ID with a fixed `.txt` or `.png` extension, outside the
  web root, never executable. Script code that arrives as text then stays harmless.
- Serve them from a separate domain without cookies, with ReaderGuard's `Content-Type`,
  `X-Content-Type-Options: nosniff`, `Content-Disposition: attachment` and a strict Content Security Policy.
- Show people `safe_text` and the rebuilt image, not the original, so they see what the AI sees.
- If you must keep the original, put it in a private quarantine bucket, download-only, and run your own
  antivirus on it.
- Put login, rate limits, quotas and a request-size cap at the edge.
- On CSV export, escape cells that start with `=`, `+`, `-` or `@`.

**Prompting (AI / RAG)**

- Index `safe_text` only. Never fetch the URL again or re-read the original.
- Give vision models only ReaderGuard's images. Set `limits.MAX_IMAGE_PX` to the model's input size so its API
  does not resize them again.
- Mark retrieved text as data, not instructions. This helps, but it can be bypassed.
- Do not automatically show remote images or links from the AI's answers; allow only hosts you trust.
- Allow at most two of these three: untrusted input, private data, a way to send data out.
- Ask a person before risky tool actions.
- Record the source, scan ID and hash for every chunk, and control who can add to the collection.

## Accepted risks

What ReaderGuard deliberately leaves out, and what that costs.

| left out | risk you accept |
|---|---|
| LibreOffice and a headless browser | Hiding rules for Office and web pages are written by hand; an unlisted trick may reach `safe_text` |
| OCR of any kind | Text drawn in images, or low-contrast text, reaches a vision model; PDFs that swap font shapes are not caught |
| A container for every file, a sandbox inside the library | A hijacked worker can touch other files being scanned in the same container at the same moment. Set the worker cap to 1 for strict tenants |
| Antivirus, YARA, VirusTotal | Nothing for the rebuilt output; kept originals need your own antivirus |
| Releasing the original | Apps that need it run their own quarantine; page PNGs replace the PDF |
| Injection classifiers, phrase lists, look-alike letter checks | Visible injection is not flagged; the rules for your app limit the damage |
| Running JavaScript, CSS `@import`, media conditions | Pages built by JavaScript give little text and are rejected; styles set that way are missed. Rules for states such as `:hover` are ignored; rules in every `@media` block but print-only apply, so text shown only at some screen sizes may be dropped |
| Old text encodings (Windows-1252, Shift-JIS, UTF-16 without a byte-order mark) | Some honest CSV files and old pages are refused |
| IPv6 fetching | IPv6-only sites are refused |
| Archives, old Office, RTF, OpenDocument, SVG, email, audio, video | Some honest files are refused; people re-save as PDF or DOCX |
| Markdown link targets, PDF form values, later GIF frames, some variation selectors | A little honest content is lost; form values still show in page PNGs |
| Queue, database, admin screen, severities, "warn" | Very large workloads need their own queue |

**What it cannot stop at all:** visible false facts, visible injection, look-alike letters, a page that
changes after you scan it ("index what you scanned" helps), and links in the AI's answer that leak data. Those
are handled by the [rules for your app](#rules-for-your-app), or not at all.

## Benchmark (measured on v0.2.0)

> **These numbers were measured on v0.2.0**, the earlier design that looked for hidden tricks and gave a
> "safe / not safe / warn" verdict. They have not been re-run on 0.3.0, and the test data is not public yet
> (`bench/out` and `../pdfbench` are needed and not included). The verdict rates of v0.2.0 do not apply to the
> accept / reject rule of 0.3.0 and are left out here. Full v0.2.0 tables: [bench/RESULTS.md](bench/RESULTS.md),
> [bench/MULTI_RESULTS.md](bench/MULTI_RESULTS.md), [bench/EXPOSURE.md](bench/EXPOSURE.md),
> [bench/E2E.md](bench/E2E.md), [bench/COMPARE.md](bench/COMPARE.md).

The test set: 1,340 attacked files in 8 types (72 ways of hiding a harmless sentence with a unique marker
word) and 838 normal files, all generated from made-up documents.

- **Common loaders pass hidden text on.** PyMuPDF, pdfminer.six, BeautifulSoup, html2text, python-docx,
  docx2txt, python-pptx, openpyxl and Microsoft's MarkItDown passed on up to 69% (PDF), 77% (web pages), 60%
  (Word) and 100% (PowerPoint, Excel) of the hidden text. This is about the loaders, not ReaderGuard.
- **Hidden text changes AI answers.** With MarkItDown's text, the hidden sentence changed the answer 45% of
  the time with Qwen3-235B and 58% with Llama-3.3-70B.
- **v0.2.0's `safe_text` held 0% of the hidden text**, and the hidden text then changed 0% of answers.

To rerun the benchmark (needs the test data and `pandoc`):

```bash
pip install -e ".[bench]"
python -m bench.attacks --src ../pdfbench/data --per 15 --out bench/out/attacks && python -m bench.evaluate
bash bench/build_clean.sh ../pdfbench/data bench/out/clean && python -m bench.multi build && python -m bench.multi eval
python -m bench.exposure
```

The attack generators in `bench/` only make harmless test files. Use them only on systems you are allowed
to test.

## License

Apache-2.0. See [LICENSE](LICENSE).
