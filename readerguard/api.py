"""scan(): one call for any document or URL, with two outcomes: accept or reject.

    >>> from readerguard import scan
    >>> r = scan("https://example.com/page")          # or pathlib.Path, bytes, or a file object
    >>> r.safe, r.message
    (True, 'accepted (removed: hidden_text x1)')
    >>> r.safe_text                                    # visible text only, for indexing
    >>> r.to_dict()                                    # JSON-ready: safe, message, reasons, removed, id, sha256, ...

Extraction runs in a fresh child process (worker.py). Anything that goes wrong (fetch error, over a limit,
parser error, worker crash or timeout, bad worker output, nothing visible) is a reject.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
import uuid
from dataclasses import dataclass, field, fields
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from . import limits
from .fetch import FetchError, FetchOptions, fetch, resource_fetcher
from .findings import Report, clip


class Reject(Exception):
    """Input refused before parsing (for example over a size limit)."""


class MissingStylesheets(Reject):
    """An HTML page links stylesheets that were neither given in resources= nor fetched."""

    def __init__(self, urls: list[str]):
        super().__init__(f"{len(urls)} linked stylesheet(s) could not be fetched")
        self.urls = urls


CTYPE_HTML = ("text/html", "application/xhtml+xml")
IMAGE_MAGIC = (b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a")
# (test on the first bytes, what it is): refused at the gate with this reason.
REFUSED = [
    (lambda h: h.startswith((b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
                             b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe")) or (h[:2] == b"MZ" and b"\0" in h),
     "an executable program"),
    (lambda h: h.lstrip(b"\xef\xbb\xbf").startswith(b"#!"), "an executable script"),
    (lambda h: h.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), "a legacy Office (OLE) file"),
    (lambda h: h.startswith(b"{\\rtf"), "an RTF document"),
    (lambda h: (h[:2] == b"BM" and h[6:10] == b"\0" * 4) or h.startswith((b"II*\0", b"MM\0*")),
     "a BMP or TIFF image"),
    (lambda h: h.startswith((b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"\xfd7zXZ\0",
                             b"\x28\xb5\x2f\xfd")) or (h[:3] == b"BZh" and h[4:10] == b"1AY&SY"),
     "a compressed archive"),
]
BINARY = re.compile(rb"[\x00-\x08\x0e-\x1a\x1c-\x1f]")       # control bytes that do not occur in text
SVG_NS = b"www.w3.org/2000/svg"
# Reader-side structure that a text extractor would show as plain text but another reader renders differently.
# bounded and anchored to the start of a number: linear on any input (an unbounded \d+ is quadratic on digits)
PDF_OBJ = re.compile(rb"(?<![0-9])[0-9]{1,10}[ \t\r\n\f\x00]{1,16}[0-9]{1,5}[ \t\r\n\f\x00]{1,16}obj\b")
MAIL_HEADER = re.compile(rb"(?im)^(mime-version|content-type|content-transfer-encoding|received|message-id|"
                         rb"return-path|x-mailer|delivered-to)[ \t]*:")
# Charsets in which ASCII bytes do not mean ASCII ('<' can be part of a two-byte character), or that a browser
# replaces with one U+FFFD: the page would not read as the UTF-8 that is scanned.
BAD_CHARSET = re.compile(rb"(iso-?2022|csiso2022|utf-?7|unicode-1-1-utf-7|hz-gb|hz\b|x-user-defined|replacement)",
                         re.I)
META_CHARSET = re.compile(rb"<meta[^>]{0,500}?charset\s*=\s*[\"']?\s*([\w.:-]+)", re.I)
XML_CTYPE = re.compile(r"^(application/xhtml\+xml|[\w.+-]+/[\w.+-]*\+xml|[\w.+-]+/xml)$")


def sniff(raw: bytes, content_type: str = "") -> str:
    """Content family from the first bytes: "pdf" | "image" | "zip" | "text". Anything else raises Reject.

    No zip is opened here (the Office extractor decides DOCX / XLSX / PPTX) and the file name plays no part."""
    head = raw[:4096]
    for test, what in REFUSED:                          # first, so no magic or %PDF- marker can let them through
        if test(head):
            raise Reject(f"content is {what}, which is not accepted")
    if head.startswith(IMAGE_MAGIC) or (head[:4] == b"RIFF" and head[8:12] == b"WEBP"):
        return "image"
    if head.startswith(b"PK\x03\x04"):
        return "zip"
    ct = content_type.split(";")[0].strip().lower()
    if raw.lstrip(b"\xef\xbb\xbf \t\r\n\f").startswith(b"%PDF-"):
        if ct.startswith("text/"):                      # the server says text: a PDF reader would show other text
            raise Reject("content is a PDF served as text, which is not accepted")
        return "pdf"
    low = _text_head(raw)
    if BINARY.search(low):
        if b"%PDF-" in raw[:1024]:                      # a binary prefix before the header: a PDF reader opens it
            return "pdf"
        raise Reject("content is binary data of an unknown type, which is not accepted")
    if b"%PDF-" in raw or (PDF_OBJ.search(raw) and b"endobj" in raw):
        # text that is also a PDF (header late, in a comment, or missing): a PDF reader shows something else
        raise Reject("content is text that also holds a PDF document, which is not accepted")
    _refuse_other_readers(raw, low, ct)
    return "text"


def _refuse_other_readers(raw: bytes, low: bytes, ct: str) -> None:
    """Text that another kind of reader renders (SVG / XML, email / MHTML, a stateful 7-bit charset): the text
    extractors would read it differently from what a person sees, so it is refused."""
    if ct == "image/svg+xml":
        raise Reject("content is an SVG image, which is not accepted")
    whole = _text_all(raw)
    tag = _first_tag(whole)
    if tag is not None:
        prefix, _, local = tag.rpartition(b":")
        if local == b"svg":                                                  # <svg>, <x:svg>
            raise Reject("content is an SVG image, which is not accepted")
        if prefix and local and b"xmlns:" + prefix in whole:                 # <x:doc xmlns:x=...>
            raise Reject("content is an XML document, which is not accepted")
    if low.startswith(b"<") and SVG_NS in low and _text_kind(raw, ct) != "html":
        raise Reject("content is an SVG image, which is not accepted")
    if XML_CTYPE.match(ct) or low.startswith(b"<?xml") or b"<?xml-stylesheet" in whole:
        raise Reject("content is an XML document, which is not accepted")
    first = low.split(b"\n", 1)[0]
    block = re.split(rb"\r?\n\r?\n", low, maxsplit=1)[0]
    if re.match(rb"from \S+ +(mon|tue|wed|thu|fri|sat|sun) ", low) or (
            re.match(rb"[!-9;-~]+[ \t]*:", first) and MAIL_HEADER.search(block)):
        raise Reject("content is an email or MHTML message, which is not accepted")
    if b"\x1b" in raw:
        raise Reject("content holds escape (ESC) characters, which are not accepted")
    m = META_CHARSET.search(whole)
    if m and BAD_CHARSET.match(m.group(1)):
        raise Reject("content declares a character set that is not read as UTF-8, which is not accepted")


def _text_all(raw: bytes) -> bytes:
    """The whole input as lower-case UTF-8 (UTF-16 with a byte-order mark decoded) for the structure checks."""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        raw = raw.decode("utf-16", "ignore").encode("utf-8")
    return raw.lstrip(b"\xef\xbb\xbf").lower()


_SPACE = re.compile(rb"\s*")
MAX_PROLOG_ITEMS = 10_000


def _first_tag(low: bytes) -> bytes | None:
    """Name of the first element, after whitespace, comments, processing instructions and a doctype (with its
    internal subset), read the XML way. Linear: every step moves forward with bytes.find."""
    i, n, steps = 0, len(low), 0
    while i < n:
        steps += 1
        if steps > MAX_PROLOG_ITEMS:
            raise Reject("content starts with too many comments or declarations, which is not accepted")
        if low[i:i + 1].isspace():
            i = _SPACE.match(low, i).end()
        elif low.startswith(b"<!--", i):
            j = low.find(b"-->", i + 4)
            if j < 0:
                return None
            i = j + 3
        elif low.startswith(b"<?", i):
            j = low.find(b"?>", i + 2)
            if j < 0:
                return None
            i = j + 2
        elif low.startswith(b"<!", i):
            j = low.find(b">", i)
            k = low.find(b"[", i, j) if j >= 0 else -1     # bounded by the '>': linear over many declarations
            if 0 <= k < j:
                k2 = low.find(b"]", k)
                j = low.find(b">", k2) if k2 >= 0 else -1
            if j < 0:
                return None
            i = j + 1
        elif low.startswith(b"<", i):
            m = re.match(rb"<([^\s/>]{1,200})", low[i:i + 202])
            return m.group(1) if m else None
        else:
            return None
    return None


def _text_head(raw: bytes) -> bytes:
    """The first bytes as lower-case UTF-8 for the text checks; UTF-16 (with a byte-order mark) is decoded first."""
    head = raw[:4096]
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        head = head.decode("utf-16", "ignore").encode("utf-8")
    return head.lstrip(b"\xef\xbb\xbf \t\r\n").lower()


def _text_kind(raw: bytes, content_type: str) -> str:
    """Which text extractor: "html" for web pages (by content type, or a document that starts as one), else
    "markdown" (Markdown handling, then raw HTML through the HTML extractor). Only the first token counts: a
    "<body>" tucked into a Markdown comment must not switch a Markdown file to the HTML extractor."""
    ct = content_type.split(";")[0].strip().lower()
    if ct in CTYPE_HTML or _text_head(raw).startswith((b"<!doctype html", b"<html")):
        return "html"
    return "text" if ct == "text/plain" else "markdown"


# Findings that make the whole input a reject (over a limit, unreadable).
REJECT = {"malformed_archive", "malformed_image", "malformed_xml"}   # an unparsed Office part may hide text
# Removed content that strict=True rejects: macros, scripts, PDF JavaScript, embedded files, DDE, remote templates.
ACTIVE = {"macros", "javascript", "open_action", "launch_action", "form_action", "rich_content", "scripts",
          "javascript_url", "plugin_content", "activex", "embedded_object", "embedded_file",
          "embedded_executable", "dde", "dangerous_formula", "dangerous_uri", "remote_content",
          "alt_chunk", "appended_data", "polyglot"}


@dataclass
class ScanResult:
    safe: bool                                           # True = accept, False = reject
    message: str
    reasons: list[str] = field(default_factory=list)     # reject: why; accept: what was removed
    removed: dict[str, int] = field(default_factory=dict)
    safe_text: str = ""
    safe_images: list[bytes] = field(default_factory=list)
    format: str = ""
    family: str = ""                                     # pdf | image | zip | text
    sha256: str = ""                                     # of the input bytes
    missing_stylesheets: list[str] = field(default_factory=list)   # reject: get these, scan again with resources=
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    source: str = ""
    error: str | None = None

    def __bool__(self):
        return self.safe

    def to_dict(self, include_text: bool = False) -> dict:
        d = {f.name: getattr(self, f.name) for f in fields(self) if f.name not in ("safe_text", "safe_images")}
        d["images"] = len(self.safe_images)
        if include_text:
            d["safe_text"] = self.safe_text
        return d


def _capped(raw: bytes) -> bytes:
    if len(raw) > limits.MAX_FILE_BYTES:
        raise Reject(f"input is larger than the {limits.MAX_FILE_BYTES // limits.MB} MB limit")
    return raw


def _read_all(f) -> bytes:
    """Read to the end, or to one byte over the cap: a raw stream (pipe, socket, unbuffered file) may return less
    than asked for on each read. A non-blocking stream with nothing ready (read() -> None) is a reject."""
    buf = bytearray()
    while len(buf) <= limits.MAX_FILE_BYTES:
        chunk = f.read(limits.MAX_FILE_BYTES + 1 - len(buf))
        if chunk is None:
            raise Reject("input stream is non-blocking and had no data ready")
        if not chunk:
            break
        buf += chunk
    return _capped(bytes(buf))


def _load(source, name, opt, content_type=None):
    """-> (raw, name, content_type, base_url, resource fetcher). Every input is size-capped before parsing."""
    # A str is ALWAYS a URL, never a path: apps pass user-supplied "URLs" straight to scan(), and a str that
    # fell through to Path() let a user read local files (/etc/passwd, /proc/self/environ) back as safe_text.
    # Local files must be passed as pathlib.Path (or an open file), which only the calling code can create.
    if isinstance(source, str):
        if not re.match(r"^https?://", source, re.I):
            raise Reject("a string source must be an http(s) URL; pass pathlib.Path to scan a local file")
        opt = opt or FetchOptions()
        got = fetch(source, opt)
        _check_headers(got.headers)
        return (_capped(got.body), name or got.final_url, got.content_type, got.final_url,
                resource_fetcher(opt) if opt.fetch_resources else None)
    ctype = (content_type or "").strip().lower()
    _check_headers({"content-type": ctype})
    if isinstance(source, (bytes, bytearray, memoryview)):
        return _capped(bytes(source)), name or "<bytes>", ctype, None, None
    if hasattr(source, "read"):
        return _read_all(source), name or getattr(source, "name", "<stream>"), ctype, None, None
    if not isinstance(source, Path):
        raise Reject(f"unsupported source type {type(source).__name__}; pass bytes, a file object, "
                     "pathlib.Path or an http(s) URL string")
    with _open_regular(source) as f:
        return _read_all(f), name or str(source), ctype, None, None


def _open_regular(path: Path, follow_symlinks: bool = True):
    """Open a regular file without blocking: a FIFO, socket or device in its place is a reject (open() on a
    FIFO with no writer would wait forever)."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | (0 if follow_symlinks else getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(path, flags)
    except OSError as e:
        raise Reject(f"cannot open the file ({type(e).__name__})") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Reject("the path is not a regular file")
        if hasattr(os, "set_blocking"):
            os.set_blocking(fd, True)
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def _check_headers(headers: dict) -> None:
    """URL scans: a page whose HTTP headers change how a browser reads it in ways the extractors do not model."""
    m = re.search(r"charset\s*=\s*[\"']?([\w.:-]+)", headers.get("content-type", ""), re.I)
    if m and BAD_CHARSET.match(m.group(1).encode()):
        raise Reject("the server declares a character set that is not read as UTF-8, which is not accepted")
    if "stylesheet" in headers.get("link", "").lower():        # a plain substring test: linear, fails closed
        raise Reject("the server links a stylesheet in an HTTP Link header, which is not accepted")


def _redact(url: str) -> str:
    """A URL for display, without any user name or password in it."""
    try:
        u = urlsplit(url)
    except ValueError:
        return "<invalid URL>"
    if "@" not in u.netloc:
        return url
    return urlunsplit((u.scheme, "***@" + u.netloc.rsplit("@", 1)[1], u.path, u.query, u.fragment))


def _dispatch(family, raw, name, ctype, base_url, fetcher, page_images=False) -> Report:
    """Extraction runs in a fresh child process; its output comes back checked and Unicode-stripped."""
    from .worker import run
    return run(raw, family, name, ctype, base_url, fetcher, page_images)


def _sheets(resources, net):
    """Stylesheet getter: the caller's resources first, then (URL scans only) the safe fetcher. None = missing."""
    def get(url, kind="text/css"):
        if resources and url in resources:
            return bytes(resources[url]) if resources[url] is not None else None
        return net(url, kind) if net else None
    return get


def _unique(xs):
    return list(dict.fromkeys(xs))


def _reject(res: ScanResult, reasons: list[str]) -> ScanResult:
    from .textscan import strip_invisible
    reasons = _unique(clip(strip_invisible(r), 300) for r in reasons)   # host-side reasons can quote a server
    res.safe, res.reasons, res.safe_text, res.safe_images = False, reasons, "", []
    more = f" (+{len(reasons) - 3} more)" if len(reasons) > 3 else ""
    res.message = "rejected: " + "; ".join(reasons[:3]) + more
    return res


def _judge(res: ScanResult, rep: Report, strict: bool) -> ScanResult:
    removed: dict[str, int] = {}
    notes, rejects = [], [rep.error] if rep.error else []
    for f in rep.findings:
        if f.check in REJECT:
            rejects.append(f.message)
        else:
            removed[f.check] = removed.get(f.check, 0) + 1
            notes.append(f.message + (f" (page {f.page + 1})" if f.page is not None else ""))
    res.removed = removed
    text = rep.safe_text
    if strict and removed.keys() & ACTIVE:
        rejects.append("active content was removed (strict): " + ", ".join(sorted(removed.keys() & ACTIVE)))
    if not rejects and not text.strip() and not rep.images:
        rejects.append("no visible text")
    if rejects:
        return _reject(res, _unique(rejects))
    res.safe, res.safe_text, res.safe_images, res.reasons = True, text, rep.images, _unique(notes)
    res.message = "accepted" + (" (removed: " + ", ".join(f"{k} x{v}" for k, v in removed.items()) + ")"
                                if removed else "")
    return res


def scan(source, *, strict: bool = False, name: str | None = None, fetch_options: FetchOptions | None = None,
         page_images: bool = False, resources: dict[str, bytes] | None = None,
         content_type: str | None = None) -> ScanResult:
    """Scan bytes, a file object, a pathlib.Path, or an http(s) URL given as str. Never raises: any error
    is a reject. A str is only ever treated as a URL (never a local path), so user input is safe to pass.

    Accept (safe=True): safe_text holds only visible text; `removed` counts what was left out.
    strict=True also rejects when active content (macros, scripts, PDF JavaScript, embedded files, DDE,
    remote templates) was removed.
    page_images=True (PDF): also return each page as a PNG in safe_images (at most MAX_PAGE_IMAGES pages); a
    PDF with no visible text is then accepted with its page images (a scan).
    resources (HTML): linked stylesheets as {url: bytes}, keyed as `missing_stylesheets` of a rejected scan
    lists them (resolved against the page URL; as written in the page for bytes). For URL scans, sheets not
    given here are fetched with the safe fetcher. A linked sheet that is not available is a reject. The page
    chose those URLs: fetch missing_stylesheets with readerguard.fetch.fetch, never a plain HTTP client (SSRF).
    content_type (bytes, file object, Path): the HTTP Content-Type the bytes came with (for example a page that
    was fetched outside), so a web page is read as one. URL scans use the server's.
    """
    res = ScanResult(safe=False, message="")
    try:
        res.source = _redact(source) if isinstance(source, str) else str(source) if isinstance(source, Path) else (
            name or getattr(source, "name", None) or "<bytes>")
        raw, name, ctype, base_url, fetcher = _load(source, name, fetch_options, content_type)
        res.sha256 = hashlib.sha256(raw).hexdigest()
        res.family = sniff(raw, ctype)
        rep = _dispatch(res.family, raw, name, ctype, base_url, _sheets(resources, fetcher), page_images)
        res.format = rep.format
        return _judge(res, rep, strict)
    except Exception as e:
        res.missing_stylesheets = e.urls if isinstance(e, MissingStylesheets) else []
        res.error = (str(e) if isinstance(e, Reject) else f"could not fetch URL ({e})" if isinstance(e, FetchError)
                     else f"scan failed ({type(e).__name__}: {e})")
        return _reject(res, [res.error])
