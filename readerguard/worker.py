"""Extraction in a fresh child process, and the host-side finish step.

Host:  run(raw, family, ...) -> Report. Starts `python -m readerguard.worker` (one child per file, at most
       WORKER_CONCURRENCY at once), with a kill timer of WORKER_SECONDS. A crash, timeout, oversize or badly
       shaped output raises Reject. The output is untrusted: it is size-capped, decoded as strict UTF-8,
       shape-checked, and its text is stripped of invisible Unicode here, on the host.
Child: reads one JSON header line plus the file bytes on stdin, caps its own CPU / memory / output size, runs
       the extractor for the family and writes one JSON object on stdout (images as base64 PNG).

HTML pages: the child lists the linked stylesheets it needs ("need"); the host gets them (from the caller's
resources, or its safe fetcher for URL scans) and runs a second child with the bytes. A sheet the host cannot
get is a reject (MissingStylesheets). The child never touches the network.
The child is for crashes and hangs; the security boundary is the container around the scan step.
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from . import limits
from .api import MissingStylesheets, Reject, _text_kind
from .findings import Finding, Report, clip
from .textscan import strip_invisible

# -I: no PYTHON* variables, no user site, no script or working directory on sys.path. The host's own path is
# appended AFTER the standard library (argv[1]), so a stray json.py next to the package can never shadow it.
COMMAND = [sys.executable, "-I", "-c",
           "import sys, json; sys.path += json.loads(sys.argv[1]); import readerguard.worker as w; w.main()"]
ROOT = str(Path(__file__).resolve().parent.parent)      # where the package lives
PNG = b"\x89PNG\r\n\x1a\n"
_SLOTS = threading.BoundedSemaphore(limits.WORKER_CONCURRENCY)
MAX_ROUNDS = 6                                          # one per @import level (html.MAX_IMPORT_DEPTH) + links
SLOT_WAIT = 600                                         # seconds to wait for a free worker slot, then a reject


def _reset_slots():                                     # slots held by threads at fork() are never freed in the child
    global _SLOTS
    _SLOTS = threading.BoundedSemaphore(limits.WORKER_CONCURRENCY)


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_slots)
_CHECK = re.compile(r"[a-z_]{1,40}")


# --------------------------------------------------------------------------- host


def run(raw: bytes, family: str, name: str, ctype: str = "", base_url: str | None = None,
        fetcher=None, page_images: bool = False) -> Report:
    """Extract in a child process and return a checked Report. Raises Reject on any worker failure.

    fetcher(url, "text/css") -> bytes | None gets an HTML page's linked stylesheets; None (or no fetcher) means
    the sheet is missing, which raises MissingStylesheets."""
    job = {"family": family, "name": name, "ctype": ctype, "base_url": base_url, "page_images": page_images,
           "resources": {},
           "limits": {k: v for k, v in vars(limits).items() if k.isupper() and isinstance(v, (int, float))}}
    out = _call(job, raw)
    # linked stylesheets: get them on the host and run again. A fetched sheet can @import more, so this repeats,
    # once per import level (the child refuses deeper chains), never asking for the same URL twice.
    for _ in range(MAX_ROUNDS):
        if not out["need"] or out["error"] is not None:
            return _finish(out, name)
        if (family != "text" or any(u in job["resources"] for u in out["need"])
                or len(job["resources"]) + len(out["need"]) > limits.MAX_STYLESHEETS):
            raise Reject("worker asked for stylesheets it may not have")
        got = {url: fetcher(url, "text/css") if fetcher else None for url in out["need"]}
        missing = [clip(strip_invisible(u), 2000) for u, data in got.items() if data is None]
        if missing:
            raise MissingStylesheets(missing)
        job["resources"].update({url: base64.b64encode(data).decode() for url, data in got.items()})
        out = _call(job, raw)
    raise Reject("worker kept asking for stylesheets")


def _call(job: dict, raw: bytes) -> dict:
    slots = _SLOTS
    if not slots.acquire(timeout=SLOT_WAIT):
        raise Reject("scanner busy: no worker slot became free")
    try:
        return _check(_child(json.dumps(job).encode() + b"\n" + raw))
    finally:
        slots.release()


def _child(data: bytes) -> bytes:
    """One fresh child in its own process group: stdin and stdout are temporary files (no pipe deadlocks); the
    whole group is killed after WORKER_SECONDS, or when the child is done (nothing it started outlives it)."""
    env = {"OPENBLAS_NUM_THREADS": "1", "OMP_NUM_THREADS": "1"}
    paths = json.dumps([ROOT] + [p for p in sys.path if p])
    with tempfile.TemporaryFile() as fin, tempfile.TemporaryFile() as fout:
        fin.write(data)
        fin.seek(0)
        proc = subprocess.Popen(COMMAND + [paths], stdin=fin, stdout=fout, stderr=subprocess.DEVNULL,
                                cwd=tempfile.gettempdir(), env=env, start_new_session=True)
        try:
            code = proc.wait(timeout=limits.WORKER_SECONDS)
        except subprocess.TimeoutExpired:
            raise Reject(f"worker timed out after {limits.WORKER_SECONDS} s") from None
        finally:                                       # timeout, or the host itself interrupted: never leave it
            _kill_group(proc)
        if code != 0:
            raise Reject(f"worker crashed (exit code {code})")
        if os.fstat(fout.fileno()).st_size > limits.MAX_WORKER_OUTPUT_BYTES:
            raise Reject("worker output is over the size limit")
        fout.seek(0)
        return fout.read()


def _kill_group(proc) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)            # the child and anything it started
    except (AttributeError, ProcessLookupError, PermissionError, OSError):
        pass
    if proc.poll() is None:
        proc.kill()
    proc.wait()


def _check(body: bytes) -> dict:
    """Strict UTF-8, valid JSON, exact shape. Anything else is a reject."""
    try:
        out = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Reject("worker output is not valid UTF-8 JSON") from None
    ok = (isinstance(out, dict) and set(out) == {"format", "text", "findings", "error", "images", "need"}
          and isinstance(out["format"], str) and isinstance(out["text"], str)
          and isinstance(out["error"], (str, type(None)))
          and all(isinstance(x, list) for x in (out["findings"], out["images"], out["need"]))
          and all(isinstance(x, str) for x in out["images"] + out["need"])
          and all(isinstance(f, dict) and set(f) == {"check", "message", "page"}
                  and isinstance(f["check"], str) and _CHECK.fullmatch(f["check"])
                  and isinstance(f["message"], str)
                  and (f["page"] is None or (type(f["page"]) is int and f["page"] >= 0))
                  for f in out["findings"]))
    if not ok:
        raise Reject("worker output has the wrong shape")
    return out


def _finish(out: dict, name: str) -> Report:
    if len(out["findings"]) > limits.MAX_FINDINGS:
        raise Reject(f"more than {limits.MAX_FINDINGS} findings")
    if len(out["text"].encode("utf-8", "surrogatepass")) > limits.MAX_SAFE_TEXT_BYTES:
        raise Reject(f"visible text is larger than the {limits.MAX_SAFE_TEXT_BYTES // limits.MB} MB limit")
    if len(out["images"]) > limits.MAX_PAGE_IMAGES:
        raise Reject(f"worker returned more than {limits.MAX_PAGE_IMAGES} images")
    images = []
    for s in out["images"]:
        try:
            img = base64.b64decode(s, validate=True)
        except binascii.Error:
            raise Reject("worker returned an image that is not base64") from None
        if not img.startswith(PNG):
            raise Reject("worker returned an image that is not a PNG")
        images.append(img)

    def tidy(s):
        return clip(strip_invisible(s), 300)
    return Report(path=name, format=tidy(out["format"]) or "unknown", safe_pages=[strip_invisible(out["text"])],
                  error=tidy(out["error"]) if out["error"] is not None else None, images=images,
                  findings=[Finding(check=f["check"], message=tidy(f["message"]),
                                    page=f["page"]) for f in out["findings"]])


# --------------------------------------------------------------------------- child


def extract(raw: bytes, job: dict) -> dict:
    """Run the extractor for job["family"]. Never raises: an exception becomes the "error" field."""
    need: list[str] = []
    resources = job.get("resources") or {}

    def from_host(url, kind):                          # stylesheets come as bytes from the host, never the network
        if url not in resources:
            need.append(url)
            return b""
        return None if resources[url] is None else base64.b64decode(resources[url])

    try:
        rep = _dispatch(raw, job, from_host)
        # the caps hold here, before anything is serialised: the host only ever parses a bounded reply
        text = strip_invisible("\n\f".join(rep.safe_pages))
        if len(text.encode("utf-8", "surrogatepass")) > limits.MAX_SAFE_TEXT_BYTES:
            raise limits.OverLimit(f"visible text is larger than the {limits.MAX_SAFE_TEXT_BYTES // limits.MB} MB limit")
        if len(rep.findings) > limits.MAX_FINDINGS:
            raise limits.OverLimit(f"more than {limits.MAX_FINDINGS} findings")
    except Exception as e:
        # the exception type only: its message can carry text from the file (part names, values) into the reason
        why = str(e) if isinstance(e, limits.Refused) else f"scan failed ({type(e).__name__})"
        return {"format": "", "text": "", "findings": [], "error": why, "images": [], "need": []}
    return {"format": rep.format, "text": text, "error": rep.error,
            "findings": [{"check": f.check, "message": clip(f.message, 300), "page": f.page}
                         for f in rep.findings],
            "images": [base64.b64encode(i).decode() for i in rep.images], "need": list(dict.fromkeys(need))}


def _dispatch(raw: bytes, job: dict, fetch_resource) -> Report:
    family, name = job["family"], job["name"]
    if family == "pdf":
        from .pdf.validator import scan_pdf
        return scan_pdf(raw, name, page_images=bool(job.get("page_images")))
    if family == "image":
        from .formats.image import scan_image
        return scan_image(raw, name)
    if family == "zip":
        from .formats.office import scan_ooxml
        return scan_ooxml(raw, name)
    kind = _text_kind(raw, job["ctype"])
    if kind == "html":
        from .formats.html import scan_html
        return scan_html(raw, name, base_url=job["base_url"], fetch_resource=fetch_resource)
    from .formats.text import scan_text
    return scan_text(raw, name, markdown=kind == "markdown", base_url=job["base_url"], fetch_resource=fetch_resource,
                     ambiguous=not job["ctype"])


def _limit_self() -> None:
    """CPU seconds, address space and output file size. Some limits fail on macOS: tolerated (the host's kill
    timer and output check still hold)."""
    try:
        import resource
    except ImportError:                                # not on Windows
        return
    caps = [(resource.RLIMIT_CPU, max(1, math.ceil(limits.WORKER_SECONDS))),
            (resource.RLIMIT_AS, limits.WORKER_MEMORY_BYTES),
            (resource.RLIMIT_FSIZE, limits.MAX_WORKER_OUTPUT_BYTES),
            (resource.RLIMIT_CORE, 0)]
    for which, soft in caps:
        try:
            _, hard = resource.getrlimit(which)
            if hard != resource.RLIM_INFINITY:
                soft = min(soft, hard)
            resource.setrlimit(which, (soft, hard))
        except (ValueError, OSError):
            pass


def main() -> None:
    head, _, raw = sys.stdin.buffer.read().partition(b"\n")
    job = json.loads(head)
    for k, v in job.get("limits", {}).items():        # the host's caps are the ones that count
        if k.isupper() and hasattr(limits, k):
            setattr(limits, k, v)
    _limit_self()
    out = extract(raw, job)
    sys.stdout.buffer.write(json.dumps(out).encode("ascii"))           # ASCII: one byte per character on the host


if __name__ == "__main__":
    main()
