"""readerguard scan <paths|dirs|URLs|-> [--json [--with-text] [--with-images]] [--strict]
                                                       exit code 0 all accepted, 1 any rejected
   readerguard text <path|URL|-> [-o out.txt] [--strict]   visible-only text; exit code 0 accepted, 1 rejected
   readerguard update-ioc [--ioc-dir DIR]              download the domain threat lists (run hourly)
   A directory means every file under it, whatever its name (the content decides); an empty one is a reject.
   "-" reads the file from standard input (for example inside the no-network scan container).
   --resources FILE: a web page's linked stylesheets, as JSON {"<url as in missing_stylesheets>": "<base64>"}"""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import sys
from pathlib import Path

from . import limits
from .api import ScanResult, _open_regular, scan
from .fetch import FetchOptions
from .ioc import refresh_ioc


STDIN = object()                                         # the literal top-level "-" argument, and nothing else


def _input(src):
    """CLI arguments come from the operator, so a non-URL argument is a local path. The library itself never treats
    a str as a path (see api._load): only this explicit Path() opts in. A file found inside a directory comes as
    an open file (see _sources), never as a name, so a file called "-" is never read as standard input."""
    if src is STDIN or src == "-":
        return sys.stdin.buffer
    if not isinstance(src, str):
        return src
    return src if src.lower().startswith(("http://", "https://")) else Path(src)


def _resources(path):
    """--resources FILE -> {url: bytes}. Anything malformed raises ValueError (the CLI then exits 1)."""
    if not path:
        return None
    if Path(path).stat().st_size > 2 * limits.MAX_STYLESHEET_BYTES:          # base64 + keys: well under 2x
        raise ValueError("file is over the stylesheet size limit")
    data = json.loads(Path(path).read_text("utf-8"))
    if not isinstance(data, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in data.items()):
        raise ValueError("must be a JSON object of URL -> base64 string")
    out = {k: base64.b64decode(v, validate=True) for k, v in data.items()}
    if len(out) > limits.MAX_STYLESHEETS or sum(map(len, out.values())) > limits.MAX_STYLESHEET_BYTES:
        raise ValueError(f"more than {limits.MAX_STYLESHEETS} stylesheets or "
                         f"{limits.MAX_STYLESHEET_BYTES // limits.MB} MB")
    return out


def _sources(items):
    """-> (source, None) for each input, or (name, reason) for one that cannot be scanned. A directory gives every
    regular file under it, whatever its name: the content decides, never the extension. Inside a directory,
    symbolic links are never followed (an uploaded link could point at /etc/passwd or a key file) and each file is
    opened without following links or blocking, so a FIFO swapped in later is a reject, not a hang."""
    for s in items:
        if not s.strip():
            yield s, "empty path"
            continue
        if s == "-":
            yield STDIN, None
            continue
        if s.lower().startswith(("http://", "https://")) or not Path(s).is_dir():
            yield s, None
            continue
        files = []
        for root, dirs, names in os.walk(s, followlinks=False):
            dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(root, d)))
            files += [os.path.join(root, n) for n in sorted(names)]
        if not files:
            yield s, "directory holds no files to scan"
        for f in files:
            if os.path.islink(f):
                yield f, "symbolic link (not followed)"
                continue
            try:
                yield _Named(_open_regular(Path(f), follow_symlinks=False), f), None
            except Exception as e:
                yield f, str(e)


class _Named:
    """An open file object that reports the path it was found at."""

    def __init__(self, f, name):
        self.f, self.name = f, name

    def read(self, n=-1):
        return self.f.read(n)

    def close(self):
        self.f.close()

    def __str__(self):
        return self.name


def _show(s) -> str:
    """A name or message for the terminal: control characters (newline, ESC...) escaped, never interpreted."""
    s = str(s)
    return s if s.isprintable() else json.dumps(s, ensure_ascii=False)[1:-1]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="readerguard", description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="check documents / URLs")
    s.add_argument("sources", nargs="+")
    s.add_argument("--json", action="store_true")
    s.add_argument("--with-text", action="store_true", help="with --json: include safe_text in each JSON line")
    s.add_argument("--with-images", action="store_true",
                   help="with --json: include the rebuilt PNGs (base64) in each JSON line; PDFs also give page PNGs")
    s.add_argument("--strict", action="store_true", help="reject when active content (macros, scripts, ...) was removed")
    s.add_argument("-v", "--verbose", action="store_true", help="list every reason")
    t = sub.add_parser("text", help="print visible text only")
    t.add_argument("source")
    t.add_argument("-o", "--out")
    t.add_argument("--strict", action="store_true", help="reject when active content (macros, scripts, ...) was removed")
    u = sub.add_parser("update-ioc", help="download the domain threat lists (URLhaus, OpenPhish)")
    for p in (s, t, u):
        p.add_argument("--ioc-dir", help="threat list directory (default ~/.cache/readerguard/ioc)")
    for p in (s, t):
        p.add_argument("--no-resources", action="store_true",
                       help="do not fetch linked stylesheets (a page that links one is then rejected)")
        p.add_argument("--resources", metavar="FILE",
                       help='linked stylesheets as JSON {"url": "<base64>"}, keyed as missing_stylesheets lists them')
        p.add_argument("--allow-private", action="store_true", help="allow URLs that resolve to private addresses")
        p.add_argument("--deny-network", metavar="CIDR", action="append", default=[],
                       help="also refuse URLs that resolve into this network (repeatable)")
        p.add_argument("--content-type", metavar="TYPE",
                       help="the HTTP Content-Type of files and stdin (for example text/html for a fetched page)")
        p.add_argument("--ioc", choices=("auto", "off", "required"), default="auto",
                       help="domain threat lists: auto (default; checked when present), off, required")
    a = ap.parse_args(argv)
    if a.cmd == "update-ioc":
        try:
            for f, n in refresh_ioc(a.ioc_dir).items():
                print(f"{f}: {n} entries")
        except Exception as e:
            print(f"[readerguard] {e}", file=sys.stderr)
            return 1
        return 0
    try:
        res = _resources(a.resources)
    except Exception as e:
        print(f"[readerguard] --resources: {e}", file=sys.stderr)
        return 1
    try:
        deny = tuple(str(ipaddress.ip_network(n, strict=False)) for n in getattr(a, "deny_network", []))
    except ValueError as e:
        print(f"[readerguard] --deny-network: {e}", file=sys.stderr)
        return 1
    fo = FetchOptions(fetch_resources=not a.no_resources, allow_private=a.allow_private, ioc=a.ioc,
                      ioc_dir=a.ioc_dir, deny_networks=deny)

    if a.cmd == "text":
        if not a.source.strip():
            print("[readerguard] rejected: empty path", file=sys.stderr)
            return 1
        r = scan(_input(a.source), strict=a.strict, fetch_options=fo, resources=res, content_type=a.content_type)
        (Path(a.out).write_text if a.out else sys.stdout.write)(r.safe_text)
        print(f"[readerguard] {_show(r.message)}", file=sys.stderr)
        return 0 if r.safe else 1

    worst = 0
    for src, empty in _sources(a.sources):
        if empty:
            r = ScanResult(safe=False, message=f"rejected: {empty}", reasons=[empty], error=empty, source=str(src))
        else:
            r = scan(_input(src), strict=a.strict, fetch_options=fo, resources=res, page_images=a.with_images,
                     content_type=a.content_type, name=str(src) if isinstance(src, _Named) else None)
            if isinstance(src, _Named):
                src.close()
        worst = max(worst, 0 if r.safe else 1)
        if a.json:
            d = r.to_dict(include_text=a.with_text)
            if a.with_images:
                d["safe_images"] = [base64.b64encode(i).decode() for i in r.safe_images]
            print(json.dumps(d))
            continue
        shown = "-" if src is STDIN else src
        print(f"{'ACCEPT' if r.safe else 'REJECT'} [{_show(r.format or '?')}] {_show(shown)}\n       {_show(r.message)}")
        if a.verbose:
            for line in r.reasons:
                print(f"         - {_show(line)}")
    return worst


if __name__ == "__main__":
    sys.exit(main())
