"""Domain threat lists (IOC), checked before any DNS lookup: on the URL, on every redirect hop and on every
linked stylesheet. Matching uses local files only, never a per-URL network call.

- URLhaus host file (abuse.ch, CC0) -> hosts: a listed host blocks itself and all its subdomains.
- OpenPhish community feed -> exact URLs only (shared hosting: never the whole host).
- Your own lists: any `*.hosts` file in the list directory, one host per line (`#` comments), host-level.

`refresh_ioc()` (CLI: `readerguard update-ioc`, meant to run hourly) is the only code that downloads lists, and
it goes through the safe fetcher. Modes: "auto" (default) skips the check while no list exists but rejects when
the downloaded lists are stale; "off" never checks; "required" also rejects when no downloaded list is present.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import os
import re
import socket
import string
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import limits

DEFAULT_DIR = Path.home() / ".cache" / "readerguard" / "ioc"
FEEDS = {  # file name -> (download URL, label, kind)
    "urlhaus.txt": ("https://urlhaus.abuse.ch/downloads/hostfile/", "URLhaus (malware)", "hosts"),
    "openphish.txt": ("https://openphish.com/feed.txt", "OpenPhish (phishing)", "urls"),
}


_LEGACY_V4 = re.compile(r"(0x[0-9a-f]*|[0-9]+)(\.(0x[0-9a-f]*|[0-9]+)){0,3}", re.ASCII)
_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", re.ASCII)


def _ip(h: str) -> str | None:
    """Canonical form of an IP literal, including the legacy IPv4 spellings that resolvers accept (2130706433,
    0x7f.1, 127.1, 0177.0.0.1); None when h is not one. Raises ValueError for a broken legacy spelling."""
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    if _LEGACY_V4.fullmatch(h):
        try:
            return socket.inet_ntoa(socket.inet_aton(h))
        except OSError:
            raise ValueError(f"invalid IPv4 address {h!r}") from None
    return None


def norm_host(host: str) -> str:
    """Lowercase, no trailing dot, IDNA -> punycode; IP literals in canonical form (checked again after IDNA, which
    maps Unicode digits such as superscripts to ASCII). Anything that is not then an IP or a plain DNS name
    (letters, digits, '-', '_'; labels of 1-63, 253 in all) raises ValueError: a resolver reads backslash
    escapes and other odd bytes its own way, so such a name could reach a listed host unchecked."""
    h = host.strip().strip("[]").lower().rstrip(".")
    if not h:
        return ""
    if len(h) > 1000:
        raise ValueError("host name is too long")
    ip = _ip(h)
    if ip:
        return ip
    h = h.encode("idna").decode("ascii").rstrip(".").lower()
    ip = _ip(h)
    if ip:
        return ip
    labels = h.split(".")
    if len(h) > 253 or not all(_LABEL.fullmatch(x) for x in labels):
        raise ValueError("host name is not a valid DNS name")
    return h


_UNRESERVED = frozenset(string.ascii_letters + string.digits + "-._~")


def _canon_path(path: str) -> str:
    """RFC 3986 normal form, then lower case: unreserved escapes decoded, other escapes upper-cased, ';params'
    dropped, '//' collapsed, dot segments removed, no trailing '/' (but the root)."""
    def esc(m):
        c = chr(int(m.group(1), 16))
        return c if c in _UNRESERVED else "%" + m.group(1).upper()
    p = re.sub(r"%([0-9A-Fa-f]{2})", esc, path or "/")
    p = re.sub(r";[^/]*", "", p)
    out: list[str] = []
    for seg in re.sub(r"/{2,}", "/", p).split("/")[1:]:
        if seg == "..":
            if out:
                out.pop()
        elif seg != ".":
            out.append(seg)
    return ("/" + "/".join(out)).lower().rstrip("/") or "/"


def _canon_query(q: str) -> str:
    return re.sub(r"%([0-9A-Fa-f]{2})", lambda m: "%" + m.group(1).upper(), q).lower()


def norm_url(url: str) -> str:
    """normalised host + path (+ ?query); scheme, port, user info and fragment dropped (see _canon_path)."""
    u = urlsplit(url.strip())
    return f"{norm_host(u.hostname or '')}{_canon_path(u.path)}" + (f"?{_canon_query(u.query)}" if u.query else "")


def _url_keys(url: str) -> list[str]:
    """What a checked URL is looked up as: itself, without its query, and every parent path (not the bare host
    unless that is the URL): a listed phishing page also covers what lies under it."""
    u = urlsplit(url.strip())
    host, path = norm_host(u.hostname or ""), _canon_path(u.path)
    keys = [host + path] + ([f"{host}{path}?{_canon_query(u.query)}"] if u.query else [])
    while path.count("/") > 1:
        path = path.rsplit("/", 1)[0]
        keys.append(host + path)
    return keys


def _entry_host(tok: str) -> str:
    """A host-list entry in any common spelling: host, .host, *.host, ||host^, host:port, a URL."""
    tok = tok.strip().removeprefix("||").removesuffix("^")
    if "://" in tok:
        tok = urlsplit(tok).hostname or ""
    elif tok.count(":") == 1 and not tok.startswith("["):
        tok = tok.split(":", 1)[0]
    tok = tok.removeprefix("*.").lstrip(".")
    h = norm_host(tok)
    if not h:
        raise ValueError("empty host")
    return h


def _hosts(text: str) -> tuple[set[str], int]:
    """Hosts-file lines (`127.0.0.1<TAB>evil.com`) or bare hosts; `#` starts a comment. -> (hosts, bad lines)."""
    out, bad = set(), 0
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if parts:
            try:
                out.add(_entry_host(parts[-1]))
            except ValueError:
                bad += 1
    return out - {"", "localhost"}, bad


def _urls(text: str) -> tuple[set[str], int]:
    out, bad = set(), 0
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.strip().lower().startswith(("http://", "https://")):
            try:
                out.add(norm_url(line))
                continue
            except ValueError:
                pass
        bad += 1
    return out, bad


_PARSE = {"hosts": _hosts, "urls": _urls}
_cache: dict[str, tuple] = {}


def _read(path: Path, kind: str) -> tuple[set[str], int]:
    st = path.stat()
    key = (st.st_mtime_ns, st.st_size)
    hit = _cache.get(str(path))
    if not hit or hit[0] != key:
        hit = _cache[str(path)] = (key, _PARSE[kind](path.read_text("utf-8", "replace")))
    return hit[1]


def _walk(host: str):
    """a.b.evil.com -> a.b.evil.com, b.evil.com, evil.com (never the bare TLD)."""
    try:
        ipaddress.ip_address(host)
        yield host
        return
    except ValueError:
        pass
    labels = host.split(".")
    for i in range(max(len(labels) - 1, 1)):
        yield ".".join(labels[i:])


def check(url: str, mode: str = "auto", directory=None, max_age: float = limits.IOC_MAX_AGE_SECONDS) -> str | None:
    """None when the URL may be fetched, else the reason to reject it."""
    if mode == "off":
        return None
    if mode not in ("auto", "required"):
        return f"unknown ioc mode {mode!r}"
    d = Path(directory or DEFAULT_DIR)
    feeds = [d / n for n in FEEDS if (d / n).is_file()]
    own = sorted(p for p in d.glob("*.hosts") if p.is_file()) if d.is_dir() else []
    if feeds or own:
        url = url.strip()                            # the same string the fetcher uses
        try:
            host, keys = norm_host(urlsplit(url).hostname or ""), set(_url_keys(url))
        except ValueError:
            return "blocked: the URL host cannot be normalised for the threat lists"
        if not host:
            return "blocked: the URL has no host to check against the threat lists"
        for p in feeds + own:
            _, label, kind = FEEDS.get(p.name, (None, f"local blocklist {p.name}", "hosts"))
            entries, bad = _read(p, kind)
            if bad and p in own:                     # an entry the operator wrote may not be silently ignored
                return f"blocked: local blocklist {p.name} has {bad} line(s) that are not a host name"
            if kind == "urls":
                if hit := next((k for k in keys if k in entries), None):
                    return f"blocked: {hit} is on {label}"
            elif hit := next((h for h in _walk(host) if h in entries), None):
                return f"blocked: {hit} is on {label}"
    if feeds:
        age = time.time() - min(p.stat().st_mtime for p in feeds)     # the OLDEST list decides
        if age > max_age:
            return f"threat lists are stale ({age / 3600:.0f} h old; run: readerguard update-ioc)"
    if mode == "required" and len(feeds) < len(FEEDS):
        missing = ", ".join(n for n in FEEDS if not (d / n).is_file())
        return f"threat lists are required but {missing} is not loaded from {d} (run: readerguard update-ioc)"
    return None


def _validate(text: str, kind: str, old: Path) -> int:
    """Entry count of a downloaded list; raises when it does not look like the feed (an error or rate-limit page
    served with status 200, a changed format) or shrank to under half of the list it would replace."""
    if re.search(r"<(html|!doctype|body|head)\b", text[:4096], re.I):
        raise ValueError("the download is an HTML page, not the list")
    entries, bad = _PARSE[kind](text)
    if not entries or bad > 0.1 * (len(entries) + bad):
        raise ValueError("the download does not look like the list")
    if old.is_file():
        before = len(_PARSE[kind](old.read_text("utf-8", "replace"))[0])
        if len(entries) < 0.5 * before:
            raise ValueError(f"the list shrank from {before} to {len(entries)} entries")
    return len(entries)


def refresh_ioc(directory=None, fetch_options=None) -> dict[str, int]:
    """Download every list into `directory` (default DEFAULT_DIR) through the safe fetcher; returns the entry
    count per list. Lists that downloaded are saved even when another failed; any failure then raises."""
    from .fetch import FetchOptions, fetch
    opt = dataclasses.replace(fetch_options or FetchOptions(), ioc="off")   # stale lists must not block refresh
    d = Path(directory or DEFAULT_DIR)
    d.mkdir(parents=True, exist_ok=True)
    counts, errors = {}, []
    for fname, (url, label, kind) in FEEDS.items():
        try:
            text = fetch(url, opt).body.decode("utf-8")
            n = _validate(text, kind, d / fname)
            # a temp file of its own: two refreshes at once must never write into the same file
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=d, prefix=fname + ".", suffix=".tmp",
                                             delete=False) as f:
                f.write(text)
                f.flush()
                os.fsync(f.fileno())
            os.replace(f.name, d / fname)
            counts[fname] = n
        except Exception as e:
            errors.append(f"{label}: {e}")
    if errors:
        raise RuntimeError("could not refresh " + "; ".join(errors))
    return counts
