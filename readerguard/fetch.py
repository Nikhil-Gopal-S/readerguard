"""Safe fetcher: the only part that touches the network, and it parses nothing.

http(s) on ports 80 and 443, IPv4 only. On every hop (at most 3 redirects): the domain threat lists (ioc.py)
before any DNS lookup, one lookup, every address must be public (`is_global`), then the connection goes to that
checked address (TLS is still verified against the host name). One deadline for the whole fetch, a size cap,
no compression, no environment proxies, no cookies, no credentials. Every error is a FetchError."""
from __future__ import annotations

import dataclasses
import http.client
import ipaddress
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from . import ioc, limits

UA = "readerguard/0.3 (+document safety scanner)"
REDIRECTS = (301, 302, 303, 307, 308)


@dataclass
class FetchOptions:
    timeout: float = limits.FETCH_SECONDS      # one deadline for the whole fetch, redirects included
    max_bytes: int = limits.MAX_FILE_BYTES
    max_redirects: int = limits.MAX_REDIRECTS
    allow_private: bool = False                # dev only: skips the public-address and port checks
    fetch_resources: bool = True               # linked stylesheets of HTML pages
    user_agent: str = UA
    ioc: str = "auto"                          # domain threat lists: "auto" | "off" | "required" (see ioc.py)
    ioc_dir: str | Path | None = None          # default: ioc.DEFAULT_DIR
    ioc_max_age: float = limits.IOC_MAX_AGE_SECONDS
    deny_networks: tuple = ()                  # extra CIDRs to refuse (your network's internal "public" ranges)


@dataclass
class Fetched:
    url: str
    final_url: str
    status: int
    content_type: str
    headers: dict                              # lower-case names
    body: bytes


class FetchError(Exception):
    pass


class _Pinned:
    """Connects to the address that was checked, never to a fresh DNS answer (no rebinding). kill() (from the
    deadline timer) shuts down the connection, so a server that drips bytes cannot outlast the deadline. `raw` is
    always the object that owns the file descriptor: the TLS socket once it is wrapped (wrapping detaches the
    plain one), set before the handshake so a dripped handshake is cut off too."""
    killed, raw = False, None

    def _open(self):
        self.raw = socket.create_connection((self.ip, self.port), self.timeout)
        if self.killed:
            self.raw.close()
            raise TimeoutError("timed out")
        return self.raw

    def kill(self):
        self.killed = True
        if self.raw is not None:
            try:
                socket.socket.shutdown(self.raw, socket.SHUT_RDWR)     # the raw socket, also under TLS
            except OSError:
                pass


class _HTTP(_Pinned, http.client.HTTPConnection):
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self.ip = ip

    def connect(self):
        self.sock = self._open()


class _HTTPS(_Pinned, http.client.HTTPSConnection):
    """TLS verified against the host name (SNI + certificate check)."""

    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self.ip = ip

    def connect(self):
        sock = self._open()
        try:
            self.sock = self.raw = self._context.wrap_socket(sock, server_hostname=self.host,
                                                             do_handshake_on_connect=False)
            if self.killed:
                raise TimeoutError("timed out")
            self.sock.do_handshake()
        except BaseException:
            (self.raw or sock).close()
            raise


def _left(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise FetchError("timed out")
    return left


def _settimeout(conn, deadline: float) -> None:
    """Each blocking socket call may only use what is left of the one deadline."""
    left = _left(deadline)
    if conn.sock:
        conn.sock.settimeout(left)


# Refused whatever the interpreter's ipaddress tables say (older Pythons call 192.0.0.0/24 global): the IANA
# special-purpose IPv4 registry, plus platform-internal addresses that are "public" on paper.
DENY_V4 = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "168.63.129.16/32",                     # Azure WireServer / host agent, reachable from every Azure VM
)]


def _public(ip) -> bool:
    return (ip.version == 4 and ip.is_global and not ip.is_multicast
            and not any(ip in n for n in DENY_V4))


def _check_url(url: str, opt: FetchOptions):
    """-> (scheme, host, port, request target). Threat lists are checked here, before any DNS lookup, on the
    same string that is fetched."""
    url = url.strip()
    u = urlsplit(url)
    scheme = u.scheme.lower()
    if scheme not in ("http", "https"):
        raise FetchError(f"unsupported URL scheme '{u.scheme}'")
    if "@" in u.netloc:
        raise FetchError("URL must not contain a user name or password")
    try:
        host, port = ioc.norm_host(u.hostname or ""), u.port or (443 if scheme == "https" else 80)
    except ValueError:
        raise FetchError("URL has an invalid host or port") from None
    if not host:
        raise FetchError("URL has no host")
    if port not in (80, 443) and not opt.allow_private:
        raise FetchError(f"port {port} is not allowed (80 and 443 only)")
    reason = ioc.check(url, opt.ioc, opt.ioc_dir, opt.ioc_max_age)
    if reason:
        raise FetchError(reason)
    return scheme, host, port, (u.path or "/") + (f"?{u.query}" if u.query else "")


_LOOKUPS = threading.BoundedSemaphore(32)     # lookups in flight; one that outlives its deadline holds its slot


def _no_public(host: str) -> FetchError:
    """One message for every resolution or address-policy failure: it must not tell an outside user which
    internal names exist or what they resolve to."""
    return FetchError(f"refusing to fetch {host}: no public IPv4 address (unresolvable, or a non-public address)")


def _lookup(host: str, port: int, deadline: float):
    """getaddrinfo has no timeout of its own: run it in a thread and stop waiting at the deadline. A lookup that
    never returns keeps its slot, so a resolver that hangs cannot pile up threads without bound."""
    if not _LOOKUPS.acquire(blocking=False):
        raise FetchError("too many DNS lookups pending")
    box = []

    def run():
        try:
            box.append(socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM))
        except BaseException as e:
            box.append(e)
        finally:
            _LOOKUPS.release()
    t = threading.Thread(target=run, daemon=True)
    try:
        t.start()
    except BaseException:
        _LOOKUPS.release()
        raise
    t.join(_left(deadline))
    if not box:
        raise FetchError("timed out")
    if isinstance(box[0], BaseException):
        raise _no_public(host)
    return box[0]


def _resolve(host: str, port: int, opt: FetchOptions, deadline: float) -> str:
    """One lookup, IPv4 only; every address must be public. Returns the address to connect to."""
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        ips = [ipaddress.ip_address(i[4][0]) for i in _lookup(host, port, deadline)]
    if not ips:
        raise _no_public(host)
    for ip in ips:
        if ip.version != 4 or (not opt.allow_private and not _public(ip)) or any(
                ip in ipaddress.ip_network(n, strict=False) for n in opt.deny_networks):
            raise _no_public(host)
    return str(ips[0])


def _get(scheme, host, ip, port, target, opt: FetchOptions, deadline: float):
    conn = (_HTTPS if scheme == "https" else _HTTP)(host, ip, port, _left(deadline))
    timer = threading.Timer(_left(deadline), conn.kill)
    timer.daemon = True
    timer.start()
    try:
        conn.request("GET", target, headers={"User-Agent": opt.user_agent, "Accept": "*/*",
                                             "Accept-Encoding": "identity", "Connection": "close"})
        _settimeout(conn, deadline)
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        if not 200 <= resp.status < 300:
            return resp.status, headers, b""
        if headers.get("content-encoding", "identity").strip().lower() not in ("", "identity"):
            raise FetchError("compressed response refused")
        too_big = f"response exceeds the {opt.max_bytes:,} byte limit"
        size = headers.get("content-length", "").strip()
        if size.isdigit() and int(size) > opt.max_bytes:
            raise FetchError(too_big)
        body = bytearray()
        while True:
            _settimeout(conn, deadline)
            chunk = resp.read1(65536)
            if not chunk:
                if conn.killed:                  # cut short by the deadline, not the end of the body
                    raise FetchError("timed out")
                if size.isdigit() and len(body) != int(size):   # read1 does not raise on a short body
                    raise FetchError("incomplete response (connection closed early)")
                return resp.status, headers, bytes(body)
            body += chunk
            if len(body) > opt.max_bytes:
                raise FetchError(too_big)
    except Exception:
        if conn.killed:
            raise FetchError("timed out") from None
        raise
    finally:
        timer.cancel()
        conn.close()


def fetch(url: str, opt: FetchOptions | None = None) -> Fetched:
    opt = opt or FetchOptions()
    deadline = time.monotonic() + opt.timeout
    cur = url
    try:
        for _ in range(opt.max_redirects + 1):
            scheme, host, port, target = _check_url(cur, opt)
            ip = _resolve(host, port, opt, deadline)
            if ip != host and (reason := ioc.check(f"http://{ip}/", opt.ioc, opt.ioc_dir, opt.ioc_max_age)):
                raise FetchError(reason)                 # the address a name resolves to may be listed too
            status, headers, body = _get(scheme, host, ip, port, target, opt, deadline)
            if status in REDIRECTS:
                if not headers.get("location"):
                    raise FetchError(f"redirect without Location from {cur}")
                cur = urljoin(cur, headers["location"].strip())
                continue
            if not 200 <= status < 300:
                raise FetchError(f"HTTP {status} from {cur}")
            ctype = headers.get("content-type", "").split(";")[0].strip().lower()
            return Fetched(url=url, final_url=cur, status=status, content_type=ctype, headers=headers, body=body)
        raise FetchError(f"more than {opt.max_redirects} redirects")
    except FetchError:
        raise
    except Exception as e:                       # TLS, socket, HTTP protocol, timeouts, bad URLs, ...
        # socket / TLS errors say what failed; HTTP protocol errors can quote what the server sent
        raise FetchError(f"{type(e).__name__}: {e}" if isinstance(e, OSError) else type(e).__name__) from None


def resource_fetcher(opt: FetchOptions):
    """fn(url, kind) -> bytes | None, for an HTML page's linked stylesheets only (any other kind: None).
    Same rules as the page on every hop; per page at most MAX_STYLESHEETS files, MAX_STYLESHEET_BYTES in total
    and one shared deadline. None means not fetched; it never raises."""
    start, used = time.monotonic(), {"files": 0, "bytes": 0}

    def get(url: str, kind: str = "text/css"):
        left = opt.timeout - (time.monotonic() - start)
        room = min(opt.max_bytes, limits.MAX_STYLESHEET_BYTES - used["bytes"])
        if kind != "text/css" or used["files"] >= limits.MAX_STYLESHEETS or left <= 0:
            return None
        used["files"] += 1
        try:
            body = fetch(url, dataclasses.replace(opt, max_bytes=room, timeout=left)).body
        except Exception:
            return None
        used["bytes"] += len(body)
        return body
    return get
