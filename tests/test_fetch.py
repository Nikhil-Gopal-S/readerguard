"""Safe fetcher and domain threat lists. No real network: DNS and connections are mocked."""
import io
import ipaddress
import os
import socket
import ssl
import time

import pytest

from readerguard import fetch, ioc, scan
from readerguard.cli import main
from readerguard.fetch import FetchError, FetchOptions

PUBLIC = "93.184.216.34"
PAGE = b"<!doctype html><html><body><p>The Silver plan covers day-care procedures.</p></body></html>"

# Must be refused whatever the Python version says about is_global (the list decides, not the version).
PRIVATE_V4 = ["127.0.0.1", "127.255.255.254", "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255",
              "192.168.0.1", "192.168.255.255", "169.254.169.254", "100.64.0.1", "100.127.255.254", "0.0.0.0",
              "198.18.0.1", "198.19.255.255", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
              "192.0.0.8", "192.0.0.192", "168.63.129.16"]
PRIVATE_V6 = ["::1", "::ffff:127.0.0.1", "64:ff9b::a00:1", "fc00::1", "fdff:ffff::1", "fe80::1"]


class Resp:
    def __init__(self, status=200, headers=None, body=b"", on_read=None):
        self.status, self.headers, self._buf, self.on_read = status, headers or {}, io.BytesIO(body), on_read

    def getheaders(self):
        return list(self.headers.items())

    def read1(self, n):
        if self.on_read:
            self.on_read()
        return self._buf.read(min(n, 4))


class Net:
    """Fake DNS + fake HTTP(S) connections. routes: (host, target) -> Resp."""

    def __init__(self, monkeypatch, dns=None, routes=None):
        self.dns, self.routes, self.conns, self.lookups = dns or {}, routes or {}, [], []
        monkeypatch.setattr(socket, "getaddrinfo", self.getaddrinfo)
        net = self

        class Conn:
            killed = False

            def kill(self):
                self.killed = True

            def __init__(self, host, ip, port, timeout, tls):
                self.host, self.ip, self.port, self.timeout, self.tls, self.sock = host, ip, port, timeout, tls, None
                net.conns.append(self)

            def request(self, method, target, headers):
                self.method, self.target, self.headers = method, target, headers

            def getresponse(self):
                return net.routes[(self.host, self.target)]

            def close(self):
                pass
        monkeypatch.setattr(fetch, "_HTTP", lambda *a: Conn(*a, tls=False))
        monkeypatch.setattr(fetch, "_HTTPS", lambda *a: Conn(*a, tls=True))

    def getaddrinfo(self, host, port, family=0, type=0, *a):
        self.lookups.append((host, family))
        if host not in self.dns:
            raise socket.gaierror(socket.EAI_NONAME, "no such host")
        return [(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))
                for ip in self.dns[host]]


def ok(body=PAGE, ctype="text/html"):
    return Resp(200, {"Content-Type": ctype}, body)


def moved(to, status=302):
    return Resp(status, {"Location": to})


# ---------------------------------------------------------------- addresses

@pytest.mark.parametrize("addr", PRIVATE_V4 + PRIVATE_V6)
def test_private_and_special_addresses_are_refused(monkeypatch, addr):
    net = Net(monkeypatch, dns={"evil.example": [addr]})
    with pytest.raises(FetchError, match="non-public|IPv6|IPv4"):
        fetch.fetch("https://evil.example/")
    assert net.conns == []


@pytest.mark.parametrize("addr", PRIVATE_V4)
def test_private_ipv4_literals_are_refused(monkeypatch, addr):
    net = Net(monkeypatch)
    assert not fetch._public(ipaddress.ip_address(addr))
    with pytest.raises(FetchError, match="non-public"):
        fetch.fetch(f"http://{addr}/")
    assert net.conns == [] and net.lookups == []


@pytest.mark.parametrize("url", ["http://[::1]/", "http://[::ffff:7f00:1]/", "http://2130706433/",
                                 "http://0x7f.1/", "http://127.1/"])
def test_odd_address_spellings_are_refused(monkeypatch, url):
    Net(monkeypatch, dns={"2130706433": ["127.0.0.1"], "0x7f.1": ["127.0.0.1"], "127.1": ["127.0.0.1"]})
    with pytest.raises(FetchError):
        fetch.fetch(url)


def test_one_private_answer_among_public_ones_is_refused(monkeypatch):
    net = Net(monkeypatch, dns={"mixed.example": [PUBLIC, "10.0.0.5"]})
    with pytest.raises(FetchError, match="non-public"):         # the address itself is not echoed
        fetch.fetch("https://mixed.example/")
    assert net.conns == []


def test_ipv4_only_lookup_and_aaaa_only_host_refused(monkeypatch):
    net = Net(monkeypatch, dns={})                        # an AAAA-only host has no IPv4 answer
    with pytest.raises(FetchError, match="IPv4"):
        fetch.fetch("https://v6only.example/")
    assert net.lookups == [("v6only.example", socket.AF_INET)]


def test_public_address_is_fetched_from_the_checked_ip(monkeypatch):
    net = Net(monkeypatch, dns={"example.org": [PUBLIC]}, routes={("example.org", "/a?b=1"): ok()})
    got = fetch.fetch("https://example.org/a?b=1#frag")
    assert got.body == PAGE and got.content_type == "text/html" and got.final_url == "https://example.org/a?b=1#frag"
    (c,) = net.conns
    assert (c.host, c.ip, c.port, c.tls, c.method) == ("example.org", PUBLIC, 443, True, "GET")
    assert 0 < c.timeout <= 20
    assert c.headers["Accept-Encoding"] == "identity"
    assert not {"Cookie", "Authorization", "Proxy-Authorization"} & set(c.headers)


def test_allow_private_is_the_only_way_to_a_private_address(monkeypatch):
    net = Net(monkeypatch, dns={"intranet": ["10.0.0.5"]}, routes={("intranet", "/"): ok()})
    assert fetch.fetch("http://intranet:8080/", FetchOptions(allow_private=True)).body == PAGE
    assert net.conns[0].ip == "10.0.0.5"


# ---------------------------------------------------------------- pinned connection, TLS

def test_https_connection_pins_ip_and_verifies_host_name(monkeypatch):
    seen = {}
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout: seen.setdefault("addr", addr) and "sock")
    c = fetch._HTTPS("example.org", PUBLIC, 443, 5)
    assert c._context.verify_mode == ssl.CERT_REQUIRED and c._context.check_hostname

    class TLS:
        def do_handshake(self):
            seen["handshake"] = True

    tls = TLS()

    class Ctx:
        def wrap_socket(self, sock, server_hostname, do_handshake_on_connect=True):
            seen["sni"] = server_hostname
            return tls
    c._context = Ctx()
    c.connect()
    assert seen == {"addr": (PUBLIC, 443), "sni": "example.org", "handshake": True}
    assert c.sock is tls and c.raw is tls          # the deadline kill shuts the socket that owns the descriptor


def test_http_connection_pins_ip(monkeypatch):
    seen = []
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout: seen.append(addr) or "sock")
    c = fetch._HTTP("example.org", PUBLIC, 80, 5)
    c.connect()
    assert seen == [(PUBLIC, 80)] and c.host == "example.org"


def test_environment_proxies_are_ignored(monkeypatch):
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
        monkeypatch.setenv(k, "http://10.0.0.1:3128")
    net = Net(monkeypatch, dns={"example.org": [PUBLIC]}, routes={("example.org", "/"): ok()})
    fetch.fetch("http://example.org")
    assert [(c.host, c.ip) for c in net.conns] == [("example.org", PUBLIC)]


# ---------------------------------------------------------------- URL rules

@pytest.mark.parametrize("url,msg", [("ftp://example.org/a", "scheme"), ("file:///etc/passwd", "scheme"),
                                     ("https://user:pw@example.org/", "user name"), ("https://user@example.org/", "user name"),
                                     ("http://example.org:8080/", "port 8080"), ("https://example.org:22/", "port 22"),
                                     ("http:///nohost", "no host"), ("http://example.org:99999/", "invalid")])
def test_url_rules(monkeypatch, url, msg):
    net = Net(monkeypatch, dns={"example.org": [PUBLIC]})
    with pytest.raises(FetchError, match=msg):
        fetch.fetch(url)
    assert net.conns == [] and net.lookups == []


def test_compressed_response_refused(monkeypatch):
    Net(monkeypatch, dns={"example.org": [PUBLIC]},
        routes={("example.org", "/"): Resp(200, {"Content-Encoding": "gzip"}, b"\x1f\x8b...")})
    with pytest.raises(FetchError, match="compressed"):
        fetch.fetch("https://example.org/")


def test_size_cap(monkeypatch):
    Net(monkeypatch, dns={"example.org": [PUBLIC]},
        routes={("example.org", "/big"): Resp(200, {}, b"x" * 101),
                ("example.org", "/len"): Resp(200, {"Content-Length": "999999999"}, b"x"),
                ("example.org", "/fit"): Resp(200, {}, b"x" * 100)})
    opt = FetchOptions(max_bytes=100)
    for path in ("/big", "/len"):
        with pytest.raises(FetchError, match="limit"):
            fetch.fetch("https://example.org" + path, opt)
    assert len(fetch.fetch("https://example.org/fit", opt).body) == 100


def test_http_errors_refused(monkeypatch):
    Net(monkeypatch, dns={"example.org": [PUBLIC]}, routes={("example.org", "/"): Resp(404), ("example.org", "/n"): Resp(304)})
    for path in ("/", "/n"):
        with pytest.raises(FetchError, match="HTTP"):
            fetch.fetch("https://example.org" + path)


@pytest.mark.parametrize("exc", [OSError("reset"), ssl.SSLError("bad tls"), socket.timeout("slow"), KeyError("x")])
def test_every_error_becomes_fetch_error(monkeypatch, exc):
    Net(monkeypatch, dns={"example.org": [PUBLIC]})

    def boom(*a):
        raise exc
    monkeypatch.setattr(fetch, "_HTTPS", boom)
    with pytest.raises(FetchError):
        fetch.fetch("https://example.org/")


# ---------------------------------------------------------------- deadline

def test_one_total_deadline(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])

    def slow():
        clock[0] += 6                                      # each chunk takes 6 s; 20 s total for everything

    net = Net(monkeypatch, dns={"example.org": [PUBLIC]},
              routes={("example.org", "/"): Resp(200, {}, b"x" * 40, on_read=slow)})
    with pytest.raises(FetchError, match="timed out"):
        fetch.fetch("https://example.org/")
    assert net.conns[0].timeout == 20


def test_deadline_covers_redirects(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])

    class Slow(Resp):
        def getheaders(self):
            clock[0] += 8
            return super().getheaders()
    Net(monkeypatch, dns={"example.org": [PUBLIC]},
        routes={("example.org", "/1"): Slow(302, {"Location": "/2"}), ("example.org", "/2"): Slow(302, {"Location": "/3"}),
                ("example.org", "/3"): Slow(302, {"Location": "/4"}), ("example.org", "/4"): ok()})
    with pytest.raises(FetchError, match="timed out"):
        fetch.fetch("https://example.org/1")


# ---------------------------------------------------------------- redirects

def _chain(n):
    routes = {("example.org", f"/{i}"): moved(f"/{i + 1}") for i in range(n)}
    routes[("example.org", f"/{n}")] = ok()
    return routes


def test_three_redirects_allowed_four_refused(monkeypatch):
    Net(monkeypatch, dns={"example.org": [PUBLIC]}, routes=_chain(3))
    assert fetch.fetch("https://example.org/0").final_url == "https://example.org/3"
    Net(monkeypatch, dns={"example.org": [PUBLIC]}, routes=_chain(4))
    with pytest.raises(FetchError, match="more than 3 redirects"):
        fetch.fetch("https://example.org/0")


@pytest.mark.parametrize("to,msg", [("http://internal.example/", "non-public"), ("http://169.254.169.254/latest/", "non-public"),
                                    ("file:///etc/passwd", "scheme"), ("http://u:p@example.org/", "user name"),
                                    ("http://example.org:2375/", "port")])
def test_every_redirect_hop_is_rechecked(monkeypatch, to, msg):
    net = Net(monkeypatch, dns={"example.org": [PUBLIC], "internal.example": ["10.1.2.3"]},
              routes={("example.org", "/"): moved(to)})
    with pytest.raises(FetchError, match=msg):
        fetch.fetch("https://example.org/")
    assert len(net.conns) == 1


def test_redirect_without_location_refused(monkeypatch):
    Net(monkeypatch, dns={"example.org": [PUBLIC]}, routes={("example.org", "/"): Resp(301)})
    with pytest.raises(FetchError, match="Location"):
        fetch.fetch("https://example.org/")


# ---------------------------------------------------------------- linked stylesheets

def test_resource_fetcher_is_stylesheets_only(monkeypatch):
    net = Net(monkeypatch, dns={"example.org": [PUBLIC]}, routes={("example.org", "/a.css"): ok(b".h{}", "text/css"),
                                                                  ("example.org", "/a.js"): ok(b"x()", "text/javascript")})
    get = fetch.resource_fetcher(FetchOptions())
    assert get("https://example.org/a.js", "script") is None and net.conns == []
    assert get("https://example.org/a.css", "text/css") == b".h{}"


def test_resource_fetcher_file_cap(monkeypatch):
    monkeypatch.setattr(fetch.limits, "MAX_STYLESHEETS", 2)
    net = Net(monkeypatch, dns={"example.org": [PUBLIC]}, routes={("example.org", "/a.css"): ok(b"", "text/css")})
    get = fetch.resource_fetcher(FetchOptions())
    assert [get("https://example.org/a.css", "text/css") for _ in range(3)] == [b"", b"", None]
    assert len(net.conns) == 2


def test_resource_fetcher_total_byte_cap(monkeypatch):
    monkeypatch.setattr(fetch.limits, "MAX_STYLESHEET_BYTES", 10)
    Net(monkeypatch, dns={"example.org": [PUBLIC]}, routes={("example.org", "/a.css"): ok(b"x" * 6, "text/css"),
                                                            ("example.org", "/b.css"): ok(b"y" * 6, "text/css")})
    get = fetch.resource_fetcher(FetchOptions())
    assert get("https://example.org/a.css", "text/css") == b"x" * 6
    assert get("https://example.org/b.css", "text/css") is None          # 12 bytes in total is over 10


def test_resource_fetcher_shares_one_deadline(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    net = Net(monkeypatch, dns={"example.org": [PUBLIC]}, routes={("example.org", "/a.css"): ok(b"", "text/css")})
    get = fetch.resource_fetcher(FetchOptions())
    clock[0] += 15
    assert get("https://example.org/a.css", "text/css") == b"" and net.conns[0].timeout == 5
    clock[0] += 5
    assert get("https://example.org/a.css", "text/css") is None and len(net.conns) == 1


# ---------------------------------------------------------------- domain threat lists (IOC)

@pytest.fixture
def lists(tmp_path, monkeypatch):
    monkeypatch.setattr(ioc, "DEFAULT_DIR", tmp_path)
    (tmp_path / "urlhaus.txt").write_text("# URLhaus\n127.0.0.1\tevil.com\n127.0.0.1\txn--80ak6aa92e.com\n"
                                          "127.0.0.1\t203.0.113.66\n")
    (tmp_path / "openphish.txt").write_text("https://shared-host.example/login/paypal.html\n"
                                            "http://Phish.Example:8080/a?x=1#frag\n")
    return tmp_path


@pytest.mark.parametrize("url", ["https://evil.com/", "http://a.b.evil.com/x", "https://EVIL.com/", "https://evil.com./",
                                 "https://WWW.Evil.Com.:443/p", "https://user@evil.com/", "https://ｅｖｉｌ.com/",
                                 "https://evil。com/", "https://аррӏе.com/", "https://XN--80AK6AA92E.com/",
                                 "http://203.0.113.66/"])
def test_urlhaus_host_and_subdomains_blocked(lists, url):
    assert "is on URLhaus" in ioc.check(url)


@pytest.mark.parametrize("url", ["https://notevil.com/", "https://evil.com.example.org/", "https://com/",
                                 "https://shared-host.example/other-page", "http://203.0.113.67/"])
def test_not_listed_passes(lists, url):
    assert ioc.check(url) is None


def test_openphish_is_url_level_only(lists):
    assert "is on OpenPhish" in ioc.check("https://SHARED-HOST.example./login/paypal.html#x")
    assert "is on OpenPhish" in ioc.check("http://phish.example/a?x=1")                   # port and fragment dropped
    assert ioc.check("https://shared-host.example/") is None
    assert "is on OpenPhish" in ioc.check("https://shared-host.example/login/paypal.html?y=2")   # extra query
    assert ioc.check("http://phish.example/a?x=2") is None


def test_user_host_list(lists):
    (lists / "mine.hosts").write_text("# my list\nBad.Example.\n")
    assert ioc.check("https://x.bad.example/") == "blocked: bad.example is on local blocklist mine.hosts"


def test_stale_lists_reject(lists):
    old = time.time() - 25 * 3600
    for f in ("urlhaus.txt", "openphish.txt"):
        os.utime(lists / f, (old, old))
    assert "stale" in ioc.check("https://fine.example/")
    assert ioc.check("https://fine.example/", max_age=26 * 3600) is None
    assert ioc.check("https://fine.example/", mode="off") is None


def test_missing_lists(tmp_path):
    missing = tmp_path / "nothing-here"
    assert ioc.check("https://evil.com/", "off", missing) is None
    assert ioc.check("https://evil.com/", "auto", missing) is None                   # usable out of the box
    assert "required" in ioc.check("https://evil.com/", "required", missing)
    assert "unknown ioc mode" in ioc.check("https://evil.com/", "maybe", missing)


def test_list_changes_are_picked_up(lists):
    assert ioc.check("https://new-bad.example/") is None
    (lists / "urlhaus.txt").write_text("127.0.0.1\tnew-bad.example\n# grown\n")
    assert "new-bad.example is on URLhaus" in ioc.check("https://new-bad.example/")


def test_fetcher_checks_lists_before_dns(lists, monkeypatch):
    net = Net(monkeypatch, dns={"evil.com": [PUBLIC]})
    with pytest.raises(FetchError, match="blocked: evil.com is on URLhaus"):
        fetch.fetch("https://login.evil.com/")
    assert net.lookups == [] and net.conns == []
    r = scan("https://login.evil.com/")
    assert not r.safe and "evil.com is on URLhaus" in r.message


def test_redirect_hop_to_listed_host_rejected(lists, monkeypatch):
    net = Net(monkeypatch, dns={"example.org": [PUBLIC], "evil.com": [PUBLIC]},
              routes={("example.org", "/"): moved("https://cdn.evil.com/payload")})
    with pytest.raises(FetchError, match="evil.com is on URLhaus"):
        fetch.fetch("https://example.org/")
    assert [h for h, _ in net.lookups] == ["example.org"]


def test_listed_stylesheet_is_not_fetched_and_page_rejects(lists, monkeypatch):
    page = b'<!doctype html><html><head><link rel="stylesheet" href="https://evil.com/a.css"></head><body>' \
           b'<p>The Silver plan covers day-care procedures.</p></body></html>'
    net = Net(monkeypatch, dns={"example.org": [PUBLIC], "evil.com": [PUBLIC]},
              routes={("example.org", "/"): ok(page), ("evil.com", "/a.css"): ok(b"", "text/css")})
    assert fetch.resource_fetcher(FetchOptions())("https://evil.com/a.css", "text/css") is None
    r = scan("https://example.org/")
    assert not r.safe and "stylesheet" in r.message
    assert [c.host for c in net.conns] == ["example.org"]


def test_ioc_options_reach_the_fetcher(tmp_path, monkeypatch):
    Net(monkeypatch, dns={"example.org": [PUBLIC]}, routes={("example.org", "/"): ok()})
    with pytest.raises(FetchError, match="required"):
        fetch.fetch("https://example.org/", FetchOptions(ioc="required", ioc_dir=tmp_path))
    (tmp_path / "urlhaus.txt").write_text("0.0.0.0 example.org\n")
    with pytest.raises(FetchError, match="URLhaus"):
        fetch.fetch("https://example.org/", FetchOptions(ioc="required", ioc_dir=tmp_path))
    assert fetch.fetch("https://example.org/", FetchOptions(ioc="off", ioc_dir=tmp_path)).body == PAGE


# ---------------------------------------------------------------- refreshing the lists

FEEDS = {"https://urlhaus.abuse.ch/downloads/hostfile/": b"# URLhaus\n127.0.0.1\tevil.com\n127.0.0.1\tbad.org\n",
         "https://openphish.com/feed.txt": b"https://x.example/login\n"}


def _fake_fetch(seen, feeds=FEEDS):
    def get(url, opt):
        seen.append((url, opt))
        if url not in feeds:
            raise FetchError("HTTP 503")
        return fetch.Fetched(url, url, 200, "text/plain", {}, feeds[url])
    return get


def test_refresh_ioc_writes_lists_through_the_safe_fetcher(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(fetch, "fetch", _fake_fetch(seen))
    d = tmp_path / "ioc"
    old = time.time() - 48 * 3600
    d.mkdir()
    (d / "urlhaus.txt").write_text("127.0.0.1 old.example\n")
    os.utime(d / "urlhaus.txt", (old, old))                 # stale lists must not block their own refresh
    assert ioc.refresh_ioc(d) == {"urlhaus.txt": 2, "openphish.txt": 1}
    assert {u for u, _ in seen} == set(FEEDS) and all(o.ioc == "off" and not o.allow_private for _, o in seen)
    assert "evil.com is on URLhaus" in ioc.check("https://evil.com/", directory=d)
    assert ioc.check("https://old.example/", directory=d) is None
    assert "OpenPhish" in ioc.check("https://x.example/login", directory=d)
    assert not list(d.glob("*.tmp"))


def test_refresh_ioc_failure_keeps_old_list_and_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch, "fetch", _fake_fetch([], {"https://openphish.com/feed.txt": b"<html>error</html>",
                                                         **{k: v for k, v in FEEDS.items() if "urlhaus" in k}}))
    (tmp_path / "openphish.txt").write_text("https://kept.example/\n")
    with pytest.raises(RuntimeError, match="OpenPhish"):
        ioc.refresh_ioc(tmp_path)
    assert (tmp_path / "openphish.txt").read_text() == "https://kept.example/\n"
    assert "evil.com" in (tmp_path / "urlhaus.txt").read_text()


def test_cli_update_ioc(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(fetch, "fetch", _fake_fetch([]))
    assert main(["update-ioc", "--ioc-dir", str(tmp_path)]) == 0
    assert "urlhaus.txt: 2 entries" in capsys.readouterr().out
    monkeypatch.setattr(fetch, "fetch", _fake_fetch([], {}))
    assert main(["update-ioc", "--ioc-dir", str(tmp_path)]) == 1
    assert "could not refresh" in capsys.readouterr().err


def test_cli_scan_uses_ioc_options(tmp_path, capsys):
    (tmp_path / "urlhaus.txt").write_text("127.0.0.1\tevil.com\n")
    assert main(["scan", "--ioc-dir", str(tmp_path), "https://evil.com/"]) == 1
    assert "evil.com is on URLhaus" in capsys.readouterr().out
    assert main(["scan", "--ioc", "required", "--ioc-dir", str(tmp_path / "none"), "https://a.example/"]) == 1
    assert "required" in capsys.readouterr().out


# ---------------------------------------------------------------- review fixes

def test_slow_drip_server_cannot_outlast_the_deadline(monkeypatch):
    """Real http.client over a local socket pair: one byte every 50 ms never trips a per-read timeout, so only
    the whole-fetch deadline can stop it."""
    import threading
    a, b = socket.socketpair()
    stop = threading.Event()

    def drip():
        try:
            b.recv(65536)
            b.sendall(b"HTTP/1.1 200 OK\r\nX-Slow: ")
            while not stop.wait(0.05):
                b.sendall(b"a")
        except OSError:
            pass
    threading.Thread(target=drip, daemon=True).start()
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a_, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC, 80))])
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout: a)
    t0 = time.monotonic()
    try:
        with pytest.raises(FetchError, match="timed out"):
            fetch.fetch("http://example.org/", FetchOptions(timeout=0.5))
    finally:
        stop.set()
        b.close()
    assert time.monotonic() - t0 < 3


def test_slow_dns_cannot_outlast_the_deadline(monkeypatch):
    import threading
    release = threading.Event()
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: release.wait(10) and [])
    t0 = time.monotonic()
    try:
        with pytest.raises(FetchError, match="timed out"):
            fetch.fetch("http://example.org/", FetchOptions(timeout=0.3))
    finally:
        release.set()
    assert time.monotonic() - t0 < 3


@pytest.mark.parametrize("url", ["　http://evil.com/", "\x85https://evil.com/", " http://a.evil.com/"])
def test_leading_unicode_space_cannot_skip_the_threat_lists(lists, monkeypatch, url):
    net = Net(monkeypatch, dns={"evil.com": [PUBLIC], "a.evil.com": [PUBLIC]})
    assert "is on URLhaus" in ioc.check(url)
    with pytest.raises(FetchError, match="is on URLhaus"):
        fetch.fetch(url)
    assert net.lookups == [] and net.conns == []


def test_url_without_host_is_blocked_by_the_list_check(lists):
    assert "no host" in ioc.check("not a url")


def test_external_scripts_are_never_fetched(monkeypatch):
    from readerguard.formats.html import scan_html
    asked = []
    page = PAGE.replace(b"<body>", b'<body><script src="https://cdn.example/x.js"></script>')
    scan_html(page, base_url="https://example.org/", fetch_resource=lambda u, k: asked.append((u, k)) or b"")
    assert asked == []
    net = Net(monkeypatch, dns={"example.org": [PUBLIC], "cdn.example": [PUBLIC]}, routes={("example.org", "/"): ok(page)})
    assert scan("https://example.org/").safe
    assert [c.host for c in net.conns] == ["example.org"]


@pytest.mark.parametrize("url", ["http://3405803842/", "http://0xcb.0x0.0x71.0x42/", "http://203.0.28994/",
                                 "http://0313.0.0161.0102/", "http://0xcb.0.0x7142/"])
def test_listed_ip_cannot_be_respelled(lists, monkeypatch, url):
    net = Net(monkeypatch)
    assert "203.0.113.66 is on URLhaus" in ioc.check(url)
    with pytest.raises(FetchError, match="is on URLhaus"):
        fetch.fetch(url)
    assert net.lookups == [] and net.conns == []


@pytest.mark.parametrize("url", ["http://2130706433/", "http://0x7f.1/", "http://127.1/", "http://0177.0.0.1/"])
def test_legacy_ipv4_spellings_are_checked_as_addresses_without_dns(monkeypatch, url):
    net = Net(monkeypatch)
    with pytest.raises(FetchError, match="non-public"):
        fetch.fetch(url)
    assert net.lookups == []


def test_bad_legacy_ipv4_is_refused():
    with pytest.raises(FetchError, match="invalid host"):
        fetch.fetch("http://0x/")


def test_resource_fetcher_keeps_a_smaller_page_cap(monkeypatch):
    Net(monkeypatch, dns={"example.org": [PUBLIC]}, routes={("example.org", "/a.css"): ok(b"x" * 20, "text/css")})
    assert fetch.resource_fetcher(FetchOptions(max_bytes=10))("https://example.org/a.css", "text/css") is None
