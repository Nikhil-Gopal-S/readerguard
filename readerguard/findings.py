"""Finding and Report types shared by every extractor. A finding only names what was removed (or why the input
is refused): the host turns findings into the `removed` counts and reasons; nothing is graded."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    check: str                 # e.g. "hidden_text", "macros"
    message: str
    page: int | None = None    # 0-based; None for document-level findings


@dataclass
class Report:
    path: str
    format: str = "unknown"
    findings: list[Finding] = field(default_factory=list)
    safe_pages: list[str] = field(default_factory=list)   # visible-only text per page
    images: list[bytes] = field(default_factory=list)     # rebuilt PNGs
    error: str | None = None

    @property
    def safe_text(self) -> str:
        from .textscan import strip_invisible
        return strip_invisible("\n\f".join(self.safe_pages))


def clip(s: str, n: int = 160) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"
