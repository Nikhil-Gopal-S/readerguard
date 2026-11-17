"""readerguard: rebuild documents and web pages into visible text before they reach a RAG index or an LLM.

    from readerguard import scan
    r = scan(Path("upload.docx"))      # Path, bytes, file object, or an http(s) URL str; never raises
    r.safe, r.message                  # True = accept, False = reject; "accepted" / "rejected: <reason>"
    r.safe_text                        # visible text only (empty on reject)
    r.removed                          # what was left out, e.g. {"hidden_text": 3, "macros": 1}
    r.to_dict()                        # JSON-ready

Accepted: PDF, HTML / URLs, DOCX / PPTX / XLSX (+ macro-enabled), Markdown and plain text (UTF-8 / UTF-16),
PNG / JPEG / GIF / WebP. Everything else (executables, archives, legacy Office, RTF, OpenDocument, SVG,
BMP / TIFF, unknown binary) is rejected at the gate.
"""
from . import limits
from .api import ScanResult, scan, sniff
from .fetch import FetchOptions

__all__ = ["scan", "sniff", "ScanResult", "FetchOptions", "limits"]
__version__ = "0.3.0"
