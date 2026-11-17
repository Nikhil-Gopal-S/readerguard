"""Raster images (PNG, JPEG, GIF, WebP), rebuilt into a new PNG. No text is read from the pixels (no OCR).

What the rebuild removes is counted:

- Payload smuggling: data appended after the image end marker, other file formats embedded (polyglots).
- Side-channel text: EXIF / XMP / PNG text chunks / JPEG comments.
- Content painted into fully transparent pixels (a model reading raw RGB can see it).
"""
from __future__ import annotations

import io
import re
import struct
import warnings

import numpy as np

from .. import limits
from ..content import content_findings
from ..findings import Finding, Report

SIGNATURES = [(rb"<script", "HTML script"), (rb"<\?php", "PHP code"), (rb"<html", "HTML document"),
              (rb"%PDF-", "PDF document"), (rb"PK\x03\x04", "ZIP archive"), (rb"MZ\x90\x00", "Windows executable"),
              (rb"\x7fELF", "Linux executable"), (rb"<svg", "SVG document"), (rb"#!/bin/", "shell script")]
META_KEYS = {"comment", "Comment", "Description", "Title", "Author", "Software", "parameters", "xmp",
             "XML:com.adobe.xmp"}
EXIF_TEXT = {270: "ImageDescription", 315: "Artist", 33432: "Copyright", 305: "Software", 0x9C9B: "XPTitle",
             0x9C9C: "XPComment", 0x9C9D: "XPAuthor", 0x9C9E: "XPKeywords", 0x9C9F: "XPSubject"}


def _png_end(raw: bytes):
    i = 8
    while i + 8 <= len(raw):
        n, typ = struct.unpack(">I4s", raw[i:i + 8])
        i += 12 + n
        if typ == b"IEND":
            return i
    return None


def _jpeg_end(raw: bytes):
    i = 2
    while i + 4 <= len(raw):
        if raw[i] != 0xFF:
            return None
        m = raw[i + 1]
        if m == 0xD9:
            return i + 2
        if m in (0x01,) or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        seg = struct.unpack(">H", raw[i + 2:i + 4])[0]
        i += 2 + seg
        if m == 0xDA:                       # start of scan: skip entropy-coded data
            while i + 1 < len(raw):
                if raw[i] == 0xFF and raw[i + 1] != 0x00 and not (0xD0 <= raw[i + 1] <= 0xD7):
                    break
                i += 1
    return None


DECODERS = ["PNG", "JPEG", "GIF", "WEBP"]             # the only Pillow plugins ever tried
MAX_JPEG_SCANS = 100        # a progressive JPEG has about 10; each scan walks every block (CPU time, not pixels)
MAX_INFO_ENTRIES = 1000     # metadata / text chunks per image


def _jpeg_scans(raw: bytes) -> int:
    """Start-of-scan markers in a JPEG, counted by walking its segments (entropy-coded data is skipped)."""
    i, n = 2, 0
    while i + 4 <= len(raw):
        if raw[i] != 0xFF:
            return n
        m = raw[i + 1]
        if m == 0xFF:
            i += 1
            continue
        if m == 0xD9:
            return n
        if m == 0x01 or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        i += 2 + struct.unpack(">H", raw[i + 2:i + 4])[0]
        if m == 0xDA:
            n += 1
            if n > MAX_JPEG_SCANS:
                return n
            j = raw.find(b"\xff", i)
            while j >= 0 and j + 1 < len(raw) and (raw[j + 1] == 0 or 0xD0 <= raw[j + 1] <= 0xD7):
                j = raw.find(b"\xff", j + 2)
            i = len(raw) if j < 0 else j
    return n


def _png_check(raw: bytes) -> None:
    """A greyscale or RGB PNG with a transparency key (tRNS) at a bit depth other than 8: the key is not
    applied correctly when the image is reduced to 8 bits, so 'transparent' pixels would show. Refused."""
    if raw[12:16] != b"IHDR" or len(raw) < 26:
        return
    depth, ctype = raw[24], raw[25]
    if ctype not in (0, 2) or depth == 8:
        return
    i = 8
    while i + 8 <= len(raw):
        n, typ = struct.unpack(">I4s", raw[i:i + 8])
        if typ in (b"IDAT", b"IEND"):
            return
        if typ == b"tRNS":
            raise limits.Refused("PNG with a transparency key at a bit depth other than 8 is not accepted")
        i += 12 + n


def scan_image(raw: bytes, name: str = "<bytes>") -> Report:
    """Rebuild: first frame -> flatten onto white -> 8-bit RGB -> averaging downscale to MAX_IMAGE_PX -> new PNG.
    Nothing of the original file (metadata, ICC profile, later frames, alpha, trailing bytes) is copied."""
    from PIL import Image

    rep = Report(path=name, format="image")
    Image.MAX_IMAGE_PIXELS = limits.MAX_IMAGE_PIXELS
    if raw.startswith(b"\xff\xd8") and _jpeg_scans(raw) > MAX_JPEG_SCANS:
        raise limits.OverLimit(f"JPEG has more than {MAX_JPEG_SCANS} scans")
    if raw.startswith(b"\x89PNG"):
        _png_check(raw)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            im = Image.open(io.BytesIO(raw), formats=DECODERS)      # reads the header only
            if im.width * im.height > limits.MAX_IMAGE_PIXELS:      # checked before any pixel is decoded
                raise Image.DecompressionBombError
            im.verify()
            im = Image.open(io.BytesIO(raw), formats=DECODERS)
            im.seek(0)
            im.load()
            if getattr(im, "default_image", False) or im.info.get("default_image"):
                im.seek(1)              # APNG: frame 0 is a default image that animating viewers never show
                im.load()
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise limits.OverLimit(f"image is larger than the {limits.MAX_IMAGE_PIXELS // 1_000_000} megapixel limit")
    except Exception as e:
        rep.error = f"cannot decode image: {type(e).__name__}"
        rep.findings.append(Finding(check="malformed_image", message=rep.error))
        return rep
    if len(im.info or {}) > MAX_INFO_ENTRIES:
        raise limits.OverLimit(f"image has more than {MAX_INFO_ENTRIES} metadata entries")
    rep.format = f"image/{(im.format or 'unknown').lower()}"
    rep.images = [_rebuild(im)]

    # ---- appended data and polyglots
    end = _png_end(raw) if im.format == "PNG" else _jpeg_end(raw) if im.format == "JPEG" else None
    if end is not None and len(raw) - end > 16:
        tail = raw[end:]
        kinds = [k for sig, k in SIGNATURES if re.search(sig, tail[:5_000_000], re.I)]
        rep.findings.append(Finding("appended_data", f"{len(tail)} bytes after the end of the image"
                                    + (f" containing a {kinds[0]}" if kinds else "")))
    else:
        body = raw[64:]
        kinds = [k for sig, k in SIGNATURES[:4] + SIGNATURES[5:7] if re.search(sig, body[:20_000_000], re.I)]
        if kinds:
            rep.findings.append(Finding(check="polyglot", message=f"image bytes embed a {kinds[0]}"))

    # ---- metadata text
    meta = []
    for k, v in (im.info or {}).items():
        if isinstance(v, bytes):
            v = v.decode("utf-8", "ignore")
        if isinstance(v, str) and k not in ("icc_profile", "exif"):
            meta.append((f"metadata.{k}" if k in META_KEYS else "metadata", v))   # other keys came from the file
    try:
        exif = im.getexif()
        for tag, label in EXIF_TEXT.items():
            v = exif.get(tag)
            if v:
                v = v.decode("utf-16-le", "ignore") if isinstance(v, bytes) and tag >= 0x9C9B else v
                meta.append((f"exif.{label}", v if isinstance(v, str) else str(v)))
        uc = exif.get_ifd(0x8769).get(0x9286)
        if uc:
            meta.append(("exif.UserComment", uc[8:].decode("utf-16-le" if uc[:8].startswith(b"UNICODE") else "utf-8",
                                                          "ignore") if isinstance(uc, bytes) else str(uc)))
    except Exception:
        pass
    for ch, v in meta:
        v = v.replace("\x00", "")
        long_ = sum(c.isalnum() for c in v) >= 40 and ch not in ("metadata.parameters", "metadata.xmp",
                                                                   "metadata.XML:com.adobe.xmp")
        rep.findings += content_findings(v, ch, side_channel=long_)

    # ---- pixels
    rgba = im.convert("RGBA") if im.mode in ("RGBA", "LA", "PA") or "transparency" in im.info else None
    if rgba is not None:
        a = np.asarray(rgba)
        clear = a[..., 3] == 0
        if clear.mean() > 0.01:
            rgb = a[..., :3][clear].astype(np.int16)
            spread = rgb.std(axis=0).max() if len(rgb) > 50 else 0
            if spread > 25:
                rep.findings.append(Finding(check="hidden_pixels",
                                            message="fully transparent pixels carry image content that a model "
                                                    "reading raw RGB can see"))
    return rep


def _rebuild(im) -> bytes:
    from PIL import Image

    if im.mode.startswith("I"):                       # 16/32-bit grey: keep the top 8 bits, not a clipped copy
        im = Image.fromarray(np.clip(np.asarray(im).astype(np.int64) >> 8, 0, 255).astype(np.uint8))
    rgba = im.convert("RGBA")
    flat = Image.new("RGB", rgba.size, (255, 255, 255))
    flat.paste(rgba, mask=rgba.getchannel("A"))       # onto white: what is transparent stays unseen
    long_side = max(flat.size)
    if long_side > limits.MAX_IMAGE_PX:
        k = limits.MAX_IMAGE_PX / long_side
        flat = flat.resize((max(1, round(flat.width * k)), max(1, round(flat.height * k))), Image.Resampling.BOX)
    flat.info = {}
    for _ in range(3):
        out = io.BytesIO()
        flat.save(out, "PNG")
        png = out.getvalue()
        # pixels can be chosen so that the encoder writes another file format byte for byte (stored deflate
        # blocks): if the new PNG carries one, nudge the low bit of every pixel at random and encode again
        if not any(re.search(sig, png, re.I) for sig, _ in SIGNATURES) and b"PK\x05\x06" not in png:
            return png
        a = np.asarray(flat).astype(np.int16)
        noise = np.random.default_rng().integers(-1, 2, a.shape, dtype=np.int16)
        flat = Image.fromarray(np.clip(a + noise, 0, 255).astype(np.uint8))
    raise limits.Refused("the rebuilt image still carries another file format")
