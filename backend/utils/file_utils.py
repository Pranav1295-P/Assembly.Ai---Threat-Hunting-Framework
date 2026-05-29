"""File hashing, magic-byte detection, entropy."""
from __future__ import annotations

import hashlib
import math
from collections import Counter
from pathlib import Path
from typing import Dict


# Common magic-byte signatures (extendable)
MAGIC_SIGNATURES = [
    (b"MZ",                 "PE/DOS executable (Windows .exe/.dll)"),
    (b"\x7fELF",            "ELF executable (Linux)"),
    (b"\xca\xfe\xba\xbe",   "Mach-O fat binary (macOS)"),
    (b"\xcf\xfa\xed\xfe",   "Mach-O 64-bit (macOS)"),
    (b"PK\x03\x04",         "ZIP archive / Office OOXML / JAR / APK"),
    (b"%PDF",               "PDF document"),
    (b"\xd0\xcf\x11\xe0",   "OLE Compound Document (legacy Office .doc/.xls)"),
    (b"#!",                 "Shell script / interpreted binary"),
    (b"<?xml",              "XML document"),
    (b"<!DOCTYPE html",     "HTML document"),
    (b"<html",              "HTML document"),
    (b"\x1f\x8b",           "GZIP archive"),
    (b"Rar!",               "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"BM",                 "BMP image"),
    (b"\x89PNG",            "PNG image"),
    (b"\xff\xd8\xff",       "JPEG image"),
]


def file_hashes(path: Path) -> Dict[str, str]:
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def detect_filetype(path: Path) -> str:
    """Return a human-readable type. Falls back to ext if no magic match."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(64)
        for sig, label in MAGIC_SIGNATURES:
            if head.startswith(sig):
                return label
    except Exception:
        pass
    return f"Unknown ({path.suffix or 'no-ext'})"


def shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy (0..8). High entropy ≈ packed/encrypted."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def file_entropy(path: Path, max_bytes: int = 4 * 1024 * 1024) -> float:
    with open(path, "rb") as fh:
        data = fh.read(max_bytes)
    return round(shannon_entropy(data), 4)


def extract_strings(path: Path, min_len: int = 6, max_strings: int = 1500) -> list[str]:
    """Naive ASCII + UTF-16LE printable string extraction."""
    out: list[str] = []
    try:
        with open(path, "rb") as fh:
            blob = fh.read(8 * 1024 * 1024)
    except Exception:
        return out

    # ASCII
    cur = bytearray()
    for b in blob:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", errors="replace"))
                if len(out) >= max_strings:
                    return out
            cur.clear()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", errors="replace"))

    # UTF-16LE
    try:
        text = blob.decode("utf-16-le", errors="ignore")
        token = []
        for ch in text:
            if ch.isprintable() and ch.isascii():
                token.append(ch)
            else:
                if len(token) >= min_len:
                    out.append("".join(token))
                    if len(out) >= max_strings:
                        return out
                token = []
        if len(token) >= min_len:
            out.append("".join(token))
    except Exception:
        pass

    return out[:max_strings]
