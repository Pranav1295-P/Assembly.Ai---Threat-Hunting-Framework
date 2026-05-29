"""Indicator-of-Compromise extraction from extracted strings."""
from __future__ import annotations

import re
from typing import Dict, List

# These regexes are pragmatic, not RFC-perfect — false positives are filtered.
URL_RE       = re.compile(r"\bhttps?://[A-Za-z0-9_.\-/%?=&#:+~@]{4,}", re.I)
DOMAIN_RE    = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|club|shop|site|onion|dev|ai|ws|tk)\b")
IPV4_RE      = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
EMAIL_RE     = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
BTC_RE       = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b")
ETH_RE       = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
REG_KEY_RE   = re.compile(r"\b(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[A-Za-z0-9\\\-_ .]{4,}", re.I)
FILEPATH_RE  = re.compile(r"[A-Za-z]:\\\\?[A-Za-z0-9_.\\\\\- ]{4,}\.(?:exe|dll|bat|ps1|vbs|js|hta|lnk)", re.I)
MUTEX_RE     = re.compile(r"\b(?:Global|Local)\\\\[A-Za-z0-9_\-]{4,}", re.I)

PRIVATE_IPS = (
    "10.", "192.168.", "127.", "0.0.0.0", "255.255.255.255",
    "169.254.", "224.", "239.",
) + tuple(f"172.{i}." for i in range(16, 32))

SAFE_DOMAINS = {
    "microsoft.com", "windows.com", "schemas.microsoft.com",
    "msdn.microsoft.com", "go.microsoft.com", "support.microsoft.com",
    "schemas.openxmlformats.org", "w3.org", "ietf.org",
    "verisign.com", "digicert.com", "globalsign.com",
}


def _filter_ips(ips: List[str]) -> List[str]:
    return sorted({ip for ip in ips if not ip.startswith(PRIVATE_IPS)})


def _filter_domains(domains: List[str]) -> List[str]:
    out = set()
    for d in domains:
        d = d.lower().strip(".")
        if d in SAFE_DOMAINS:
            continue
        if any(d.endswith(safe) for safe in SAFE_DOMAINS):
            continue
        out.add(d)
    return sorted(out)


def extract(strings: List[str]) -> Dict[str, List[str]]:
    blob = "\n".join(strings)

    return {
        "urls":        sorted(set(URL_RE.findall(blob)))[:50],
        "domains":     _filter_domains(DOMAIN_RE.findall(blob))[:50],
        "ipv4":        _filter_ips(IPV4_RE.findall(blob))[:50],
        "emails":      sorted(set(EMAIL_RE.findall(blob)))[:30],
        "btc":         sorted(set(BTC_RE.findall(blob)))[:20],
        "eth":         sorted(set(ETH_RE.findall(blob)))[:20],
        "registry":    sorted(set(REG_KEY_RE.findall(blob)))[:30],
        "filepaths":   sorted(set(FILEPATH_RE.findall(blob)))[:30],
        "mutexes":     sorted(set(MUTEX_RE.findall(blob)))[:20],
    }
